use crate::app::validate_tx::PublicTxError;
use crate::enclave_bridge::EnclaveProxy;
use crate::staking_table::StakingTable;
use chain_core::common::Timespec;
use chain_core::init::coin::Coin;
use chain_core::state::account::{StakedState, StakedStateAddress, StakedStateOpAttributes};
use chain_core::tx::data::input::{TxoPointer, TxoSize};
use chain_core::tx::fee::Fee;
use chain_core::tx::{TransactionId, TxEnclaveAux, TxObfuscated, TxPublicAux};
use chain_storage::account::{
    get_staked_state, AccountStorage, StakedStateError, StarlingFixedKey,
};
use chain_storage::buffer::{GetKV, GetStaking, StoreStaking};
use chain_tx_validation::{verify_unjailed, witness::verify_tx_recover_address, ChainInfo, Error};
use enclave_protocol::{IntraEnclaveRequest, IntraEnclaveResponseOk, SealedLog};

/// fee: Written into block result events
/// spend_utxo: Modify UTxO storage
/// create_utxo: Write into UTxO storage
/// sealed_log: Write into storage
/// deposit/withdraw: Modify staking state and related validator state structure
#[derive(Debug, Clone)]
pub enum TxEnclaveAction {
    Transfer {
        fee: Fee,
        spend_utxo: Vec<TxoPointer>,
        create_utxo: TxoSize,
        sealed_log: SealedLog,
    },
    Deposit {
        fee: Fee,
        spend_utxo: Vec<TxoPointer>,
        deposit: (StakedStateAddress, Coin),
    },
    Withdraw {
        fee: Fee,
        withdraw: (StakedStateAddress, Coin),
        create_utxo: TxoSize,
        sealed_log: SealedLog,
    },
}

impl TxEnclaveAction {
    fn transfer(
        fee: Fee,
        spend_utxo: Vec<TxoPointer>,
        create_utxo: TxoSize,
        sealed_log: SealedLog,
    ) -> Self {
        Self::Transfer {
            fee,
            spend_utxo,
            create_utxo,
            sealed_log,
        }
    }
    fn deposit(fee: Fee, spend_utxo: Vec<TxoPointer>, deposit: (StakedStateAddress, Coin)) -> Self {
        Self::Deposit {
            fee,
            spend_utxo,
            deposit,
        }
    }
    fn withdraw(
        fee: Fee,
        create_utxo: TxoSize,
        sealed_log: SealedLog,
        withdraw: (StakedStateAddress, Coin),
    ) -> Self {
        Self::Withdraw {
            fee,
            create_utxo,
            sealed_log,
            withdraw,
        }
    }

    pub fn fee(&self) -> Fee {
        match self {
            Self::Transfer { fee, .. } => *fee,
            Self::Deposit { fee, .. } => *fee,
            Self::Withdraw { fee, .. } => *fee,
        }
    }
}

/// checks that the account can be retrieved from the trie storage
pub fn get_account(
    account_address: &StakedStateAddress,
    last_root: &StarlingFixedKey,
    accounts: &AccountStorage,
) -> Result<StakedState, Error> {
    match get_staked_state(account_address, last_root, accounts) {
        Ok(a) => Ok(a),
        Err(StakedStateError::NotFound) => Err(Error::AccountNotFound),
        Err(StakedStateError::IoError(_e)) => Err(Error::IoError),
    }
}

fn check_spent_input_lookup(
    kvdb: &impl GetKV,
    inputs: &[TxoPointer],
) -> Result<Vec<SealedLog>, Error> {
    // check that there are inputs
    if inputs.is_empty() {
        return Err(Error::NoInputs);
    }
    let mut result = Vec::with_capacity(inputs.len());
    for txin in inputs.iter() {
        let spent = chain_storage::lookup_input(kvdb, txin).ok_or(Error::InvalidInput)?;
        if spent {
            return Err(Error::InputSpent);
        } else {
            result.push(
                chain_storage::get_sealed_log(kvdb, &txin.id)
                    .expect("valid unspent tx output should be stored"),
            );
        }
    }
    Ok(result)
}

/// Checks TX against the current DB, passes to the enclave and returns an `Error` if something fails.
/// If OK, returns the paid fee + affected staked state (if any).
pub fn verify_enclave_tx<T: EnclaveProxy>(
    tx_validator: &mut T,
    txaux: &TxEnclaveAux,
    extra_info: &ChainInfo,
    trie: &impl GetStaking,
    kvdb: &impl GetKV,
) -> Result<TxEnclaveAction, Error> {
    match txaux {
        TxEnclaveAux::TransferTx {
            inputs,
            no_of_outputs,
            ..
        } => {
            let tx_inputs = check_spent_input_lookup(kvdb, &inputs)?;
            let response = tx_validator.process_request(
                IntraEnclaveRequest::new_validate_transfer(txaux.clone(), *extra_info, tx_inputs),
            );
            match response {
                Ok(IntraEnclaveResponseOk::TxWithOutputs {
                    paid_fee,
                    sealed_tx,
                }) => Ok(TxEnclaveAction::transfer(
                    paid_fee,
                    inputs.clone(),
                    *no_of_outputs,
                    sealed_tx,
                )),
                Err(e) => Err(e),
                _ => unreachable!("unexpected enclave response"),
            }
        }
        TxEnclaveAux::DepositStakeTx { tx, .. } => {
            let account = trie.get(&tx.to_staked_account);
            if let Some(ref account) = account {
                verify_unjailed(account)?;
            }

            let tx_inputs = check_spent_input_lookup(kvdb, &tx.inputs)?;

            let response = tx_validator.process_request(IntraEnclaveRequest::new_validate_deposit(
                txaux.clone(),
                *extra_info,
                account,
                tx_inputs,
            ));
            match response {
                Ok(IntraEnclaveResponseOk::DepositStakeTx { input_coins }) => {
                    let deposit_amount = (input_coins - extra_info.min_fee_computed.to_coin())
                        .expect("diff with min fee in coins");
                    Ok(TxEnclaveAction::deposit(
                        extra_info.min_fee_computed,
                        tx.inputs.clone(),
                        (tx.to_staked_account, deposit_amount),
                    ))
                }
                Err(e) => Err(e),
                _ => unreachable!("unexpected enclave response"),
            }
        }
        TxEnclaveAux::WithdrawUnbondedStakeTx {
            payload: TxObfuscated { txid, .. },
            witness,
            no_of_outputs,
        } => {
            let account_address =
                verify_tx_recover_address(&witness, &txid).map_err(|_| Error::EcdsaCrypto)?;
            let account = trie.get(&account_address).ok_or(Error::AccountNotFound)?;
            verify_unjailed(&account)?;
            let withdraw_amount = account.unbonded;
            let response = tx_validator.process_request(
                IntraEnclaveRequest::new_validate_withdraw(txaux.clone(), *extra_info, account),
            );
            match response {
                Ok(IntraEnclaveResponseOk::TxWithOutputs {
                    paid_fee,
                    sealed_tx,
                }) => Ok(TxEnclaveAction::withdraw(
                    paid_fee,
                    *no_of_outputs,
                    sealed_tx,
                    (account_address, withdraw_amount),
                )),
                Err(e) => Err(e),
                _ => unreachable!("unexpected enclave response"),
            }
        }
    }
}

fn check_staking_attributes(
    attrs: &StakedStateOpAttributes,
    chain_hex_id: u8,
) -> Result<(), PublicTxError> {
    // check that chain IDs match
    if chain_hex_id != attrs.chain_hex_id {
        return Err(PublicTxError::WrongChainHexId);
    }
    // check that version number is <= current one
    if chain_core::APP_VERSION < attrs.app_version {
        return Err(PublicTxError::UnsupportedVersion);
    }
    Ok(())
}

/// Execute public transactions against uncommitted db.
/// If OK, returns the paid fee + affected staking address
pub fn process_public_tx(
    staking_store: &mut impl StoreStaking,
    staking_table: &mut StakingTable,
    chain_info: &ChainInfo,
    txaux: &TxPublicAux,
) -> Result<(Fee, Option<StakedStateAddress>), PublicTxError> {
    check_staking_attributes(txaux.attributes(), chain_info.chain_hex_id)?;
    match txaux {
        // TODO: delay checking witness, as address is contained in Tx?
        TxPublicAux::UnbondStakeTx(maintx, witness) => {
            let address = verify_tx_recover_address(&witness, &maintx.id())?;
            if address != maintx.from_staked_account {
                return Err(PublicTxError::StakingWitnessNotMatch);
            }
            staking_table.unbond(
                staking_store,
                chain_info.unbonding_period as Timespec,
                chain_info.block_time,
                chain_info.block_height,
                &maintx,
            )?;
            Ok((chain_info.min_fee_computed, Some(address)))
        }
        // TODO: delay checking witness, as address is contained in Tx?
        TxPublicAux::UnjailTx(maintx, witness) => {
            let address = verify_tx_recover_address(&witness, &maintx.id())?;
            if address != maintx.address {
                return Err(PublicTxError::StakingWitnessNotMatch);
            }

            staking_table.unjail(staking_store, chain_info.block_time, maintx)?;
            Ok((Fee::new(Coin::zero()), Some(address)))
        }
        // TODO: delay checking witness, as address is contained in Tx?
        TxPublicAux::NodeJoinTx(maintx, witness) => {
            let address = verify_tx_recover_address(&witness, &maintx.id())?;
            if address != maintx.address {
                return Err(PublicTxError::StakingWitnessNotMatch);
            }
            staking_table.node_join(staking_store, chain_info.block_time, maintx)?;
            Ok((Fee::new(Coin::zero()), Some(address)))
        }
    }
}
