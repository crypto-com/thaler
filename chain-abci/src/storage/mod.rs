use crate::enclave_bridge::EnclaveProxy;
use crate::staking::StakingTable;
use crate::tx_error::PublicTxError;
use chain_core::common::Timespec;
use chain_core::init::coin::Coin;
use chain_core::state::account::{CouncilNode, StakedStateAddress, StakedStateOpAttributes};
use chain_core::tx::data::input::{TxoPointer, TxoSize};
use chain_core::tx::fee::Fee;
use chain_core::tx::{TransactionId, TxEnclaveAux, TxObfuscated, TxPublicAux};
use chain_storage::buffer::{GetKV, GetStaking, StoreStaking};
use chain_tx_validation::{verify_unjailed, witness::verify_tx_recover_address, ChainInfo, Error};
use enclave_protocol::{IntraEnclaveRequest, IntraEnclaveResponseOk, SealedLog};

pub enum TxAction {
    Enclave(TxEnclaveAction),
    Public(TxPublicAction),
}

impl TxAction {
    pub fn fee(&self) -> Fee {
        match self {
            Self::Enclave(action) => action.fee(),
            Self::Public(action) => action.fee(),
        }
    }

    pub fn staking_address(&self) -> Option<StakedStateAddress> {
        match self {
            Self::Enclave(action) => action.staking_address(),
            Self::Public(action) => action.staking_address(),
        }
    }
}

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

    pub fn staking_address(&self) -> Option<StakedStateAddress> {
        match self {
            Self::Transfer { .. } => None,
            Self::Deposit { deposit, .. } => Some(deposit.0),
            Self::Withdraw { withdraw, .. } => Some(withdraw.0),
        }
    }
}

pub enum TxPublicAction {
    Unbond {
        fee: Fee,
        unbond: (StakedStateAddress, Coin),
        unbonded_from: Timespec,
    },
    NodeJoin {
        address: StakedStateAddress,
        council_node: CouncilNode,
        // most recent isv_svn
        isv_svn: u16,
    },
    Unjail(StakedStateAddress),
}

impl TxPublicAction {
    fn unbond(fee: Fee, unbond: (StakedStateAddress, Coin), unbonded_from: Timespec) -> Self {
        Self::Unbond {
            fee,
            unbond,
            unbonded_from,
        }
    }
    fn node_join(address: StakedStateAddress, council_node: CouncilNode, isv_svn: u16) -> Self {
        Self::NodeJoin {
            address,
            council_node,
            isv_svn,
        }
    }
    fn unjail(staking_address: StakedStateAddress) -> Self {
        Self::Unjail(staking_address)
    }

    pub fn fee(&self) -> Fee {
        match self {
            Self::Unbond { fee, .. } => *fee,
            Self::NodeJoin { .. } => Fee::new(Coin::zero()),
            Self::Unjail(_) => Fee::new(Coin::zero()),
        }
    }

    pub fn staking_address(&self) -> Option<StakedStateAddress> {
        match self {
            Self::Unbond { unbond, .. } => Some(unbond.0),
            Self::NodeJoin { address, .. } => Some(*address),
            Self::Unjail(staking_address) => Some(*staking_address),
        }
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
    enclave_isv_svn: u16,
    chain_info: &ChainInfo,
    txaux: &TxPublicAux,
) -> Result<TxPublicAction, PublicTxError> {
    check_staking_attributes(txaux.attributes(), chain_info.chain_hex_id)?;
    match txaux {
        // TODO: delay checking witness, as address is contained in Tx?
        TxPublicAux::UnbondStakeTx(maintx, witness) => {
            let address = verify_tx_recover_address(&witness, &maintx.id())?;
            if address != maintx.from_staked_account {
                return Err(PublicTxError::StakingWitnessNotMatch);
            }
            let unbonded_from = staking_table.unbond(
                staking_store,
                chain_info.get_unbonding_period(),
                chain_info.block_time,
                chain_info.block_height,
                &maintx,
                chain_info.min_fee_computed,
            )?;

            Ok(TxPublicAction::unbond(
                chain_info.min_fee_computed,
                (address, maintx.value),
                unbonded_from,
            ))
        }
        // TODO: delay checking witness, as address is contained in Tx?
        TxPublicAux::UnjailTx(maintx, witness) => {
            let address = verify_tx_recover_address(&witness, &maintx.id())?;
            if address != maintx.address {
                return Err(PublicTxError::StakingWitnessNotMatch);
            }

            staking_table.unjail(staking_store, chain_info.block_time, maintx)?;

            Ok(TxPublicAction::unjail(address))
        }
        // TODO: delay checking witness, as address is contained in Tx?
        TxPublicAux::NodeJoinTx(maintx, witness) => {
            let address = verify_tx_recover_address(&witness, &maintx.id())?;
            if address != maintx.address {
                return Err(PublicTxError::StakingWitnessNotMatch);
            }
            let isv_svn = staking_table.node_join(
                staking_store,
                chain_info.block_time,
                chain_info.max_evidence_age,
                enclave_isv_svn,
                maintx,
            )?;

            Ok(TxPublicAction::node_join(
                address,
                maintx.node_meta.clone(),
                isv_svn,
            ))
        }
    }
}
