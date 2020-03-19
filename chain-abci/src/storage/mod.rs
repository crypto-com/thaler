use crate::enclave_bridge::EnclaveProxy;
use chain_core::init::coin::Coin;
use chain_core::state::account::{StakedState, StakedStateAddress};
use chain_core::tx::data::input::{TxoIndex, TxoPointer};
use chain_core::tx::fee::Fee;
use chain_core::tx::{TransactionId, TxEnclaveAux, TxObfuscated, TxPublicAux};
use chain_storage::account::{
    get_staked_state, AccountStorage, StakedStateError, StarlingFixedKey,
};
use chain_storage::buffer::{GetKV, GetStaking};
use chain_tx_validation::{
    verify_node_join, verify_unbonding, verify_unjailed, verify_unjailing,
    witness::verify_tx_recover_address, ChainInfo, Error, NodeChecker,
};
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
        create_utxo: TxoIndex,
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
        create_utxo: TxoIndex,
        sealed_log: SealedLog,
    },
}

impl TxEnclaveAction {
    fn transfer(
        fee: Fee,
        spend_utxo: Vec<TxoPointer>,
        create_utxo: TxoIndex,
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
        create_utxo: TxoIndex,
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

#[derive(Debug, Clone)]
pub enum TxAction {
    Enclave(TxEnclaveAction),
    Public(TxPublicAux),
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

/// Checks non-enclave TX against the current DB and returns an `Error` if something fails.
/// If OK, returns the paid fee + affected staked state.
pub fn verify_public_tx(
    txaux: &TxPublicAux,
    extra_info: &ChainInfo,
    node_info: impl NodeChecker,
    trie: &impl GetStaking,
) -> Result<(Fee, Option<StakedState>), Error> {
    match txaux {
        // TODO: delay checking witness, as address is contained in Tx?
        TxPublicAux::UnbondStakeTx(maintx, witness) => {
            match verify_tx_recover_address(&witness, &maintx.id()) {
                Ok(account_address) => {
                    let account = trie.get(&account_address).ok_or(Error::AccountNotFound)?;
                    verify_unbonding(maintx, extra_info, account)
                }
                Err(_) => {
                    Err(Error::EcdsaCrypto) // FIXME: Err(Error::EcdsaCrypto(e))
                }
            }
        }
        // TODO: delay checking witness, as address is contained in Tx?
        TxPublicAux::UnjailTx(maintx, witness) => {
            match verify_tx_recover_address(&witness, &maintx.id()) {
                Ok(account_address) => {
                    let account = trie.get(&account_address).ok_or(Error::AccountNotFound)?;
                    verify_unjailing(maintx, extra_info, account)
                }
                Err(_) => {
                    Err(Error::EcdsaCrypto) // FIXME: Err(Error::EcdsaCrypto(e))
                }
            }
        }
        // TODO: delay checking witness, as address is contained in Tx?
        TxPublicAux::NodeJoinTx(maintx, witness) => {
            match verify_tx_recover_address(&witness, &maintx.id()) {
                Ok(account_address) => {
                    let account = trie.get(&account_address).ok_or(Error::AccountNotFound)?;
                    verify_node_join(maintx, extra_info, node_info, account)
                }
                Err(_) => {
                    Err(Error::EcdsaCrypto) // FIXME: Err(Error::EcdsaCrypto(e))
                }
            }
        }
    }
}
