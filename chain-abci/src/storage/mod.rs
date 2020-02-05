use crate::enclave_bridge::EnclaveProxy;
use chain_core::state::account::{StakedState, StakedStateAddress};
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::fee::Fee;
use chain_core::tx::TransactionId;
use chain_core::tx::TxObfuscated;
use chain_core::tx::{TxAux, TxEnclaveAux};
use chain_storage::account::{
    get_staked_state, AccountStorage, StakedStateError, StarlingFixedKey,
};
use chain_storage::tx::{InputError, InputStatus};
use chain_storage::Storage;
use chain_tx_validation::{
    verify_node_join, verify_unbonding, verify_unjailed, verify_unjailing,
    witness::verify_tx_recover_address, ChainInfo, Error, NodeChecker,
};
use enclave_protocol::{EnclaveRequest, EnclaveResponse, VerifyOk};

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

fn check_spent_input_lookup(inputs: &[TxoPointer], storage: &Storage) -> Result<(), Error> {
    // check that there are inputs
    if inputs.is_empty() {
        return Err(Error::NoInputs);
    }
    for txin in inputs.iter() {
        let txo = storage.lookup_input(txin);
        match txo {
            Err(InputError::InvalidIndex) => {
                return Err(Error::InvalidInput);
            }
            Err(InputError::InvalidTxId) => {
                return Err(Error::InvalidInput);
            }
            Err(InputError::IoError(_e)) => {
                return Err(Error::IoError);
            }
            Ok(InputStatus::Spent) => {
                return Err(Error::InputSpent);
            }
            Ok(InputStatus::Unspent) => {}
        }
    }
    Ok(())
}

/// Checks TX against the current DB, passes to the enclave and returns an `Error` if something fails.
/// If OK, returns the paid fee + affected staked state (if any).
pub fn verify_enclave_tx<T: EnclaveProxy>(
    tx_validator: &mut T,
    txaux: &TxEnclaveAux,
    extra_info: ChainInfo,
    last_account_root_hash: &StarlingFixedKey,
    storage: &Storage,
    accounts: &AccountStorage,
) -> Result<VerifyOk, Error> {
    match txaux {
        TxEnclaveAux::TransferTx {
            inputs,
            no_of_outputs,
            payload,
        } => {
            check_spent_input_lookup(&inputs, storage)?;
            let response = tx_validator.process_request(EnclaveRequest::new_tx_request(
                TxEnclaveAux::TransferTx {
                    inputs: inputs.clone(),
                    no_of_outputs: *no_of_outputs,
                    payload: payload.clone(),
                },
                None,
                extra_info,
            ));
            match response {
                EnclaveResponse::VerifyTx(r) => r,
                _ => Err(Error::EnclaveRejected),
            }
        }
        TxEnclaveAux::DepositStakeTx { tx, payload } => {
            let maccount = get_account(&tx.to_staked_account, last_account_root_hash, accounts);
            let account = match maccount {
                Ok(a) => Some(a),
                Err(Error::AccountNotFound) => None,
                Err(e) => {
                    return Err(e);
                }
            };
            if let Some(ref account) = account {
                verify_unjailed(account)?;
            }

            check_spent_input_lookup(&tx.inputs, storage)?;

            let response = tx_validator.process_request(EnclaveRequest::new_tx_request(
                TxEnclaveAux::DepositStakeTx {
                    tx: tx.clone(),
                    payload: payload.clone(),
                },
                account,
                extra_info,
            ));
            match response {
                EnclaveResponse::VerifyTx(r) => r,
                _ => Err(Error::EnclaveRejected),
            }
        }
        TxEnclaveAux::WithdrawUnbondedStakeTx {
            payload:
                TxObfuscated {
                    key_from,
                    init_vector,
                    txpayload,
                    txid,
                },
            witness,
            no_of_outputs,
        } => {
            let account_address = verify_tx_recover_address(&witness, &txid);
            if let Err(_e) = account_address {
                return Err(Error::EcdsaCrypto); // FIXME: Err(Error::EcdsaCrypto(e));
            }
            let account = get_account(&account_address.unwrap(), last_account_root_hash, accounts)?;
            verify_unjailed(&account)?;
            let response = tx_validator.process_request(EnclaveRequest::new_tx_request(
                TxEnclaveAux::WithdrawUnbondedStakeTx {
                    payload: TxObfuscated {
                        key_from: *key_from,
                        init_vector: *init_vector,
                        txpayload: txpayload.clone(),
                        txid: *txid,
                    },
                    witness: witness.clone(),
                    no_of_outputs: *no_of_outputs,
                },
                Some(account),
                extra_info,
            ));
            match response {
                EnclaveResponse::VerifyTx(r) => r,
                _ => Err(Error::EnclaveRejected),
            }
        }
    }
}

/// Checks non-enclave TX against the current DB and returns an `Error` if something fails.
/// If OK, returns the paid fee + affected staked state.
pub fn verify_public_tx(
    txaux: &TxAux,
    extra_info: ChainInfo,
    node_info: impl NodeChecker,
    last_account_root_hash: &StarlingFixedKey,
    accounts: &AccountStorage,
) -> Result<(Fee, Option<StakedState>), Error> {
    match txaux {
        TxAux::EnclaveTx(_) => unreachable!("should be handled by verify_enclave_tx"),
        // TODO: delay checking witness, as address is contained in Tx?
        TxAux::UnbondStakeTx(maintx, witness) => {
            match verify_tx_recover_address(&witness, &maintx.id()) {
                Ok(account_address) => {
                    let account = get_account(&account_address, last_account_root_hash, accounts)?;
                    verify_unbonding(maintx, extra_info, account)
                }
                Err(_) => {
                    Err(Error::EcdsaCrypto) // FIXME: Err(Error::EcdsaCrypto(e))
                }
            }
        }
        // TODO: delay checking witness, as address is contained in Tx?
        TxAux::UnjailTx(maintx, witness) => {
            match verify_tx_recover_address(&witness, &maintx.id()) {
                Ok(account_address) => {
                    let account = get_account(&account_address, last_account_root_hash, accounts)?;
                    verify_unjailing(maintx, extra_info, account)
                }
                Err(_) => {
                    Err(Error::EcdsaCrypto) // FIXME: Err(Error::EcdsaCrypto(e))
                }
            }
        }
        // TODO: delay checking witness, as address is contained in Tx?
        TxAux::NodeJoinTx(maintx, witness) => {
            match verify_tx_recover_address(&witness, &maintx.id()) {
                Ok(account_address) => {
                    let account = get_account(&account_address, last_account_root_hash, accounts)?;
                    verify_node_join(maintx, extra_info, node_info, account)
                }
                Err(_) => {
                    Err(Error::EcdsaCrypto) // FIXME: Err(Error::EcdsaCrypto(e))
                }
            }
        }
    }
}
