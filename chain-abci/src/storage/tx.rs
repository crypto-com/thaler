use crate::enclave_bridge::EnclaveProxy;
use crate::storage::account::AccountStorage;
use crate::storage::account::AccountWrapper;
use crate::storage::COL_TX_META;
use bit_vec::BitVec;
use chain_core::state::account::{to_stake_key, StakedState, StakedStateAddress};
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::fee::Fee;
use chain_core::tx::TransactionId;
use chain_core::tx::TxObfuscated;
use chain_core::tx::{TxAux, TxEnclaveAux};
use chain_tx_validation::{
    verify_node_join, verify_unbonding, verify_unjailed, verify_unjailing,
    witness::verify_tx_recover_address, ChainInfo, Error, NodeInfo,
};
use enclave_protocol::{EnclaveRequest, EnclaveResponse};
use kvdb::KeyValueDB;
use starling::constants::KEY_LEN;
use std::sync::Arc;

/// key type for looking up accounts/staked states in the merkle tree storage
pub type StarlingFixedKey = [u8; KEY_LEN];

/// checks that the account can be retrieved from the trie storage
pub fn get_account(
    account_address: &StakedStateAddress,
    last_root: &StarlingFixedKey,
    accounts: &AccountStorage,
) -> Result<StakedState, Error> {
    let account_key = to_stake_key(account_address);
    let account = accounts.get_one(last_root, &account_key);
    match account {
        Err(_e) => Err(Error::IoError)
        /* FIXME: Err(Error::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            e,
        )))*/,
        Ok(None) => Err(Error::AccountNotFound),
        Ok(Some(AccountWrapper(a))) => Ok(a),
    }
}

fn check_spent_input_lookup(inputs: &[TxoPointer], db: Arc<dyn KeyValueDB>) -> Result<(), Error> {
    // check that there are inputs
    if inputs.is_empty() {
        return Err(Error::NoInputs);
    }
    for txin in inputs.iter() {
        let txo = db.get(COL_TX_META, &txin.id[..]);
        match txo {
            Ok(Some(v)) => {
                let input_index = txin.index as usize;
                let bv = BitVec::from_bytes(&v).get(input_index);
                if bv.is_none() {
                    return Err(Error::InvalidInput);
                }
                if bv.unwrap() {
                    return Err(Error::InputSpent);
                }
            }
            Ok(None) => {
                return Err(Error::InvalidInput);
            }
            Err(_e) => {
                return Err(Error::IoError); // FIXME: Err(Error::IoError(e));
            }
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
    db: Arc<dyn KeyValueDB>,
    accounts: &AccountStorage,
) -> Result<(Fee, Option<StakedState>), Error> {
    match txaux {
        TxEnclaveAux::TransferTx {
            inputs,
            no_of_outputs,
            payload,
        } => {
            check_spent_input_lookup(&inputs, db)?;
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

            check_spent_input_lookup(&tx.inputs, db)?;

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
    node_info: NodeInfo,
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
