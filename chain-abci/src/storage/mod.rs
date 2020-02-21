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
use enclave_protocol::{IntraEnclaveRequest, IntraEnclaveResponseOk, SealedLog, VerifyOk};

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
    inputs: &[TxoPointer],
    storage: &Storage,
) -> Result<Vec<SealedLog>, Error> {
    // check that there are inputs
    if inputs.is_empty() {
        return Err(Error::NoInputs);
    }
    let mut result = Vec::with_capacity(inputs.len());
    for txin in inputs.iter() {
        let txo = storage.lookup_input(txin, true);
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
            Ok(InputStatus::Unspent) => {
                result.push(
                    storage
                        .get_sealed_log(&txin.id)
                        .expect("valid unspent tx output should be stored"),
                );
            }
        }
    }
    Ok(result)
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
        TxEnclaveAux::TransferTx { inputs, .. } => {
            let tx_inputs = check_spent_input_lookup(&inputs, storage)?;
            let response = tx_validator.process_request(
                IntraEnclaveRequest::new_validate_transfer(txaux.clone(), extra_info, tx_inputs),
            );
            match response {
                Ok(IntraEnclaveResponseOk::TxWithOutputs {
                    paid_fee,
                    sealed_tx,
                }) => Ok((paid_fee, None, Some(Box::new(sealed_tx)))),
                Err(e) => Err(e),
                _ => unreachable!("unexpected enclave response"),
            }
        }
        TxEnclaveAux::DepositStakeTx { tx, .. } => {
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

            let tx_inputs = check_spent_input_lookup(&tx.inputs, storage)?;

            let response = tx_validator.process_request(IntraEnclaveRequest::new_validate_deposit(
                txaux.clone(),
                extra_info,
                account.clone(),
                tx_inputs,
            ));
            match response {
                Ok(IntraEnclaveResponseOk::DepositStakeTx { input_coins }) => {
                    let deposit_amount = (input_coins - extra_info.min_fee_computed.to_coin())
                        .expect("diff with min fee in coins");
                    let account = match account {
                        Some(mut a) => {
                            a.deposit(deposit_amount);
                            Some(a)
                        }
                        None => Some(StakedState::new_init_bonded(
                            deposit_amount,
                            extra_info.previous_block_time,
                            tx.to_staked_account,
                            None,
                        )),
                    };
                    let fee = extra_info.min_fee_computed;
                    Ok((fee, account, None))
                }
                Err(e) => Err(e),
                _ => unreachable!("unexpected enclave response"),
            }
        }
        TxEnclaveAux::WithdrawUnbondedStakeTx {
            payload: TxObfuscated { txid, .. },
            witness,
            ..
        } => {
            let account_address = verify_tx_recover_address(&witness, &txid);
            if let Err(_e) = account_address {
                return Err(Error::EcdsaCrypto); // FIXME: Err(Error::EcdsaCrypto(e));
            }
            let mut account =
                get_account(&account_address.unwrap(), last_account_root_hash, accounts)?;
            verify_unjailed(&account)?;
            let response =
                tx_validator.process_request(IntraEnclaveRequest::new_validate_withdraw(
                    txaux.clone(),
                    extra_info,
                    account.clone(),
                ));
            match response {
                Ok(IntraEnclaveResponseOk::TxWithOutputs {
                    paid_fee,
                    sealed_tx,
                }) => {
                    account.withdraw();
                    Ok((paid_fee, Some(account), Some(Box::new(sealed_tx))))
                }
                Err(e) => Err(e),
                _ => unreachable!("unexpected enclave response"),
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
