use super::ChainNodeApp;
use crate::enclave_bridge::EnclaveProxy;
use crate::storage::{verify_enclave_tx, verify_public_tx, TxAction, TxEnclaveAction};
use abci::*;
use chain_core::state::account::StakedState;
use chain_core::state::tendermint::TendermintVotePower;
use chain_core::tx::data::TxId;
use chain_core::tx::fee::Fee;
use chain_core::tx::{TxAux, TxPublicAux};
use chain_storage::account::{get_staked_state, update_staked_state, StakedStateError};
use chain_tx_validation::{ChainInfo, Error};
use parity_scale_codec::Decode;

/// Wrapper to abstract over CheckTx and DeliverTx requests
pub trait RequestWithTx {
    fn tx(&self) -> &[u8];
    fn store_valid(&self) -> bool;
}

impl RequestWithTx for RequestCheckTx {
    fn tx(&self) -> &[u8] {
        &self.tx[..]
    }
    fn store_valid(&self) -> bool {
        false
    }
}

impl RequestWithTx for RequestDeliverTx {
    fn tx(&self) -> &[u8] {
        &self.tx[..]
    }
    fn store_valid(&self) -> bool {
        true
    }
}

/// Wrapper to abstract over CheckTx and DeliverTx responses
pub trait ResponseWithCodeAndLog {
    fn set_code(&mut self, _: u32);
    fn add_log(&mut self, _: &str);
}

impl ResponseWithCodeAndLog for ResponseCheckTx {
    fn set_code(&mut self, new_code: u32) {
        self.code = new_code;
    }

    fn add_log(&mut self, entry: &str) {
        self.log += entry;
    }
}

impl ResponseWithCodeAndLog for ResponseDeliverTx {
    fn set_code(&mut self, new_code: u32) {
        self.code = new_code;
    }

    fn add_log(&mut self, entry: &str) {
        self.log += entry;
    }
}

impl<T: EnclaveProxy> ChainNodeApp<T> {
    // TODO: CheckTx only against only committed states or a custom CheckTx sub-state?
    fn handle_tx(&mut self, txaux: &TxAux, tx_len: usize) -> Result<TxAction, Error> {
        let state = self.last_state.as_ref().expect("the app state is expected");
        let min_fee = state
            .top_level
            .network_params
            .calculate_fee(tx_len)
            .expect("invalid fee policy");
        let extra_info = ChainInfo {
            min_fee_computed: min_fee,
            chain_hex_id: self.chain_hex_id,
            previous_block_time: state.block_time,
            unbonding_period: state.top_level.network_params.get_unbonding_period(),
        };
        match txaux {
            TxAux::EnclaveTx(tx) => {
                let action = verify_enclave_tx(
                    &mut self.tx_validator,
                    &tx,
                    extra_info,
                    &self.uncommitted_account_root_hash,
                    &self.storage,
                    &self.accounts,
                )?;
                Ok(TxAction::Enclave(action))
            }
            TxAux::PublicTx(tx) => Ok(TxAction::Public(min_fee, tx.clone())),
        }
    }

    /// Gets CheckTx or DeliverTx requests, tries to parse its data into TxAux and validate that TxAux.
    /// Returns Some(TxAux, TxAction) if OK, or Err(String) if some problems.
    pub fn validate_tx_req(
        &mut self,
        req: &dyn RequestWithTx,
    ) -> Result<(TxAux, TxAction), String> {
        let dtx = TxAux::decode(&mut req.tx());
        match dtx {
            Err(e) => Err(format!("failed to deserialize tx: {}", e.what())),
            Ok(txaux) => {
                let result = self.handle_tx(&txaux, req.tx().len());
                match result {
                    Ok(action) => Ok((txaux, action)),
                    Err(err) => Err(format!("verification failed: {}", err.to_string())),
                }
            }
        }
    }

    pub fn execute_enclave_tx(
        &mut self,
        txid: &TxId,
        action: &TxEnclaveAction,
    ) -> (Fee, Option<StakedState>) {
        match action {
            TxEnclaveAction::Transfer {
                spend_utxo,
                sealed_log,
                fee,
                ..
            } => {
                self.storage.spend_utxos(&spend_utxo);
                // Done in commit event
                // self.storage.create_utxo(no_of_outputs, txid);
                self.storage.store_sealed_log(&txid, sealed_log);
                (*fee, None)
            }
            TxEnclaveAction::Deposit {
                fee,
                spend_utxo,
                deposit: (address, amount),
            } => {
                self.storage.spend_utxos(&spend_utxo);
                let result =
                    get_staked_state(address, &self.uncommitted_account_root_hash, &self.accounts);
                let mut account = match result {
                    Ok(account) => account,
                    Err(StakedStateError::NotFound) => StakedState::default(*address),
                    Err(StakedStateError::IoError(err)) => {
                        panic!("get staking state io error: {}", err)
                    }
                };
                account.deposit(*amount);
                let (new_root, maccount) = update_staked_state(
                    account,
                    &self.uncommitted_account_root_hash,
                    &mut self.accounts,
                );
                self.uncommitted_account_root_hash = new_root;
                self.update_account(maccount.as_ref().unwrap());
                (*fee, maccount)
            }
            TxEnclaveAction::Withdraw {
                fee,
                withdraw: (address, amount),
                sealed_log,
                ..
            } => {
                // Done in commit event
                // self.storage.create_utxo(no_of_outputs, txid);
                self.storage.store_sealed_log(&txid, sealed_log);

                // no panic: tx is verified, account should be exist.
                // operations are sequential in the state machine, so no concurrent updates
                let mut account =
                    get_staked_state(address, &self.uncommitted_account_root_hash, &self.accounts)
                        .unwrap();
                assert_eq!(&account.unbonded, amount);
                account.withdraw();
                let (new_root, maccount) = update_staked_state(
                    account,
                    &self.uncommitted_account_root_hash,
                    &mut self.accounts,
                );
                self.uncommitted_account_root_hash = new_root;
                self.update_account(maccount.as_ref().unwrap());
                (*fee, maccount)
            }
        }
    }

    pub fn execute_public_tx(
        &mut self,
        min_fee: Fee,
        txaux: &TxPublicAux,
    ) -> Result<(Fee, Option<StakedState>), String> {
        let last_state = self.last_state.as_mut().expect("the app state is expected");
        let extra_info = ChainInfo {
            min_fee_computed: min_fee,
            chain_hex_id: self.chain_hex_id,
            previous_block_time: last_state.block_time,
            unbonding_period: last_state.top_level.network_params.get_unbonding_period(),
        };
        let fee_acc = verify_public_tx(
            txaux,
            extra_info,
            &*last_state,
            &self.uncommitted_account_root_hash,
            &self.accounts,
        )
        .map_err(|err| format!("verification failed: {}", err.to_string()))?;
        let (new_root, maccount) = match txaux {
            TxPublicAux::UnbondStakeTx(_, _) => update_staked_state(
                fee_acc
                    .1
                    .clone()
                    .expect("account returned in unbond stake verification"),
                &self.uncommitted_account_root_hash,
                &mut self.accounts,
            ),
            TxPublicAux::UnjailTx(_, _) => update_staked_state(
                fee_acc
                    .1
                    .clone()
                    .expect("account returned in unjail verification"),
                &self.uncommitted_account_root_hash,
                &mut self.accounts,
            ),
            TxPublicAux::NodeJoinTx(_, _) => {
                let state = fee_acc
                    .1
                    .clone()
                    .expect("staked state returned in node join verification");
                last_state.validators.new_valid_node_join_update(&state);
                update_staked_state(
                    state,
                    &self.uncommitted_account_root_hash,
                    &mut self.accounts,
                )
            }
        };
        self.uncommitted_account_root_hash = new_root;
        self.update_account(maccount.as_ref().unwrap());
        Ok(fee_acc)
    }

    fn update_account(&mut self, account: &StakedState) {
        let last_state = self.last_state.as_mut().unwrap();
        last_state
            .validators
            .validator_state_helper
            .voting_power_update(
                account,
                TendermintVotePower::from(
                    last_state
                        .top_level
                        .network_params
                        .get_required_council_node_stake(),
                ),
            );
    }
}
