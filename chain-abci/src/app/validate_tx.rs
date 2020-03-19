use super::ChainNodeState;
use crate::enclave_bridge::EnclaveProxy;
use crate::storage::{verify_enclave_tx, verify_public_tx, TxAction, TxEnclaveAction};
use abci::*;
use chain_core::state::account::StakedState;
use chain_core::state::tendermint::TendermintVotePower;
use chain_core::tx::data::TxId;
use chain_core::tx::fee::Fee;
use chain_core::tx::{TxAux, TxPublicAux};
use chain_storage::buffer::{GetKV, GetStaking, StoreKV, StoreStaking};
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

fn handle_tx<T: EnclaveProxy>(
    trie: &impl GetStaking,
    kvdb: &impl GetKV,
    tx_validator: &mut T,
    txaux: &TxAux,
    extra_info: &ChainInfo,
) -> Result<TxAction, Error> {
    match txaux {
        TxAux::EnclaveTx(tx) => {
            let action = verify_enclave_tx(tx_validator, &tx, extra_info, trie, kvdb)?;
            Ok(TxAction::Enclave(action))
        }
        TxAux::PublicTx(tx) => Ok(TxAction::Public(tx.clone())),
    }
}

/// Gets CheckTx or DeliverTx requests, tries to parse its data into TxAux and validate that TxAux.
/// Returns Some(TxAux, TxAction) if OK, or Err(String) if some problems.
pub fn validate_tx_req<T: EnclaveProxy>(
    trie: &impl GetStaking,
    kvdb: &impl GetKV,
    tx_validator: &mut T,
    req: &impl RequestWithTx,
    extra_info: &ChainInfo,
) -> Result<(TxAux, TxAction), String> {
    let dtx = TxAux::decode(&mut req.tx());
    match dtx {
        Err(e) => Err(format!("failed to deserialize tx: {}", e.what())),
        Ok(txaux) => {
            let result = handle_tx(trie, kvdb, tx_validator, &txaux, extra_info);
            match result {
                Ok(action) => Ok((txaux, action)),
                Err(err) => Err(format!("verification failed: {}", err.to_string())),
            }
        }
    }
}

pub fn execute_enclave_tx(
    trie: &mut impl StoreStaking,
    kvdb: &mut impl StoreKV,
    state: &mut ChainNodeState,
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
            chain_storage::spend_utxos(kvdb, &spend_utxo);
            // Done in commit event
            // chain_storage::create_utxo(kvdb, no_of_outputs, txid);
            chain_storage::store_sealed_log(kvdb, &txid, sealed_log);
            (*fee, None)
        }
        TxEnclaveAction::Deposit {
            fee,
            spend_utxo,
            deposit: (address, amount),
        } => {
            chain_storage::spend_utxos(kvdb, &spend_utxo);
            let mut account = trie.get_or_default(&address);
            account.deposit(*amount);
            trie.set_staking(account.clone());
            update_account(state, &account);
            (*fee, Some(account))
        }
        TxEnclaveAction::Withdraw {
            fee,
            withdraw: (address, amount),
            sealed_log,
            ..
        } => {
            // Done in commit event
            // chain_storage::create_utxo(kvdb, no_of_outputs, txid);
            chain_storage::store_sealed_log(kvdb, &txid, sealed_log);

            // no panic: tx is verified, account should be exist.
            // operations are sequential in the state machine, so no concurrent updates
            let mut account = trie.get(&address).unwrap();
            assert_eq!(&account.unbonded, amount);
            account.withdraw();
            trie.set_staking(account.clone());
            update_account(state, &account);
            (*fee, Some(account))
        }
    }
}

pub fn execute_public_tx(
    trie: &mut impl StoreStaking,
    state: &mut ChainNodeState,
    txaux: &TxPublicAux,
    extra_info: &ChainInfo,
) -> Result<(Fee, Option<StakedState>), String> {
    let fee_acc = verify_public_tx(txaux, extra_info, &*state, trie)
        .map_err(|err| format!("verification failed: {}", err.to_string()))?;
    let staking = fee_acc
        .1
        .clone()
        .expect("account returned in unbond stake verification");
    match txaux {
        TxPublicAux::UnbondStakeTx(_, _) => trie.set_staking(staking.clone()),
        TxPublicAux::UnjailTx(_, _) => trie.set_staking(staking.clone()),
        TxPublicAux::NodeJoinTx(_, _) => {
            state.validators.new_valid_node_join_update(&staking);
            trie.set_staking(staking.clone())
        }
    };
    update_account(state, &staking);
    Ok(fee_acc)
}

fn update_account(state: &mut ChainNodeState, account: &StakedState) {
    state.validators.validator_state_helper.voting_power_update(
        account,
        TendermintVotePower::from(
            state
                .top_level
                .network_params
                .get_required_council_node_stake(),
        ),
    );
}
