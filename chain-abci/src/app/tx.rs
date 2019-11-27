use std::collections::BTreeMap;
use std::sync::Arc;

use bit_vec::BitVec;
use kvdb::{DBTransaction, KeyValueDB};
use parity_scale_codec::Decode;

use chain_core::state::account::StakedState;
use chain_core::state::tendermint::TendermintVotePower;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::fee::Fee;
use chain_core::tx::{data::TxId, TxAux, TxEnclaveAux};
use chain_tx_validation::{ChainInfo, Error, NodeInfo};

use super::ChainNodeApp;
use crate::enclave_bridge::EnclaveProxy;
use crate::storage::account::AccountStorage;
use crate::storage::account::AccountWrapper;
use crate::storage::tx::StarlingFixedKey;
use crate::storage::tx::{verify_enclave_tx, verify_public_tx};
use crate::storage::COL_TX_META;

/// Given a db and a DB transaction, it will go through TX inputs and mark them as spent
/// in the TX_META storage.
pub fn spend_utxos(txins: &[TxoPointer], db: Arc<dyn KeyValueDB>, dbtx: &mut DBTransaction) {
    let mut updated_txs = BTreeMap::new();
    for txin in txins.iter() {
        updated_txs
            .entry(txin.id)
            .or_insert_with(|| {
                BitVec::from_bytes(&db.get(COL_TX_META, &txin.id[..]).unwrap().unwrap())
            })
            .set(txin.index as usize, true);
    }
    for (txid, bv) in &updated_txs {
        dbtx.put(COL_TX_META, &txid[..], &bv.to_bytes());
    }
}

/// Given the Account state storage and the current / uncommitted account storage root,
/// it inserts the updated account state into the account storage and returns the new root hash of the account state trie.
pub fn update_account(
    account: StakedState,
    account_root_hash: &StarlingFixedKey,
    accounts: &mut AccountStorage,
) -> Result<(StarlingFixedKey, Option<StakedState>), String> {
    Ok((
        accounts
            .insert_one(
                Some(account_root_hash),
                &account.key(),
                &AccountWrapper(account.clone()),
            )
            .map_err(|e| format!("insert account failed: {}", e.to_string()))?,
        Some(account),
    ))
}

impl<T: EnclaveProxy> ChainNodeApp<T> {
    fn verify_tx(
        &mut self,
        txaux: &TxAux,
        tx_len: usize,
    ) -> Result<(Fee, Option<StakedState>), Error> {
        let state = self.last_state.as_ref().expect("the app state is expected");
        let min_fee = state
            .network_params
            .calculate_fee(tx_len)
            .map_err(|_| Error::FeeCalculationError)?;
        let extra_info = ChainInfo {
            min_fee_computed: min_fee,
            chain_hex_id: self.chain_hex_id,
            previous_block_time: state.block_time,
            unbonding_period: state.network_params.get_unbonding_period(),
        };
        match txaux {
            TxAux::EnclaveTx(tx) => verify_enclave_tx(
                &mut self.tx_validator,
                &tx,
                extra_info,
                &self.uncommitted_account_root_hash,
                self.storage.db.clone(),
                &self.accounts,
            ),
            _ => {
                let node_info = NodeInfo {
                    minimal_stake: state.network_params.get_required_council_node_stake(),
                    tendermint_validator_addresses: &state
                        .validators
                        .tendermint_validator_addresses,
                    validator_voting_power: &self.validator_voting_power,
                };
                verify_public_tx(
                    &txaux,
                    extra_info,
                    node_info,
                    &self.uncommitted_account_root_hash,
                    &self.accounts,
                )
            }
        }
    }

    /// Gets CheckTx or DeliverTx requests, tries to parse its data into TxAux and validate that TxAux.
    /// Returns Some(parsed txaux, (paid fee, updated staking account)) if OK, or None if some problems (and sets log + error code in the passed in response).
    pub fn validate_tx_req(
        &mut self,
        mut raw_tx: &[u8],
    ) -> Result<(TxAux, Fee, Option<StakedState>), String> {
        let txaux = TxAux::decode(&mut raw_tx)
            .map_err(|e| format!("failed to deserialize tx: {}", e.what()))?;
        let (fee, account) = self
            .verify_tx(&txaux, raw_tx.len())
            .map_err(|e| format!("verification failed: {}", e))?;
        Ok((txaux, fee, account))
    }

    pub fn deliver_tx_req(
        &mut self,
        raw_tx: &[u8],
    ) -> Result<(TxId, Fee, Option<StakedState>), String> {
        let (txaux, fee, account) = self.validate_tx_req(raw_tx)?;
        let txid = txaux.tx_id();
        let account = self.process_tx(txaux, fee, account)?;
        Ok((txid, fee, account))
    }

    pub fn process_tx(
        &mut self,
        txaux: TxAux,
        fee: Fee,
        account: Option<StakedState>,
    ) -> Result<Option<StakedState>, String> {
        let mut inittx = self.storage.db.transaction();
        let (next_account_root, account) = match &txaux {
            TxAux::EnclaveTx(TxEnclaveAux::TransferTx { inputs, .. }) => {
                // here the original idea was "conservative" that it "spent" utxos here
                // but it didn't create utxos for this TX (they are created in commit)
                spend_utxos(&inputs, self.storage.db.clone(), &mut inittx);
                (self.uncommitted_account_root_hash, None)
            }
            TxAux::EnclaveTx(TxEnclaveAux::DepositStakeTx { tx, .. }) => {
                spend_utxos(&tx.inputs, self.storage.db.clone(), &mut inittx);
                update_account(
                    account.ok_or("no account returned in deposit stake verification")?,
                    &self.uncommitted_account_root_hash,
                    &mut self.accounts,
                )?
            }
            TxAux::UnbondStakeTx(_, _) => update_account(
                account.ok_or("no account returned in unbond stake verification")?,
                &self.uncommitted_account_root_hash,
                &mut self.accounts,
            )?,
            TxAux::EnclaveTx(TxEnclaveAux::WithdrawUnbondedStakeTx { .. }) => update_account(
                account.ok_or("no account returned in withdraw unbonded stake verification")?,
                &self.uncommitted_account_root_hash,
                &mut self.accounts,
            )?,
            TxAux::UnjailTx(_, _) => update_account(
                account.ok_or("no account returned in unjail verification")?,
                &self.uncommitted_account_root_hash,
                &mut self.accounts,
            )?,
            TxAux::NodeJoinTx(_, _) => {
                let state = account.ok_or("no staked state returned in node join verification")?;
                self.new_nodes_in_block.insert(
                    state.address,
                    state
                        .council_node
                        .clone()
                        .ok_or("state after nodejointx should have council node")?,
                );
                let power = TendermintVotePower::from(state.bonded);
                self.power_changed_in_block.insert(state.address, power);
                update_account(
                    state,
                    &self.uncommitted_account_root_hash,
                    &mut self.accounts,
                )?
            }
        };

        if let Some(ref account) = account {
            if self.validator_voting_power.contains_key(&account.address)
                || self.power_changed_in_block.contains_key(&account.address)
            {
                if account.is_jailed() {
                    log::error!("Validation should not be successful for jailed accounts");
                    unreachable!("Validation should not be successful for jailed accounts");
                } else {
                    let min_power = TendermintVotePower::from(
                        self.last_state
                            .as_ref()
                            .ok_or("delivertx should have app state")?
                            .network_params
                            .get_required_council_node_stake(),
                    );
                    let new_power = TendermintVotePower::from(account.bonded);
                    let old_power = self
                        .validator_voting_power
                        .get(&account.address)
                        .copied()
                        .unwrap_or_else(TendermintVotePower::zero);
                    if new_power > old_power && new_power >= min_power {
                        self.power_changed_in_block
                            .insert(account.address, new_power);
                    } else if old_power >= min_power && new_power < old_power {
                        self.power_changed_in_block
                            .insert(account.address, TendermintVotePower::zero());
                    }
                }
            }
        }

        // as self.accounts allows querying against different tree roots
        // the modifications done with "update_account" _should_ be safe, as the final tree root will
        // be persisted in commit.
        // The question is whether it really is -- e.g. if Tendermint/ABCI app crashes during DeliverTX
        // and then it tries to replay the block on the restart, will it cause problems
        // with the account storage (starling / MerkleBIT), because it already persisted those "future" / not-yet-committed account states?
        // TODO: check-verify / test starling persistence safety?
        // TODO: most of these intermediate uncommitted tree roots aren't useful (not exposed for querying) -- prune them / the account storage?
        self.uncommitted_account_root_hash = next_account_root;

        self.delivered_txs.push(txaux);
        let rewards_pool = &mut self
            .last_state
            .as_mut()
            .ok_or("deliver tx, but last state not initialized")?
            .rewards_pool;
        rewards_pool.remaining = (rewards_pool.remaining + fee.to_coin())
            .map_err(|e| format!("rewards pool overflow {}", e.to_string()))?;
        self.rewards_pool_updated = true;
        // this "buffered write" shouldn't persist (persistence done in commit)
        // but should change it in-memory -- TODO: check
        self.storage.db.write_buffered(inittx);

        Ok(account)
    }
}
