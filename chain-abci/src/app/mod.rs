mod app_init;
mod commit;
mod jail_account;
mod query;
mod slash_accounts;
mod validate_tx;

use abci::*;
use log::info;

pub use self::app_init::{ChainNodeApp, ChainNodeState};
use crate::enclave_bridge::EnclaveProxy;
use crate::liveness::LivenessTracker;
use crate::slashing::SlashingSchedule;
use crate::storage::account::AccountStorage;
use crate::storage::account::AccountWrapper;
use crate::storage::tx::StarlingFixedKey;
use crate::storage::COL_TX_META;
use bit_vec::BitVec;
use chain_core::common::TendermintEventType;
use chain_core::state::account::StakedState;
use chain_core::state::tendermint::{
    BlockHeight, TendermintValidatorAddress, TendermintValidatorPubKey, TendermintVotePower,
};
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::{TxAux, TxEnclaveAux};
use chain_tx_filter::BlockFilter;
use enclave_protocol::{EnclaveRequest, EnclaveResponse};
use kvdb::{DBTransaction, KeyValueDB};
use protobuf::RepeatedField;
use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;

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
) -> (StarlingFixedKey, Option<StakedState>) {
    (
        accounts
            .insert_one(
                Some(account_root_hash),
                &account.key(),
                &AccountWrapper(account.clone()),
            )
            .expect("update account"),
        Some(account),
    )
}

/// TODO: sanity checks in abci https://github.com/tendermint/rust-abci/issues/49
impl<T: EnclaveProxy> abci::Application for ChainNodeApp<T> {
    /// Query Connection: Called on startup from Tendermint.  The application should normally
    /// return the last know state so Tendermint can determine if it needs to replay blocks
    /// to the application.
    fn info(&mut self, _req: &RequestInfo) -> ResponseInfo {
        info!("received info request");
        let mut resp = ResponseInfo::new();
        if let Some(app_state) = &self.last_state {
            resp.last_block_app_hash = app_state.last_apphash.to_vec();
            resp.last_block_height = app_state.last_block_height;
            resp.data = serde_json::to_string(&app_state).expect("serialize app state to json");
        } else {
            resp.last_block_app_hash = self.genesis_app_hash.to_vec();
        }
        resp
    }

    /// Query Connection: Query your application. This usually resolves through a merkle tree holding
    /// the state of the app.
    fn query(&mut self, _req: &RequestQuery) -> ResponseQuery {
        info!("received query request");
        ChainNodeApp::query_handler(self, _req)
    }

    /// Mempool Connection:  Used to validate incoming transactions.  If the application reponds
    /// with a non-zero value, the transaction is added to Tendermint's mempool for processing
    /// on the deliver_tx call below.
    fn check_tx(&mut self, _req: &RequestCheckTx) -> ResponseCheckTx {
        info!("received checktx request");
        let mut resp = ResponseCheckTx::new();
        ChainNodeApp::validate_tx_req(self, _req, &mut resp);
        resp
    }

    /// Consensus Connection:  Called once on startup. Usually used to establish initial (genesis)
    /// state.
    fn init_chain(&mut self, _req: &RequestInitChain) -> ResponseInitChain {
        info!("received initchain request");
        ChainNodeApp::init_chain_handler(self, _req)
    }

    /// Consensus Connection: Called at the start of processing a block of transactions
    /// The flow is:
    /// begin_block()
    ///   deliver_tx()  for each transaction in the block
    /// end_block()
    /// commit()
    fn begin_block(&mut self, req: &RequestBeginBlock) -> ResponseBeginBlock {
        info!("received beginblock request");
        // TODO: process RequestBeginBlock -- e.g. rewards for validators? + punishment for malicious ByzantineValidators
        // TODO: Check security implications once https://github.com/tendermint/tendermint/issues/2653 is closed
        let (block_height, block_time) = match req.header.as_ref() {
            None => panic!("No block header in begin block request from tendermint"),
            Some(header) => (
                header.height,
                header
                    .time
                    .as_ref()
                    .expect("No timestamp in begin block request from tendermint")
                    .seconds,
            ),
        };

        let last_state = self
            .last_state
            .as_mut()
            .expect("executing begin block, but no app state stored (i.e. no initchain or recovery was executed)");

        last_state.block_time = block_time;

        if block_height > 1 {
            if let Some(last_commit_info) = req.last_commit_info.as_ref() {
                // liveness will always be updated for previous block, i.e., `block_height - 1`
                update_validator_liveness(last_state, block_height - 1, last_commit_info);
            } else {
                panic!(
                    "No last commit info in begin block request for height: {}",
                    block_height
                );
            }
        }

        let mut accounts_to_punish = Vec::new();

        for evidence in req.byzantine_validators.iter() {
            if let Some(validator) = evidence.validator.as_ref() {
                let validator_address =
                    TendermintValidatorAddress::try_from(validator.address.as_slice())
                        .expect("Invalid validator address in begin block request");
                let account_address = last_state
                    .punishment
                    .validator_liveness
                    .get(&validator_address)
                    .expect("Validator not found in liveness tracker")
                    .address();

                accounts_to_punish.push((
                    account_address,
                    last_state.slashing_config.byzantine_slash_percent,
                ))
            }
        }

        let missed_block_threshold = last_state.jailing_config.missed_block_threshold;

        accounts_to_punish.extend(
            last_state
                .punishment
                .validator_liveness
                .values()
                .filter(|tracker| !tracker.is_live(missed_block_threshold))
                .map(|liveness_tracker| {
                    (
                        liveness_tracker.address(),
                        last_state.slashing_config.liveness_slash_percent,
                    )
                }),
        );

        let slashing_time =
            last_state.block_time + i64::from(last_state.slashing_config.slash_wait_period);
        let slashing_proportion =
            self.get_slashing_proportion(accounts_to_punish.iter().map(|x| x.0));

        let mut jailing_event = Event::new();
        jailing_event.field_type = TendermintEventType::JailValidators.to_string();

        let last_state = self
            .last_state
            .as_mut()
            .expect("executing begin block, but no app state stored (i.e. no initchain or recovery was executed)");

        for (account_address, slash_ratio) in accounts_to_punish.iter() {
            match last_state
                .punishment
                .slashing_schedule
                .get_mut(&account_address)
            {
                Some(account_slashing_schedule) => {
                    account_slashing_schedule
                        .update_slash_ratio((*slash_ratio) * slashing_proportion);
                }
                None => {
                    last_state.punishment.slashing_schedule.insert(
                        *account_address,
                        SlashingSchedule::new((*slash_ratio) * slashing_proportion, slashing_time),
                    );
                }
            }
        }

        for (account_address, _) in accounts_to_punish {
            let mut kvpair = KVPair::new();
            kvpair.key = b"account".to_vec();
            kvpair.value = account_address.to_string().into_bytes();

            jailing_event.attributes.push(kvpair);

            self.jail_account(account_address)
                .expect("Unable to jail account in begin block");
        }

        let slashing_event = self
            .slash_eligible_accounts()
            .expect("Unable to slash accounts in slashing queue");

        let mut response = ResponseBeginBlock::new();

        if !jailing_event.attributes.is_empty() {
            response.events.push(jailing_event);
        }

        if !slashing_event.attributes.is_empty() {
            response.events.push(slashing_event);
        }

        response
    }

    /// Consensus Connection: Actually processing the transaction, performing some form of a
    /// state transistion.
    fn deliver_tx(&mut self, _req: &RequestDeliverTx) -> ResponseDeliverTx {
        info!("received delivertx request");
        let mut resp = ResponseDeliverTx::new();
        let mtxaux = ChainNodeApp::validate_tx_req(self, _req, &mut resp);
        if let (0, Some((txaux, fee_acc))) = (resp.code, mtxaux) {
            let mut inittx = self.storage.db.transaction();
            let (next_account_root, maccount) = match &txaux {
                TxAux::EnclaveTx(TxEnclaveAux::TransferTx { inputs, .. }) => {
                    // here the original idea was "conservative" that it "spent" utxos here
                    // but it didn't create utxos for this TX (they are created in commit)
                    spend_utxos(&inputs, self.storage.db.clone(), &mut inittx);
                    (self.uncommitted_account_root_hash, None)
                }
                TxAux::EnclaveTx(TxEnclaveAux::DepositStakeTx { tx, .. }) => {
                    spend_utxos(&tx.inputs, self.storage.db.clone(), &mut inittx);
                    update_account(
                        fee_acc
                            .1
                            .expect("account returned in deposit stake verification"),
                        &self.uncommitted_account_root_hash,
                        &mut self.accounts,
                    )
                }
                TxAux::UnbondStakeTx(_, _) => update_account(
                    fee_acc
                        .1
                        .expect("account returned in unbond stake verification"),
                    &self.uncommitted_account_root_hash,
                    &mut self.accounts,
                ),
                TxAux::EnclaveTx(TxEnclaveAux::WithdrawUnbondedStakeTx { .. }) => update_account(
                    fee_acc
                        .1
                        .expect("account returned in withdraw unbonded stake verification"),
                    &self.uncommitted_account_root_hash,
                    &mut self.accounts,
                ),
                TxAux::UnjailTx(_, _) => update_account(
                    fee_acc.1.expect("account returned in unjail verification"),
                    &self.uncommitted_account_root_hash,
                    &mut self.accounts,
                ),
            };
            let mut event = Event::new();
            event.field_type = TendermintEventType::ValidTransactions.to_string();
            let mut kvpair_fee = KVPair::new();
            kvpair_fee.key = Vec::from(&b"fee"[..]);
            kvpair_fee.value = Vec::from(format!("{}", fee_acc.0.to_coin()));
            event.attributes.push(kvpair_fee);

            if let Some(ref account) = maccount {
                // FIXME: no need to add to the filter / maintain this filter in abci
                self.filter.add_staked_state_address(&account.address);
                let mut kvpair = KVPair::new();
                kvpair.key = Vec::from(&b"account"[..]);
                kvpair.value = Vec::from(format!("{}", &account.address));
                event.attributes.push(kvpair);
            }
            match maccount {
                Some(ref account) if self.validator_voting_power.contains_key(&account.address) => {
                    if account.is_jailed() {
                        log::error!("Validation should not be successful for jailed accounts");
                        unreachable!("Validation should not be successful for jailed accounts");
                    } else {
                        let min_power = TendermintVotePower::from(
                            self.last_state
                                .as_ref()
                                .expect("delivertx should have app state")
                                .required_council_node_stake,
                        );
                        let new_power = TendermintVotePower::from(account.bonded);
                        let old_power = self.validator_voting_power[&account.address];
                        if new_power > old_power && new_power >= min_power {
                            self.power_changed_in_block
                                .insert(account.address, new_power);
                        } else if old_power >= min_power && new_power < old_power {
                            self.power_changed_in_block
                                .insert(account.address, TendermintVotePower::zero());
                        }
                    }
                }
                _ => {}
            };
            // as self.accounts allows querying against different tree roots
            // the modifications done with "update_account" _should_ be safe, as the final tree root will
            // be persisted in commit.
            // The question is whether it really is -- e.g. if Tendermint/ABCI app crashes during DeliverTX
            // and then it tries to replay the block on the restart, will it cause problems
            // with the account storage (starling / MerkleBIT), because it already persisted those "future" / not-yet-committed account states?
            // TODO: check-verify / test starling persistence safety?
            // TODO: most of these intermediate uncommitted tree roots aren't useful (not exposed for querying) -- prune them / the account storage?
            self.uncommitted_account_root_hash = next_account_root;
            let mut kvpair = KVPair::new();
            kvpair.key = Vec::from(&b"txid"[..]);
            kvpair.value = Vec::from(hex::encode(txaux.tx_id()).as_bytes());
            event.attributes.push(kvpair);
            resp.events.push(event);
            self.delivered_txs.push(txaux);
            let rewards_pool = &mut self
                .last_state
                .as_mut()
                .expect("deliver tx, but last state not initialized")
                .rewards_pool;
            let new_remaining = (rewards_pool.remaining + fee_acc.0.to_coin())
                .expect("rewards pool + fee greater than max coin?");
            rewards_pool.remaining = new_remaining;
            // this "buffered write" shouldn't persist (persistence done in commit)
            // but should change it in-memory -- TODO: check
            self.storage.db.write_buffered(inittx);
        }
        resp
    }

    /// Consensus Connection: Called at the end of the block.  Often used to update the validator set.
    fn end_block(&mut self, _req: &RequestEndBlock) -> ResponseEndBlock {
        info!("received endblock request");
        let mut resp = ResponseEndBlock::new();
        if !self.delivered_txs.is_empty() {
            let end_block_resp = self.tx_validator.process_request(EnclaveRequest::EndBlock);
            if let EnclaveResponse::EndBlock(Ok(raw_filter)) = end_block_resp {
                let filter = BlockFilter::from(&*raw_filter);
                self.filter.add_filter(&filter);
            } else {
                panic!("end block request to obtain the block filter failed");
            }
        }
        if let Some((key, value)) = self.filter.get_tendermint_kv() {
            let mut kvpair = KVPair::new();
            kvpair.key = key;
            kvpair.value = value;
            let mut event = Event::new();
            event.field_type = TendermintEventType::BlockFilter.to_string();
            event.attributes.push(kvpair);
            resp.events.push(event);
        }
        self.filter.reset();
        // TODO: skipchain-based validator changes?
        if !self.power_changed_in_block.is_empty() {
            let mut validators = Vec::with_capacity(self.power_changed_in_block.len());
            for (address, new_power) in self.power_changed_in_block.iter() {
                let old_power = self.validator_voting_power[&address];
                // sanity check, as multiple transactions/events may have cancelled out the vote power change
                if old_power != *new_power {
                    let mut validator = ValidatorUpdate::default();
                    validator.set_power(i64::from(*new_power));
                    validator.set_pub_key(self.validator_pubkeys[&address].clone());
                    validators.push(validator);

                    let last_state = self
                        .last_state
                        .as_mut()
                        .expect("Last app state not found, init chain was not called");

                    let validator_liveness = &mut last_state.punishment.validator_liveness;

                    let validator_address: TendermintValidatorAddress =
                        into_tendermint_validator_pub_key(&self.validator_pubkeys[&address]).into();

                    let new_vote_power: i64 = (*new_power).into();

                    if new_vote_power == 0 && validator_liveness.contains_key(&validator_address) {
                        validator_liveness.remove(&validator_address);
                    } else if new_vote_power != 0
                        && !validator_liveness.contains_key(&validator_address)
                    {
                        validator_liveness.insert(
                            validator_address,
                            LivenessTracker::new(
                                *address,
                                last_state.jailing_config.block_signing_window,
                            ),
                        );
                    }
                }
                self.validator_voting_power.insert(*address, *new_power);
            }
            resp.set_validator_updates(RepeatedField::from(validators));
            self.power_changed_in_block.clear();
        }
        self.last_state.as_mut().map(|mut x| x.last_block_height = _req.height)
            .expect("executing end block, but no app state stored (i.e. no initchain or recovery was executed)");
        resp
    }

    /// Consensus Connection: Commit the block with the latest state from the application.
    fn commit(&mut self, _req: &RequestCommit) -> ResponseCommit {
        info!("received commit request");
        ChainNodeApp::commit_handler(self, _req)
    }
}

fn update_validator_liveness(
    state: &mut ChainNodeState,
    block_height: BlockHeight,
    last_commit_info: &LastCommitInfo,
) {
    log::debug!("Updating validator liveness for block: {}", block_height);

    for vote_info in last_commit_info.votes.iter() {
        let address: TendermintValidatorAddress = vote_info
            .validator
            .as_ref()
            .expect("No validator address in vote_info")
            .address
            .as_slice()
            .try_into()
            .expect("Invalid address in vote_info");
        let signed = vote_info.signed_last_block;

        log::trace!(
            "Updating validator liveness for {} with {}",
            address,
            signed
        );

        match state.punishment.validator_liveness.get_mut(&address) {
            Some(liveness_tracker) => {
                liveness_tracker.update(block_height, signed);
            }
            None => {
                log::warn!("Validator in `last_commit_info` not found in liveness tracker");
            }
        }
    }
}

/// Converts `abci::PubKey` into `TendermintValidatorPubKey`
pub fn into_tendermint_validator_pub_key(pubkey: &PubKey) -> TendermintValidatorPubKey {
    if pubkey.field_type != "ed25519" {
        panic!("Received invalid pubkey type");
    }

    if pubkey.data.len() != 32 {
        panic!("Reviced pubkey of invalid length");
    }

    let mut bytes = [0; 32];
    bytes.copy_from_slice(&pubkey.data);

    TendermintValidatorPubKey::Ed25519(bytes)
}
