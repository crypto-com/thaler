mod app_init;
mod commit;
mod end_block;
mod jail_account;
mod query;
mod rewards;
mod slash_accounts;
mod validate_tx;

use abci::*;
use log::info;

#[cfg(fuzzing)]
pub use self::app_init::check_validators;
pub use self::app_init::{
    compute_accounts_root, get_validator_key, init_app_hash, ChainNodeApp, ChainNodeState,
    ValidatorState,
};
use crate::app::validate_tx::ResponseWithCodeAndLog;
use crate::enclave_bridge::EnclaveProxy;
use crate::storage::{get_account, TxAction};
use chain_core::common::{TendermintEventKey, TendermintEventType, Timespec};
use chain_core::state::account::PunishmentKind;
use chain_core::state::tendermint::{BlockHeight, TendermintValidatorAddress};
use slash_accounts::{get_slashing_proportion, get_vote_power_in_milli};
use std::convert::{TryFrom, TryInto};

fn get_version() -> String {
    format!(
        "{} {}:{}",
        env!("CARGO_PKG_VERSION"),
        env!("VERGEN_BUILD_DATE"),
        env!("VERGEN_SHA_SHORT")
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
            resp.last_block_height = app_state.last_block_height.value().try_into().unwrap();
            resp.app_version = chain_core::APP_VERSION;
            resp.version = get_version();
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
        match ChainNodeApp::validate_tx_req(self, _req) {
            Ok(_) => {
                resp.set_code(0);
            }
            Err(msg) => {
                resp.set_code(1);
                resp.add_log(&msg);
                log::warn!("check tx failed: {}", msg);
            }
        }
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
        // TODO: Check security implications once https://github.com/tendermint/tendermint/issues/2653 is closed
        let (block_height, block_time, proposer_address): (BlockHeight, Timespec, _) =
            match req.header.as_ref() {
                None => panic!("No block header in begin block request from tendermint"),
                Some(header) => (
                    header.height.try_into().unwrap(),
                    header
                        .time
                        .as_ref()
                        .expect("No timestamp in begin block request from tendermint")
                        .seconds
                        .try_into()
                        .expect("invalid block time"),
                    TendermintValidatorAddress::try_from(header.proposer_address.as_slice()),
                ),
            };

        let last_state = self
            .last_state
            .as_mut()
            .expect("executing begin block, but no app state stored (i.e. no initchain or recovery was executed)");

        last_state.block_time = block_time;
        last_state.validators.metadata_clean(last_state.block_time);
        if let Some(prev_height) = block_height.checked_sub(1) {
            // if previous block is not genesis, last_commit_info should be exists
            if prev_height > BlockHeight::genesis() {
                if let Some(last_commit_info) = req.last_commit_info.as_ref() {
                    // liveness will always be updated for previous block, i.e., `block_height - 1`
                    update_validator_liveness(
                        &mut last_state.validators,
                        prev_height,
                        last_commit_info,
                    );
                } else {
                    panic!(
                        "No last commit info in begin block request for height: {}",
                        block_height
                    );
                }
            }
        }

        let mut accounts_to_punish = Vec::new();

        for evidence in req.byzantine_validators.iter() {
            if let Some(validator) = evidence.validator.as_ref() {
                let validator_address =
                    TendermintValidatorAddress::try_from(validator.address.as_slice())
                        .expect("Invalid validator address in begin block request");

                let account_address = last_state.validators.lookup_address(&validator_address);

                accounts_to_punish.push((
                    *account_address,
                    last_state
                        .top_level
                        .network_params
                        .get_byzantine_slash_percent(),
                    PunishmentKind::ByzantineFault,
                ))
            }
        }

        let missed_block_threshold = last_state
            .top_level
            .network_params
            .get_missed_block_threshold();

        accounts_to_punish.extend(
            last_state.validators.get_nonlive_validators(
                missed_block_threshold,
                last_state
                    .top_level
                    .network_params
                    .get_liveness_slash_percent(),
            ),
        );

        let slashing_time =
            last_state.block_time + last_state.top_level.network_params.get_slash_wait_period();
        let accounts = &self.accounts;
        let last_root = last_state.top_level.account_root;
        let total_vp = get_vote_power_in_milli(
            last_state
                .validators
                .validator_state_helper
                .get_validator_total_bonded(&last_root, &accounts),
        );
        let slashing_proportion = get_slashing_proportion(
            accounts_to_punish.iter().map(|x| {
                (
                    x.0,
                    get_account(&x.0, &last_root, &accounts)
                        .expect("io error or validator account not exists")
                        .bonded,
                )
            }),
            total_vp,
        );

        let mut jailing_event = Event::new();
        jailing_event.field_type = TendermintEventType::JailValidators.to_string();

        let last_state = self
            .last_state
            .as_mut()
            .expect("executing begin block, but no app state stored (i.e. no initchain or recovery was executed)");

        last_state.validators.update_punishment_schedules(
            slashing_proportion,
            slashing_time,
            accounts_to_punish.iter(),
        );

        for (account_address, _, punishment_kind) in accounts_to_punish {
            let mut kvpair = KVPair::new();
            kvpair.key = TendermintEventKey::Account.into();
            kvpair.value = account_address.to_string().into_bytes();

            jailing_event.attributes.push(kvpair);

            self.jail_account(account_address, punishment_kind)
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

        // FIXME: record based on votes
        if let Ok(proposer_address) = proposer_address {
            self.rewards_record_proposer(&proposer_address);
        } else {
            log::error!("invalid proposer address");
        }
        if let Some((distributed, minted)) = self.rewards_try_distribute() {
            let mut event = Event::new();
            event.field_type = TendermintEventType::RewardsDistribution.to_string();

            let mut kvpair = KVPair::new();
            kvpair.key = TendermintEventKey::RewardsDistribution.into();
            kvpair.value = serde_json::to_string(&distributed)
                .expect("encode rewards result failed")
                .as_bytes()
                .to_owned();
            event.attributes.push(kvpair);

            let mut kvpair = KVPair::new();
            kvpair.key = TendermintEventKey::CoinMinted.into();
            kvpair.value = minted.to_string().as_bytes().to_owned();
            event.attributes.push(kvpair);

            response.events.push(event);
        }

        response
    }

    /// Consensus Connection: Actually processing the transaction, performing some form of a
    /// state transistion.
    fn deliver_tx(&mut self, _req: &RequestDeliverTx) -> ResponseDeliverTx {
        info!("received delivertx request");
        let mut resp = ResponseDeliverTx::new();
        let mtxaux = ChainNodeApp::validate_tx_req(self, _req);
        let mut event = Event::new();
        event.field_type = TendermintEventType::ValidTransactions.to_string();
        let result = mtxaux.and_then(|(txaux, action)| {
            let (fee, maccount) = match &action {
                TxAction::Enclave(action) => self.execute_enclave_tx(&txaux.tx_id(), action),
                TxAction::Public(fee) => self.execute_public_tx(*fee, &txaux)?,
            };
            Ok((txaux, fee, maccount))
        });
        match result {
            Ok((txaux, fee, maccount)) => {
                resp.set_code(0);

                // write fee into event
                let mut kvpair_fee = KVPair::new();
                kvpair_fee.key = TendermintEventKey::Fee.into();
                kvpair_fee.value = Vec::from(format!("{}", fee.to_coin()));
                event.attributes.push(kvpair_fee);

                if let Some(account) = maccount {
                    let mut kvpair = KVPair::new();
                    kvpair.key = TendermintEventKey::Account.into();
                    kvpair.value = Vec::from(format!("{}", &account.address));
                    event.attributes.push(kvpair);
                }

                let mut kvpair = KVPair::new();
                kvpair.key = TendermintEventKey::TxId.into();
                kvpair.value = Vec::from(hex::encode(txaux.tx_id()).as_bytes());
                event.attributes.push(kvpair);
                resp.events.push(event);
                self.delivered_txs.push(txaux);
                let rewards_pool = &mut self
                    .last_state
                    .as_mut()
                    .expect("deliver tx, but last state not initialized")
                    .top_level
                    .rewards_pool;
                let new_remaining = (rewards_pool.period_bonus + fee.to_coin())
                    .expect("rewards pool + fee greater than max coin?");
                rewards_pool.period_bonus = new_remaining;
                self.rewards_pool_updated = true;
            }
            Err(msg) => {
                resp.set_code(1);
                resp.add_log(&msg);
                log::error!("deliver tx failed: {}", msg);
            }
        }
        resp
    }

    /// Consensus Connection: Called at the end of the block. used to update the validator set.
    fn end_block(&mut self, _req: &RequestEndBlock) -> ResponseEndBlock {
        info!("received endblock request");
        ChainNodeApp::end_block_handler(self, _req)
    }

    /// Consensus Connection: Commit the block with the latest state from the application.
    fn commit(&mut self, _req: &RequestCommit) -> ResponseCommit {
        info!("received commit request");
        ChainNodeApp::commit_handler(self, _req)
    }
}

fn update_validator_liveness(
    state: &mut ValidatorState,
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

        state.record_signed(&address, block_height, signed);
    }
}
