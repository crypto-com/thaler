#[macro_use]
mod macros;

mod app_init;
mod commit;
mod end_block;
mod query;
mod rewards;
pub mod validate_tx;

use abci::*;
use log::info;

#[cfg(fuzzing)]
pub use self::app_init::check_validators;
pub use self::app_init::{
    compute_accounts_root, get_validator_key, init_app_hash, BufferType, ChainNodeApp,
    ChainNodeState,
};
use crate::app::validate_tx::ResponseWithCodeAndLog;
use crate::enclave_bridge::EnclaveProxy;
use crate::staking::RewardsDistribution;
use chain_core::common::{TendermintEventKey, TendermintEventType, Timespec};
use chain_core::init::coin::Coin;
use chain_core::state::account::{PunishmentKind, StakedStateAddress};
use chain_core::state::tendermint::{BlockHeight, TendermintValidatorAddress, TendermintVotePower};
use chain_core::tx::fee::Fee;
use chain_core::tx::TxAux;
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

    /// Mempool Connection:  Used to validate incoming transactions.  If the application responds
    /// with a non-zero value, the transaction is added to Tendermint's mempool for processing
    /// on the deliver_tx call below.
    fn check_tx(&mut self, req: &RequestCheckTx) -> ResponseCheckTx {
        info!("received checktx request");
        let mut resp = ResponseCheckTx::new();
        match self.process_tx(req, BufferType::Mempool) {
            Ok(_) => {
                resp.set_code(0);
            }
            Err(msg) => {
                resp.set_code(1);
                resp.add_log(&msg.to_string());
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
        let header = req
            .header
            .as_ref()
            .expect("No block header in begin block request from tendermint");
        let block_height = abci_block_height(header.height).expect("invalid block height");
        let block_time = abci_timespec(&header.time).expect("invalid block time");
        let proposer_address =
            TendermintValidatorAddress::try_from(header.proposer_address.as_slice());

        let voters = if let Some(last_commit_info) = req.last_commit_info.as_ref() {
            // ignore the invalid items (logged)
            iter_votes(last_commit_info)
                .filter_map(|vote| {
                    abci_validator(&vote.validator).map(|(addr, _)| (addr, vote.signed_last_block))
                })
                .collect::<Vec<_>>()
        } else {
            if block_height > 2.into() {
                log::error!(
                    "No last commit info in begin block request for height: {}",
                    block_height
                );
            }
            vec![]
        };

        // ignore the invalid items (logged)
        let evidences = req
            .byzantine_validators
            .iter()
            .filter_map(|ev| {
                abci_validator(&ev.validator).and_then(|(addr, _)| {
                    abci_block_height(ev.height)
                        .and_then(|height| abci_timespec(&ev.time).map(|time| (addr, height, time)))
                })
            })
            .collect::<Vec<_>>();

        let last_state = self
            .last_state
            .as_mut()
            .expect("executing begin block, but no app state stored (i.e. no initchain or recovery was executed)");
        let account_root = Some(last_state.top_level.account_root);

        last_state.block_time = block_time;
        last_state.block_height = block_height;

        let slashes = last_state.staking_table.begin_block(
            &mut staking_store!(self, account_root),
            &last_state.top_level.network_params,
            block_time,
            block_height,
            &voters,
            &evidences,
        );

        let mut jailing_event = Event::new();
        jailing_event.field_type = TendermintEventType::JailValidators.to_string();
        let mut slashing_event = Event::new();
        slashing_event.field_type = TendermintEventType::SlashValidators.to_string();

        let rewards_pool = &mut last_state.top_level.rewards_pool;
        for (addr, amount, punishment_kind) in slashes.iter() {
            rewards_pool.period_bonus = (rewards_pool.period_bonus + amount)
                .expect("rewards pool + fee greater than max coin?");

            self.rewards_pool_updated = true;
            let mut kvpair = KVPair::new();
            kvpair.key = TendermintEventKey::Account.into();
            kvpair.value = addr.to_string().into_bytes();

            if *punishment_kind == PunishmentKind::ByzantineFault {
                jailing_event.attributes.push(kvpair.clone());
            }
            slashing_event.attributes.push(kvpair);

            let mut kvpair = KVPair::new();
            kvpair.key = TendermintEventKey::Slash.into();
            kvpair.value = amount.to_string().into_bytes();
            slashing_event.attributes.push(kvpair);
        }

        let mut response = ResponseBeginBlock::new();

        if !jailing_event.attributes.is_empty() {
            response.events.push(jailing_event);
        }

        if !slashing_event.attributes.is_empty() {
            response.events.push(slashing_event);
        }

        // FIXME: record based on votes
        if let Ok(proposer_address) = &proposer_address {
            last_state
                .staking_table
                .reward_record(&staking_getter!(self, account_root), proposer_address);
        } else {
            log::error!("invalid proposer address");
        }
        if let Some((distributed, minted)) = self.rewards_try_distribute() {
            response
                .events
                .push(write_reward_event(distributed, minted));
        }

        response
    }

    /// Consensus Connection: Actually processing the transaction, performing some form of a
    /// state transistion.
    fn deliver_tx(&mut self, req: &RequestDeliverTx) -> ResponseDeliverTx {
        info!("received delivertx request");
        let mut resp = ResponseDeliverTx::new();
        let result = self.process_tx(req, BufferType::Consensus);
        match result {
            Ok((txaux, fee, maccount)) => {
                resp.set_code(0);
                resp.events.push(write_tx_event(&txaux, fee, maccount));

                self.delivered_txs.push(txaux);

                let fee_amount = fee.to_coin();
                if fee_amount > Coin::zero() {
                    let rewards_pool =
                        &mut self.last_state.as_mut().unwrap().top_level.rewards_pool;
                    rewards_pool.period_bonus = (rewards_pool.period_bonus + fee_amount)
                        .expect("rewards pool + fee greater than max coin?");
                    self.rewards_pool_updated = true;
                }
            }
            Err(msg) => {
                resp.set_code(1);
                resp.add_log(&msg.to_string());
                log::error!("deliver tx failed: {}", msg);
            }
        }
        resp
    }

    /// Consensus Connection: Called at the end of the block. used to update the validator set.
    fn end_block(&mut self, req: &RequestEndBlock) -> ResponseEndBlock {
        info!("received endblock request");
        ChainNodeApp::end_block_handler(self, req)
    }

    /// Consensus Connection: Commit the block with the latest state from the application.
    fn commit(&mut self, _req: &RequestCommit) -> ResponseCommit {
        info!("received commit request");
        ChainNodeApp::commit_handler(self, _req)
    }
}

fn iter_votes(last_commit_info: &LastCommitInfo) -> impl Iterator<Item = &VoteInfo> {
    last_commit_info.votes.iter()
}

fn abci_validator(
    v: &::protobuf::SingularPtrField<Validator>,
) -> Option<(TendermintValidatorAddress, TendermintVotePower)> {
    let result = v.as_ref().and_then(|v| {
        let addr = TendermintValidatorAddress::try_from(v.address.as_slice()).ok();
        let power = TendermintVotePower::new(v.power).ok();
        addr.and_then(|addr| power.map(|power| (addr, power)))
    });
    if result.is_none() {
        log::error!("invalid validator from abci");
    }
    result
}

fn abci_timespec(
    v: &::protobuf::SingularPtrField<::protobuf::well_known_types::Timestamp>,
) -> Option<Timespec> {
    let result = v.as_ref().and_then(|t| t.seconds.try_into().ok());
    if result.is_none() {
        log::error!("invalid abci timestamp");
    }
    result
}

fn abci_block_height(i: i64) -> Option<BlockHeight> {
    let result = i.try_into().ok();
    if result.is_none() {
        log::error!("invalid abci block height");
    }
    result
}

fn write_reward_event(distributed: RewardsDistribution, minted: Coin) -> Event {
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

    event
}

fn write_tx_event(txaux: &TxAux, fee: Fee, maccount: Option<StakedStateAddress>) -> abci::Event {
    let mut event = Event::new();
    event.field_type = TendermintEventType::ValidTransactions.to_string();

    // write fee into event
    let mut kvpair_fee = abci::KVPair::new();
    kvpair_fee.key = TendermintEventKey::Fee.into();
    kvpair_fee.value = Vec::from(format!("{}", fee.to_coin()));
    event.attributes.push(kvpair_fee);

    if let Some(address) = maccount {
        let mut kvpair = abci::KVPair::new();
        kvpair.key = TendermintEventKey::Account.into();
        kvpair.value = Vec::from(format!("{}", address));
        event.attributes.push(kvpair);
    }

    let mut kvpair = abci::KVPair::new();
    kvpair.key = TendermintEventKey::TxId.into();
    kvpair.value = Vec::from(hex::encode(txaux.tx_id()).as_bytes());
    event.attributes.push(kvpair);

    event
}
