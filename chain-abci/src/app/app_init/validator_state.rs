use crate::app::rewards::RewardsDistribution;
use crate::app::ChainNodeState;
use crate::liveness::LivenessTracker;
use crate::punishment::ValidatorPunishment;
use crate::slashing::SlashingSchedule;
use crate::storage::get_account;
use chain_core::common::Timespec;
use chain_core::init::coin::Coin;
use chain_core::init::config::SlashRatio;
use chain_core::state::account::PunishmentKind;
use chain_core::state::account::{CouncilNode, StakedState, StakedStateAddress};
use chain_core::state::tendermint::BlockHeight;
use chain_core::state::tendermint::{TendermintValidatorAddress, TendermintVotePower};
use chain_storage::account::update_staked_state;
use chain_storage::account::AccountStorage;
use chain_storage::account::StarlingFixedKey;
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeMap;

/// Validator state tracking (needs to be persisted / a part of node state)
#[derive(PartialEq, Debug, Clone, Encode, Decode, Default)]
pub struct ValidatorState {
    /// all nodes (current validator set + pending): TendermintVotePower == coin bonded amount if >= minimal
    /// or TendermintVotePower == 0 if < minimal or was jailed
    /// FIXME: delete node metadata if voting power == 0 for longer than unbonding time
    pub council_nodes_by_power: BTreeMap<(TendermintVotePower, StakedStateAddress), CouncilNode>,
    /// stores staking account address corresponding to tendermint validator addresses
    /// FIXME: delete node metadata if voting power == 0 for longer than unbonding time
    tendermint_validator_addresses: BTreeMap<TendermintValidatorAddress, StakedStateAddress>,
    /// Runtime state for computing and executing validator punishment
    punishment: ValidatorPunishment,

    /// Record how many block each validator proposed, used for rewards distribution,
    /// cleared after rewards distributed
    /// FIXME: fairness -- use lastcommitinfo for stats
    proposer_stats: BTreeMap<StakedStateAddress, u64>,

    /// various lookups for handling validator updates, rewards, punishments
    #[codec(skip)]
    pub validator_state_helper: ValidatorStateHelper,
}

impl ValidatorState {
    /// used in tests/ only -- TODO: rewrite checking/probing
    pub fn get_first_tm_validator_address(&self) -> TendermintValidatorAddress {
        self.tendermint_validator_addresses
            .iter()
            .next()
            .unwrap()
            .0
            .clone()
    }

    /// used it tests/punishment only -- TODO: rewrite
    pub fn is_scheduled_for_slash(&self, address: &StakedStateAddress) -> bool {
        self.punishment.slashing_schedule.contains_key(address)
    }

    pub fn remove_slash_schedule(&mut self, address: &StakedStateAddress) -> SlashingSchedule {
        self.punishment.slashing_schedule.remove(address).unwrap()
    }

    pub fn get_accounts_to_be_slashed(&self, current_time: Timespec) -> Vec<StakedStateAddress> {
        // TODO: no need to iterate through all if sorted by time
        self.punishment
            .slashing_schedule
            .iter()
            .filter_map(|(address, schedule)| {
                if schedule.can_slash(current_time) {
                    Some(*address)
                } else {
                    None
                }
            })
            .collect()
    }

    /// TODO: tm_min_power should be effective (min required or lowest val) and obtained from within ValidatorState
    pub fn distribute_rewards(
        &mut self,
        share: Coin,
        last_root: &StarlingFixedKey,
        accounts: &mut AccountStorage,
        tm_min_power: TendermintVotePower,
    ) -> (StarlingFixedKey, RewardsDistribution) {
        let mut root = *last_root;
        let mut distributed: RewardsDistribution = vec![];
        if share > Coin::zero() {
            for (addr, &count) in self.proposer_stats.iter() {
                let mut state = get_account(addr, &root, &accounts)
                    .expect("io error or validator account not exists");

                let amount = (share * count).unwrap();
                let _balance = state.add_reward(amount).unwrap();
                root = update_staked_state(state.clone(), &root, accounts).0;
                distributed.push((*addr, amount));
                self.validator_state_helper
                    .voting_power_update(&state, tm_min_power)
            }
        }
        self.proposer_stats.clear();
        (root, distributed)
    }

    /// FIXME: total votes?
    pub fn get_total_blocks(&self) -> u64 {
        self.proposer_stats.iter().map(|(_, count)| count).sum()
    }

    /// FIXME: vote
    pub fn record_proposed_block(&mut self, addr: &TendermintValidatorAddress) {
        let staking_address = self
            .tendermint_validator_addresses
            .get(addr)
            .expect("block proposer is not found");
        self.proposer_stats
            .entry(*staking_address)
            .and_modify(|count| *count += 1)
            .or_insert_with(|| 1);
    }

    /// for liveness tracking
    pub fn record_signed(
        &mut self,
        tm_address: &TendermintValidatorAddress,
        block_height: BlockHeight,
        signed: bool,
    ) {
        match self.punishment.validator_liveness.get_mut(&tm_address) {
            Some(liveness_tracker) => {
                liveness_tracker.update(block_height, signed);
            }
            None => {
                log::warn!("Validator in `last_commit_info` not found in liveness tracker");
            }
        }
    }

    pub fn update_punishment_schedules<'a>(
        &mut self,
        slashing_proportion: SlashRatio,
        slashing_time: Timespec,
        accounts_to_punish: impl Iterator<Item = &'a (StakedStateAddress, SlashRatio, PunishmentKind)>,
    ) {
        for (account_address, slash_ratio, punishment_kind) in accounts_to_punish {
            match self.punishment.slashing_schedule.get_mut(&account_address) {
                Some(account_slashing_schedule) => {
                    account_slashing_schedule
                        .update_slash_ratio(*slash_ratio * slashing_proportion, *punishment_kind);
                }
                None => {
                    self.punishment.slashing_schedule.insert(
                        *account_address,
                        SlashingSchedule::new(
                            *slash_ratio * slashing_proportion,
                            slashing_time,
                            *punishment_kind,
                        ),
                    );
                }
            }
        }
    }

    pub fn get_nonlive_validators(
        &self,
        missed_block_threshold: u16,
        liveness_slash_percent: SlashRatio,
    ) -> Vec<(StakedStateAddress, SlashRatio, PunishmentKind)> {
        self.punishment
            .validator_liveness
            // FIXME: liveness tracking should mark that on each update, so this could be returned directly
            // rather than re-iterated through on every block
            .iter()
            .filter(|(_, tracker)| !tracker.is_live(missed_block_threshold))
            .map(|(tendermint_validator_address, _)| {
                (
                    *self
                        .tendermint_validator_addresses
                        .get(tendermint_validator_address)
                        .expect(
                            "Staking account address for tendermint validator address not found",
                        ),
                    liveness_slash_percent,
                    PunishmentKind::NonLive,
                )
            })
            .collect()
    }

    pub fn lookup_address(&self, tm_address: &TendermintValidatorAddress) -> &StakedStateAddress {
        &self.tendermint_validator_addresses[tm_address]
    }

    pub fn is_current_validator(&self, tm_address: &TendermintValidatorAddress) -> bool {
        self.tendermint_validator_addresses.contains_key(tm_address)
    }

    pub fn is_tracked(&self, validator_address: &TendermintValidatorAddress) -> bool {
        self.punishment
            .validator_liveness
            .contains_key(validator_address)
    }

    /// init -- called for every initial validator
    pub fn add_initial_validator(
        &mut self,
        address: StakedStateAddress,
        power: TendermintVotePower,
        node: CouncilNode,
        block_signing_window: u16,
    ) {
        self.validator_state_helper
            .validator_voting_power
            .insert(address, power);
        self.council_nodes_by_power
            .insert((power, address), node.clone());

        let tendermint_validator_address = TendermintValidatorAddress::from(&node.consensus_pubkey);

        self.add_validator_for_tracking(
            tendermint_validator_address,
            address,
            block_signing_window,
        );
    }

    /// add validator for tracking if it wasn't added before
    pub fn add_validator_for_tracking(
        &mut self,
        validator_address: TendermintValidatorAddress,
        staking_address: StakedStateAddress,
        block_signing_window: u16,
    ) {
        if !self
            .punishment
            .validator_liveness
            .contains_key(&validator_address)
        {
            self.tendermint_validator_addresses
                .insert(validator_address.clone(), staking_address);
            self.punishment.validator_liveness.insert(
                validator_address,
                LivenessTracker::new(block_signing_window),
            );
        }
    }

    /// remove from tracking liveness
    pub fn remove_validator_from_tracking(
        &mut self,
        tendermint_address: &TendermintValidatorAddress,
    ) {
        self.punishment
            .validator_liveness
            .remove(tendermint_address);
    }
}

/// per block, lookup / helper
#[derive(PartialEq, Debug, Default, Clone)]
pub struct ValidatorStateHelper {
    /// validator voting power (current validator set)
    pub validator_voting_power: BTreeMap<StakedStateAddress, TendermintVotePower>,
    /// new validator addresses or whose bonded amount changed in the current block
    power_changed_in_block: BTreeMap<StakedStateAddress, TendermintVotePower>,
    /// new nodes proposed in the block
    new_nodes_in_block: BTreeMap<StakedStateAddress, CouncilNode>,
}

impl ValidatorStateHelper {
    pub fn get_validator_total_bonded(
        &self,
        last_root: &StarlingFixedKey,
        accounts: &AccountStorage,
    ) -> Coin {
        // TODO: store and remain updated?
        let mut total_staking = Coin::zero();
        for (addr, _) in self.validator_voting_power.iter() {
            let account = get_account(addr, last_root, accounts)
                .expect("io error or validator account not exists");
            total_staking = (total_staking + account.bonded).expect("coin overflow");
        }
        total_staking
    }

    /// deposit or unbond
    /// or reward distribution
    pub fn voting_power_update(&mut self, state: &StakedState, min_power: TendermintVotePower) {
        if self.validator_voting_power.contains_key(&state.address)
            || self.power_changed_in_block.contains_key(&state.address)
        {
            if state.is_jailed() {
                log::error!("Validation should not be successful for jailed accounts");
                unreachable!("Validation should not be successful for jailed accounts");
            } else {
                let new_power = TendermintVotePower::from(state.bonded);
                let old_power = self
                    .validator_voting_power
                    .get(&state.address)
                    .copied()
                    .unwrap_or_else(TendermintVotePower::zero);

                if new_power != old_power {
                    if new_power >= min_power {
                        self.power_changed_in_block.insert(state.address, new_power);
                    } else {
                        self.power_changed_in_block
                            .insert(state.address, TendermintVotePower::zero());
                    }
                }
            }
        }
    }

    pub fn new_valid_node_join_update(&mut self, state: &StakedState) {
        self.new_nodes_in_block.insert(
            state.address,
            state
                .council_node
                .clone()
                .expect("state after nodejointx should have council node"),
        );
        let power = TendermintVotePower::from(state.bonded);
        self.power_changed_in_block.insert(state.address, power);
    }

    pub fn punish_update(&mut self, address: StakedStateAddress) {
        self.power_changed_in_block
            .insert(address, TendermintVotePower::zero());
    }

    pub fn clear(&mut self) {
        self.power_changed_in_block.clear();
        self.new_nodes_in_block.clear();
    }

    pub fn get_new_node(&self, address: &StakedStateAddress) -> CouncilNode {
        self.new_nodes_in_block[address].clone()
    }

    pub fn changes(&self) -> impl Iterator<Item = (&StakedStateAddress, &TendermintVotePower)> {
        self.power_changed_in_block.iter()
    }

    pub fn changed_nodes(&self) -> usize {
        self.power_changed_in_block.len()
    }

    /// creates a fresh helper from storage and last known state
    pub fn restore(accounts: &AccountStorage, last_app_state: &ChainNodeState) -> Self {
        let validator_voting_power =
            ValidatorStateHelper::get_validator_mapping(accounts, last_app_state);
        Self {
            validator_voting_power,
            power_changed_in_block: BTreeMap::new(),
            new_nodes_in_block: BTreeMap::new(),
        }
    }

    fn get_validator_mapping(
        accounts: &AccountStorage,
        last_app_state: &ChainNodeState,
    ) -> BTreeMap<StakedStateAddress, TendermintVotePower> {
        let mut validator_voting_power = BTreeMap::new();
        for ((voting_power, address), node) in last_app_state
            .validators
            .council_nodes_by_power
            .iter()
            .rev()
            .take(last_app_state.top_level.network_params.get_max_validators())
        {
            // integrity checks -- committed / disk-persisted values should match up
            let account = get_account(&address, &last_app_state.top_level.account_root, accounts)
                .expect("council node staking state address should be in the state trie");
            assert!(
                &account.council_node.is_some(),
                "council node's staking state should contain it"
            );
            if account.is_jailed()
                || account.bonded
                    < last_app_state
                        .top_level
                        .network_params
                        .get_required_council_node_stake()
            {
                let vp = TendermintVotePower::from(Coin::zero());
                assert!(
                    voting_power == &vp,
                    "jailed or below minimum bonded amounts should have 0 voting power"
                );
                validator_voting_power.insert(*address, vp);
            } else {
                let vp = TendermintVotePower::from(account.bonded);
                assert!(
                    voting_power == &vp,
                    "voting power should match the bonded amount"
                );
                validator_voting_power.insert(*address, vp);
            }
            assert!(
                node == &account.council_node.unwrap(),
                "council node should match the one in the state trie"
            );
        }
        validator_voting_power
    }
}
