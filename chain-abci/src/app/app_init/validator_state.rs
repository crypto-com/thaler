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
use chain_storage::account::AccountStorage;
use chain_storage::account::StarlingFixedKey;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Validator state tracking (needs to be persisted / a part of node state)
#[derive(PartialEq, Debug, Clone, Default)]
pub struct ValidatorState {
    /// all nodes (current validator set): TendermintVotePower == coin bonded amount if >= minimal effective
    /// TODO: pending validators / waitlist TendermintVotePower == 0 if < minimal effective?
    pub council_nodes_by_power: BTreeMap<(TendermintVotePower, StakedStateAddress), CouncilNode>,
    /// stores staking account address corresponding to tendermint validator addresses
    tendermint_validator_addresses: BTreeMap<TendermintValidatorAddress, StakedStateAddress>,
    /// Runtime state for computing and executing validator punishment
    punishment: ValidatorPunishment,

    /// Record signing voters and the sum of voting powers at vote time, used for rewards distribution,
    /// Cleared when validator is jailed,
    /// Cleared after rewards distributed
    pub signed_voters: HashMap<StakedStateAddress, u64>,

    after_unbond_delete: DeleteScheduleMap,

    /// various lookups for handling validator updates, rewards, punishments
    pub validator_state_helper: ValidatorStateHelper,
}

#[derive(PartialEq, Debug, Clone, Default)]
struct DeleteScheduleMap {
    ordered_by_time: BTreeMap<(Timespec, StakedStateAddress), TendermintValidatorAddress>,
    lookup_time: BTreeMap<(TendermintValidatorAddress, StakedStateAddress), Timespec>,
} //= IndexMap<StakedStateAddress, (Timespec, TendermintValidatorAddress)>;
type DeleteSchedule = ((Timespec, StakedStateAddress), TendermintValidatorAddress);

impl DeleteScheduleMap {
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&(Timespec, StakedStateAddress), &TendermintValidatorAddress)> {
        self.ordered_by_time.iter()
    }

    pub fn len(&self) -> usize {
        self.ordered_by_time.len()
    }

    pub fn from_vec(inputs: Vec<DeleteSchedule>) -> Self {
        let mut schedule = DeleteScheduleMap::default();
        for ((time, address), tm_address) in inputs.iter() {
            schedule.insert(*time, *address, tm_address.clone());
        }
        schedule
    }

    pub fn insert(
        &mut self,
        time: Timespec,
        address: StakedStateAddress,
        tm_address: TendermintValidatorAddress,
    ) {
        if self
            .ordered_by_time
            .insert((time, address), tm_address.clone())
            .is_some()
        {
            log::warn!("node already scheduled for metadata deletion: {}", address);
        }
        if self
            .lookup_time
            .insert((tm_address, address), time)
            .is_some()
        {
            log::warn!("node already scheduled for metadata deletion: {}", address);
        }
    }

    pub fn check_first_time(&self) -> Option<Timespec> {
        self.ordered_by_time.keys().next().map(|key| key.0)
    }

    pub fn peek(&self) -> Option<((Timespec, StakedStateAddress), TendermintValidatorAddress)> {
        self.ordered_by_time
            .iter()
            .next()
            .map(|(x, y)| (*x, y.clone()))
    }

    pub fn deleted(
        &mut self,
        time: Timespec,
        address: StakedStateAddress,
        tm_address: TendermintValidatorAddress,
    ) {
        self.ordered_by_time.remove(&(time, address));
        self.lookup_time.remove(&(tm_address, address));
    }

    pub fn is_scheduled(
        &self,
        addresses: &(TendermintValidatorAddress, StakedStateAddress),
    ) -> bool {
        self.lookup_time.contains_key(addresses)
    }

    pub fn cancel(
        &mut self,
        address: StakedStateAddress,
        tm_address: TendermintValidatorAddress,
    ) -> bool {
        if let Some(time) = self
            .lookup_time
            .get(&(tm_address.clone(), address))
            .cloned()
        {
            self.deleted(time, address, tm_address);
            true
        } else {
            false
        }
    }
}

impl Encode for ValidatorState {
    fn size_hint(&self) -> usize {
        let mut unbond_schedule_iter = self.after_unbond_delete.iter();
        let ub_size = self.after_unbond_delete.len();
        let ub_item_size = if ub_size > 0 {
            unbond_schedule_iter.next().size_hint()
        } else {
            0
        };

        self.council_nodes_by_power.size_hint()
            + self.tendermint_validator_addresses.size_hint()
            + self.punishment.size_hint()
            + self.signed_voters.iter().collect::<Vec<_>>().size_hint()
            + ub_size * ub_item_size
    }

    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.council_nodes_by_power.encode_to(dest);
        self.tendermint_validator_addresses.encode_to(dest);
        self.punishment.encode_to(dest);
        self.signed_voters
            .iter()
            .collect::<Vec<_>>()
            .encode_to(dest);
        let unbond_schedule: Vec<DeleteSchedule> = self
            .after_unbond_delete
            .iter()
            .map(|x| (*x.0, x.1.clone()))
            .collect();
        unbond_schedule.encode_to(dest);
    }
}

impl Decode for ValidatorState {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let council_nodes_by_power =
            BTreeMap::<(TendermintVotePower, StakedStateAddress), CouncilNode>::decode(input)?;
        let tendermint_validator_addresses =
            BTreeMap::<TendermintValidatorAddress, StakedStateAddress>::decode(input)?;
        let punishment = ValidatorPunishment::decode(input)?;
        let signed_voters = Vec::<(StakedStateAddress, u64)>::decode(input)?
            .into_iter()
            .collect::<HashMap<_, _>>();
        let unbond_schedule: Vec<DeleteSchedule> = Vec::decode(input)?;
        let after_unbond_delete = DeleteScheduleMap::from_vec(unbond_schedule);
        let mut validator_state_helper = ValidatorStateHelper::default();
        for key in council_nodes_by_power.keys() {
            validator_state_helper
                .validator_voting_power
                .insert(key.1, key.0);
        }
        Ok(ValidatorState {
            council_nodes_by_power,
            tendermint_validator_addresses,
            punishment,
            signed_voters,
            after_unbond_delete,
            validator_state_helper,
        })
    }
}

impl ValidatorState {
    pub fn lowest_vote_power(&self) -> TendermintVotePower {
        self.council_nodes_by_power
            .keys()
            .next()
            .expect("at least one validator")
            .0
    }

    /// number of current validators
    pub fn number_validators(&self) -> usize {
        self.council_nodes_by_power.len()
    }

    /// Removal of council node metadata at the begin block
    pub fn metadata_clean(&mut self, current_time: Timespec) {
        match self.after_unbond_delete.check_first_time() {
            Some(t) if t <= current_time => {
                log::info!("Cleaning metadata of removed council nodes");
                let mut item = self.after_unbond_delete.peek();
                while let Some(((time, address), tm_address)) = item {
                    if time > current_time {
                        item = None;
                    } else {
                        log::info!("Removing metadata of node: {} ({})", address, tm_address);
                        if let Some(vp) = self
                            .validator_state_helper
                            .validator_voting_power
                            .remove(&address)
                        {
                            log::info!("Removed validator data from validator state helper (vote power: {})", vp);
                            if self.council_nodes_by_power.remove(&(vp, address)).is_some() {
                                log::info!("Removed validator data from council node data ordered by vote power");
                            }
                        }
                        if self
                            .tendermint_validator_addresses
                            .remove(&tm_address)
                            .is_some()
                        {
                            log::info!("Removed tendermint address mapping ({})", tm_address);
                        } else {
                            log::warn!("Did not find tendermint address mapping");
                        }
                        self.after_unbond_delete.deleted(time, address, tm_address);
                        item = self.after_unbond_delete.peek();
                    }
                }
                log::info!("Cleaning metadata of removed council nodes finished");
            }
            _ => {}
        }
    }

    /// Removal of council node metadata at the end of block end
    pub fn metadata_clean_schedule(
        &mut self,
        address: StakedStateAddress,
        node: CouncilNode,
        time_to_remove: Timespec,
        is_infraction: bool,
    ) {
        log::info!("node removed -- {}", node);
        if is_infraction {
            log::info!("(first time infraction)");
        } else {
            log::info!("(other reason -- effective bonded stake not enough or explicit unbonding)");
        }
        // rewards
        if is_infraction && self.signed_voters.remove(&address).is_some() {
            log::info!("removed reward stats for: {}", address);
        }
        let tendermint_address = node.consensus_pubkey.into();
        // liveness tracking
        if self
            .punishment
            .validator_liveness
            .remove(&tendermint_address)
            .is_some()
        {
            log::info!(
                "liveness tracking removed for: {} ({})",
                address,
                &tendermint_address
            );
        } else {
            log::warn!(
                "liveness tracking not found during removal: {} ({})",
                address,
                &tendermint_address
            );
        }
        // everything else -- lookups may be needed for detecting later infractions during slash period
        self.after_unbond_delete
            .insert(time_to_remove, address, tendermint_address);
    }

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

    fn get_voting_power(&self, addr: &StakedStateAddress) -> Option<TendermintVotePower> {
        self.validator_state_helper.get_voting_power(addr)
    }

    /// Record signing voters
    pub fn record_voters_for_rewarding(
        &mut self,
        addrs: impl Iterator<Item = TendermintValidatorAddress>,
    ) {
        for addr in addrs {
            if let Some(staking_address) = self.get_staking_address(&addr).copied() {
                if let Some(voting_power) = self.get_voting_power(&staking_address) {
                    let amount = u64::from(voting_power);
                    self.signed_voters
                        .entry(staking_address)
                        .and_modify(|power| *power = power.saturating_add(amount))
                        .or_insert(amount);
                } else {
                    log::warn!("voter found, but not in validator_voting_power");
                }
            } else {
                log::error!("voter not found");
            }
        }
    }

    // Get staking address by validator address
    fn get_staking_address(
        &self,
        validator_address: &TendermintValidatorAddress,
    ) -> Option<&StakedStateAddress> {
        self.tendermint_validator_addresses.get(validator_address)
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
                if let Some(staking_address) = self.tendermint_validator_addresses.get(tm_address) {
                    log::info!(
                        "Validator in `last_commit_info` not found in liveness tracker: {}: {}",
                        tm_address,
                        staking_address
                    );
                } else {
                    log::error!(
                        "Validator in `last_commit_info` is cleaned up/non-existent: {}",
                        tm_address
                    );
                }
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

    pub fn new_valid_node_join_update(&mut self, state: &StakedState) {
        let new_address: TendermintValidatorAddress = state
            .council_node
            .as_ref()
            .expect("node join state should have council node")
            .consensus_pubkey
            .clone()
            .into();
        if self.after_unbond_delete.cancel(state.address, new_address) {
            log::info!("node {} joins with the same consensus public key, cancelling previous delete schedule", state.address);
        }
        self.validator_state_helper
            .new_valid_node_join_update(state);
    }

    pub fn is_scheduled_for_delete(
        &self,
        address: &StakedStateAddress,
        tm_address: &TendermintValidatorAddress,
    ) -> bool {
        self.after_unbond_delete
            .is_scheduled(&(tm_address.clone(), *address))
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
    /// (first-time) punished nodes in the block
    punished_nodes_in_block: BTreeSet<StakedStateAddress>,
}

impl ValidatorStateHelper {
    pub fn caused_infraction(&self, address: &StakedStateAddress) -> bool {
        self.punished_nodes_in_block.contains(address)
    }

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

    fn new_valid_node_join_update(&mut self, state: &StakedState) {
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
        self.punished_nodes_in_block.insert(address);
    }

    pub fn clear(&mut self) {
        self.power_changed_in_block.clear();
        self.new_nodes_in_block.clear();
        self.punished_nodes_in_block.clear();
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
            punished_nodes_in_block: BTreeSet::new(),
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

    fn get_voting_power(
        &self,
        staking_address: &StakedStateAddress,
    ) -> Option<TendermintVotePower> {
        self.validator_voting_power.get(staking_address).copied()
    }
}
