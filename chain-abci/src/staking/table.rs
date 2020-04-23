//! `ValidatorTable` combined with merkle trie is complete state of staking and validator,
//! so many methods here needs caller to provide access to external merkle trie
//! through traits `GetStaking` and `StoreStaking`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use core::cmp::Ordering;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use chain_core::common::Timespec;
use chain_core::init::coin::{sum_coins, Coin, CoinError, CoinResult};
use chain_core::init::config::SlashRatio;
use chain_core::init::params::NetworkParameters;
use chain_core::state::account::{
    PunishmentKind, SlashRecord, StakedState, StakedStateAddress, ValidatorName,
    ValidatorSecurityContact,
};
use chain_core::state::tendermint::{
    BlockHeight, TendermintValidatorAddress, TendermintValidatorPubKey, TendermintVotePower,
};
use chain_storage::buffer::{GetStaking, StoreStaking};

use crate::liveness::LivenessTracker;

pub type RewardsDistribution = Vec<(StakedStateAddress, Coin)>;

#[derive(Debug, Clone, Serialize)]
/// Metadata of a validator
pub struct CouncilNodeMetadata {
    /// Name of validator
    pub name: ValidatorName,
    /// Current voting power of validator
    pub voting_power: TendermintVotePower,
    /// Address of staking account of validator
    pub staking_address: StakedStateAddress,
    /// Optional security email address of validator
    pub security_contact: ValidatorSecurityContact,
    /// Tendermint consensus validator-associated public key
    pub tendermint_pubkey: TendermintValidatorPubKey,
}

/// order by bonded desc, staking_address
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct ValidatorSortKey {
    pub bonded: Coin,
    pub address: StakedStateAddress,
}

impl Ord for ValidatorSortKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.bonded.cmp(&other.bonded) {
            Ordering::Equal => self.address.cmp(&other.address),
            ordering => ordering.reverse(),
        }
    }
}
impl PartialOrd for ValidatorSortKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl ValidatorSortKey {
    pub fn new(bonded: Coin, address: StakedStateAddress) -> Self {
        Self { bonded, address }
    }
}

impl Into<ValidatorSortKey> for &StakedState {
    fn into(self) -> ValidatorSortKey {
        ValidatorSortKey::new(self.bonded, self.address)
    }
}

impl Into<ValidatorSortKey> for &mut StakedState {
    fn into(self) -> ValidatorSortKey {
        ValidatorSortKey::new(self.bonded, self.address)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PunishmentOutcome {
    pub staking_address: StakedStateAddress,
    pub slashed_coin: SlashedCoin,
    pub punishment_kind: PunishmentKind,
    pub jailed_until: Option<Timespec>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SlashedCoin {
    pub bonded: Coin,
    pub unbonded: Coin,
}

impl SlashedCoin {
    pub fn sum(&self) -> CoinResult {
        self.bonded + self.unbonded
    }
}

/// StakedState indexes, and other tracking data structures.
/// The heap of records are stored outside.
/// Primary key is `StakedStateAddress`, secondary index reference the primary key.
///
/// Invariant 2.1: The secondary indexes should always be consistent with the heap
///
/// Invariant 2.2:
///   All the secondary indexes should be partial index with condition `validator is not null`
///   This shouldn't be prone to DoS as long as minimum required stake is high enough.
///   Combined with 2.1, it means that all addresses recorded in `idx_*` should also exist on heap,
///   and have validator record;
///   Proof: always update index when validator record created or removed.
///
/// Invariant 2.3:
///   Key set of `liveness` should be the same as addresses in `idx_*`.
///   Combined with 2.1, it means that all liveness tracking addresses should exist on heap, and have
///   validator record.
///   Proof: always update index when related validator fields changed.
#[derive(Clone, Debug, Default, Encode, Decode)]
pub struct StakingTable {
    // Selected validator voting powers of last executed end block
    chosen_validators: BTreeMap<StakedStateAddress, TendermintVotePower>,
    liveness: BTreeMap<StakedStateAddress, LivenessTracker>,
    participator_stats: BTreeMap<StakedStateAddress, u64>,

    // Call `initialize` to populate the indexes after deserialized.
    // Keep the recent value of minimal_required_staking to do sanity check on validator states.
    #[codec(skip)]
    pub(crate) minimal_required_staking: Coin,
    #[codec(skip)]
    pub(crate) idx_validator_address: BTreeMap<TendermintValidatorAddress, StakedStateAddress>,
    #[codec(skip)]
    idx_sort: BTreeSet<ValidatorSortKey>,
}

impl StakingTable {
    /// Init with genesis stakings
    ///
    /// # Panics
    ///
    /// - Panic if addresses not exists on heap.
    /// - Panic stakings don't have validator record.
    pub fn from_genesis(
        heap: &impl GetStaking,
        minimal_required_staking: Coin,
        max_validators: usize,
        addresses: &[StakedStateAddress],
    ) -> Self {
        let mut tbl = Self::default();
        tbl.minimal_required_staking = minimal_required_staking;
        for addr in addresses.iter() {
            tbl.insert_validator(&heap.get(addr).unwrap());
        }
        tbl.chosen_validators = tbl.choose_validators(heap, max_validators);
        #[cfg(debug_assertions)]
        tbl.check_invariants(heap);
        tbl
    }

    /// After restored from storage, call initialize to populate the indexes
    pub fn initialize(&mut self, heap: &impl GetStaking, minimal_required_staking: Coin) {
        assert!(self.idx_sort.is_empty());
        assert!(self.idx_validator_address.is_empty());
        self.minimal_required_staking = minimal_required_staking;

        for (addr, _) in self.liveness.iter() {
            // no panic: Invariant 2.3 + 2.2 + 2.1
            // liveness and heap and idx_* are always consistent
            let mut staking = heap.get(addr).unwrap();
            assert!(self.idx_sort.insert((&staking).into()));
            let val = staking.validator.as_mut().unwrap();
            assert!(self
                .idx_validator_address
                .insert(val.validator_address(), *addr)
                .is_none());
        }
    }

    /// Handle abci begin_block event
    /// no error other than internal invariants broken
    /// - cleanup validator records
    /// - record and detect non-live faults
    /// - process byzantine evidences
    /// - slash and jail
    pub fn begin_block(
        &mut self,
        heap: &mut impl StoreStaking,
        params: &NetworkParameters,
        block_time: Timespec,
        block_height: BlockHeight,
        voters: &[(TendermintValidatorAddress, bool)],
        evidences: &[(TendermintValidatorAddress, BlockHeight, Timespec)],
    ) -> Vec<PunishmentOutcome> {
        self.cleanup(heap, params.get_unbonding_period() as Timespec, block_time);
        self.punish(heap, params, block_time, block_height, voters, evidences)
    }

    /// Handle abci end_block event
    /// - Compute validator updates
    /// - Cleanup out dated validator records
    pub fn end_block(
        &mut self,
        heap: &impl GetStaking,
        max_validators: usize,
    ) -> Vec<(TendermintValidatorPubKey, TendermintVotePower)> {
        let updates = self.update_validators(heap, max_validators);
        #[cfg(debug_assertions)]
        self.check_invariants(heap);
        updates
    }

    /// Handle reward statistics record
    pub fn reward_record(
        &mut self,
        heap: &impl GetStaking,
        val_addr: &TendermintValidatorAddress,
        val_voting_power: TendermintVotePower,
    ) -> bool {
        if let Some(addr) = self.idx_validator_address.get(val_addr) {
            // Invariant 2.1
            let staking = heap.get(addr).unwrap();
            // Invariant 2.2
            let val = staking.validator.as_ref().unwrap();
            if val.is_active() {
                self.participator_stats
                    .entry(*addr)
                    .and_modify(|count| *count = count.saturating_add(val_voting_power.into()))
                    .or_insert_with(|| val_voting_power.into());
            }
            true
        } else {
            false
        }
    }

    /// The heap should not use the uncommited buffer.
    pub fn reward_total_staking(&self, heap: &impl GetStaking) -> Coin {
        // Sum of all the coins should not overflow max supply, TODO proof.
        sum_coins(
            self.chosen_validators
                .keys()
                .map(|addr| heap.get(addr).unwrap().bonded),
        )
        .unwrap()
    }

    /// Returns (remainder, distribution)
    pub fn reward_distribute(
        &mut self,
        heap: &mut impl StoreStaking,
        total_rewards: Coin,
    ) -> (Coin, RewardsDistribution) {
        let sum_power: u64 = self
            .participator_stats
            .iter()
            .map(|(_, count)| count)
            .fold(0, |acc, value| acc.saturating_add(*value));
        if sum_power == 0 {
            return (total_rewards, vec![]);
        }

        let mut distributed = Vec::new();
        let mut remainder = total_rewards;
        let stats = std::mem::take(&mut self.participator_stats);
        for (addr, count) in stats.into_iter() {
            let mut staking = self.get_or_default(heap, &addr);
            let amount = Coin::new(
                (((u64::from(total_rewards) as u128) * count as u128) / sum_power as u128) as u64,
            )
            .expect("Overflow while distributing rewards");
            remainder = (remainder - amount).unwrap();
            distributed.push((addr, amount));
            self.add_bonded(amount, &mut staking).unwrap();
            set_staking(heap, staking, self.minimal_required_staking);
        }
        #[cfg(debug_assertions)]
        self.check_invariants(heap);
        (remainder, distributed)
    }

    /// list council nodes for abci_query
    pub fn list_council_nodes(&self, heap: &impl GetStaking) -> Vec<CouncilNodeMetadata> {
        self.idx_sort
            .iter()
            .filter_map(|key| {
                let staking = heap.get(&key.address).unwrap();
                let val = staking.validator.as_ref().unwrap();
                if val.is_active() {
                    Some(CouncilNodeMetadata {
                        name: val.council_node.name.clone(),
                        voting_power: staking.bonded.into(),
                        staking_address: key.address,
                        security_contact: val.council_node.security_contact.clone(),
                        tendermint_pubkey: val.council_node.consensus_pubkey.clone(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Query staking address by validator address
    pub fn lookup_address(
        &self,
        val_addr: &TendermintValidatorAddress,
    ) -> Option<&StakedStateAddress> {
        self.idx_validator_address.get(val_addr)
    }

    /// Query chosen validator and it's voting power.
    pub fn get_chosen_validators(&self) -> &BTreeMap<StakedStateAddress, TendermintVotePower> {
        &self.chosen_validators
    }

    /// Insert validator (genesis or join-node tx)
    /// Caller should do the validations:
    /// - StakedState has validator record
    /// - Both the staking address and validator address should not already exists in the indexing
    /// structures
    pub(crate) fn insert_validator(&mut self, staking: &StakedState) {
        let val_addr = TendermintValidatorAddress::from(
            // no panic: Call ensure validator record exists.
            &staking
                .validator
                .as_ref()
                .unwrap()
                .council_node
                .consensus_pubkey,
        );
        // insert
        assert!(self
            .idx_validator_address
            .insert(val_addr, staking.address)
            .is_none());
        assert_eq!(self.idx_sort.insert(staking.into()), true);

        let tracker = LivenessTracker::new();
        assert!(self.liveness.insert(staking.address, tracker).is_none());
    }

    /// Change bonded, and related index, inactivate validator if not enough amount.
    pub(crate) fn sub_bonded(
        &mut self,
        block_time: Timespec,
        block_height: BlockHeight,
        amount: Coin,
        staking: &mut StakedState,
    ) -> Result<(), CoinError> {
        let bonded = (staking.bonded - amount)?;
        if staking.validator.is_some() {
            assert!(self.idx_sort.remove(&staking.into()));
        }
        staking.bonded = bonded;
        if staking.validator.is_some() {
            assert!(self.idx_sort.insert(staking.into()));
        }

        if let Some(val) = staking.validator.as_mut() {
            if val.is_active() && staking.bonded < self.minimal_required_staking {
                val.inactivate(block_time, block_height);
            }
        }
        Ok(())
    }

    /// Change bonded, and related index
    pub(crate) fn add_bonded(
        &mut self,
        amount: Coin,
        staking: &mut StakedState,
    ) -> Result<(), CoinError> {
        let bonded = (staking.bonded + amount)?;
        if staking.validator.is_some() {
            assert!(self.idx_sort.remove(&staking.into()));
        }
        staking.bonded = bonded;
        if staking.validator.is_some() {
            assert!(self.idx_sort.insert(staking.into()));
        }

        Ok(())
    }

    /// execute slash
    fn slash(
        &mut self,
        block_time: Timespec,
        block_height: BlockHeight,
        staking: &mut StakedState,
        ratio: SlashRatio,
    ) -> SlashedCoin {
        let bonded_slashed = staking.bonded * ratio;
        let unbonded_slashed = staking.unbonded * ratio;
        // no panic: SlashRatio invariant(<= 1.0)
        self.sub_bonded(block_time, block_height, bonded_slashed, staking)
            .unwrap();
        // no panic: SlashRatio invariant(<= 1.0)
        staking.unbonded = (staking.unbonded - unbonded_slashed).unwrap();
        // no panic: Invariant: 4.1 + SlashRatio invariant
        SlashedCoin {
            bonded: bonded_slashed,
            unbonded: unbonded_slashed,
        }
    }

    fn choose_validators(
        &self,
        heap: &impl GetStaking,
        max_validators: usize,
    ) -> BTreeMap<StakedStateAddress, TendermintVotePower> {
        self.idx_sort
            .iter()
            .filter_map(|key| {
                // no panic: Invariant 2.1
                let staking = heap.get(&key.address).unwrap();
                // no panic: Invariant 2.2
                let val = staking.validator.as_ref().unwrap();
                if val.is_active() {
                    Some((staking.address, staking.bonded.into()))
                } else {
                    None
                }
            })
            .take(max_validators)
            .collect::<BTreeMap<_, _>>()
    }

    /// Cleanup the validator with condition: `block_time > inactive_time + unbonding_period`
    /// - Remove the validator record from heap
    /// - Remove from index structure
    /// Complexity: O(N), Do we need to make it O(log(N))?
    fn cleanup(
        &mut self,
        heap: &mut impl StoreStaking,
        unbonding_period: Timespec,
        block_time: Timespec,
    ) {
        let to_delete = self
            .idx_validator_address
            .values()
            .filter_map(|addr| {
                let staking = heap.get(addr).unwrap();
                if let Some(val) = &staking.validator {
                    if val.is_jailed() {
                        return None;
                    }
                    if let Some(inactive_time) = val.inactive_time {
                        if block_time > inactive_time.saturating_add(unbonding_period) {
                            return Some(*addr);
                        }
                    }
                }
                None
            })
            .collect::<Vec<_>>();

        if !to_delete.is_empty() {
            log::info!("cleanup validators: {}", to_delete.len());
        }

        // only place that removes the validator records
        for addr in to_delete.iter() {
            // no panic: Already checked above, no concurrency.
            let mut staking = heap.get(addr).unwrap();
            // no panic: Already checked above
            let val = staking.validator.as_ref().unwrap();
            assert_eq!(
                self.idx_validator_address.remove(&val.validator_address()),
                Some(*addr)
            );
            for (val_addr, _) in val.used_validator_addresses.iter() {
                assert_eq!(self.idx_validator_address.remove(val_addr), Some(*addr));
            }
            assert!(self.idx_sort.remove(&(&staking).into()));
            assert!(self.liveness.remove(addr).is_some());
            self.participator_stats.remove(addr);

            staking.validator = None;
            set_staking(heap, staking, self.minimal_required_staking);
        }

        #[cfg(debug_assertions)]
        self.check_invariants(heap);
    }

    /// Record liveness and handle non-live and byzantine punishment
    fn punish(
        &mut self,
        heap: &mut impl StoreStaking,
        params: &NetworkParameters,
        block_time: Timespec,
        block_height: BlockHeight,
        voters: &[(TendermintValidatorAddress, bool)],
        evidences: &[(TendermintValidatorAddress, BlockHeight, Timespec)],
    ) -> Vec<PunishmentOutcome> {
        let mut slashes = Vec::new();

        // handle non-live
        // convert to staking address, ignore invalid validator addresses
        let mut voters = voters
            .iter()
            .filter_map(|(val_addr, signed)| {
                self.idx_validator_address
                    .get(val_addr)
                    .map(|addr| (*addr, *signed))
            })
            .collect::<HashMap<_, _>>();

        // update liveness trackers
        for (addr, tracker) in self.liveness.iter_mut() {
            // if not in voters, default to true(live)
            let signed = voters.remove(addr).unwrap_or(true);
            tracker.update(
                params.get_block_signing_window() as usize,
                block_height,
                signed,
            );

            if !tracker.is_live(params.get_missed_block_threshold() as usize) {
                // non-live fault detected
                // panic: Invariant 2.3 + 2.1
                let mut staking = heap.get(addr).unwrap();
                // panic: Invariant 2.3 + 2.2
                let val = staking.validator.as_mut().unwrap();

                // slash and inactivate if it's active
                // panic: Invariant 2.3 + 2.2
                if val.is_active() {
                    val.inactivate(block_time, block_height);
                    slashes.push((*addr, PunishmentKind::NonLive, None));
                }

                tracker.reset();
                set_staking(heap, staking, self.minimal_required_staking);
            }
        }
        if !voters.is_empty() {
            log::error!("validator for vote not exists or is cleaned up");
        }

        // handle byzantine evidences, ignore invalid addresses
        for (val_addr, _, ev_time) in evidences.iter() {
            if block_time >= ev_time.saturating_add(params.get_unbonding_period() as u64) {
                // ignore evidence too long ago
                log::warn!("evidence older than unbonding period detected");
                continue;
            }
            // slash and jail if not already jailed.
            if let Some(addr) = self.idx_validator_address.get(val_addr) {
                // panic: Invariant 2.1
                let mut staking = heap.get(addr).unwrap();
                // panic: Invariant 2.2
                let val = staking.validator.as_mut().unwrap();
                if !val.is_jailed() {
                    let jailed_until = val.jail(
                        block_time,
                        block_height,
                        params.get_unbonding_period() as Timespec,
                    );
                    let maybe_jailed_until = Some(jailed_until);
                    self.participator_stats.remove(addr);
                    slashes.push((*addr, PunishmentKind::ByzantineFault, maybe_jailed_until));
                    set_staking(heap, staking, self.minimal_required_staking);
                }
            }
        }

        if !slashes.is_empty() {
            log::info!("slashing {} stakings", slashes.len());
        }

        // execute slashes
        let slashes = slashes
            .into_iter()
            .map(|(addr, kind, maybe_jailed_until)| {
                let mut staking = heap.get(&addr).unwrap();
                let slashed_coin = self.slash(
                    block_time,
                    block_height,
                    &mut staking,
                    match kind {
                        PunishmentKind::NonLive => params.get_liveness_slash_percent(),
                        PunishmentKind::ByzantineFault => params.get_byzantine_slash_percent(),
                    },
                );

                let total_slashed_amount = slashed_coin
                    .sum()
                    .expect("sum of bonded and unboned slash amount exceed maximum coin");

                // Update the last slash record for query
                staking.last_slash = Some(SlashRecord {
                    kind,
                    time: block_time,
                    amount: total_slashed_amount,
                });
                set_staking(heap, staking, self.minimal_required_staking);

                PunishmentOutcome {
                    staking_address: addr,
                    slashed_coin,
                    punishment_kind: kind,
                    jailed_until: maybe_jailed_until,
                }
            })
            .collect::<Vec<_>>();

        #[cfg(debug_assertions)]
        self.check_invariants(heap);
        slashes
    }

    /// Choose new validator set and diff with current set
    fn update_validators(
        &mut self,
        heap: &impl GetStaking,
        max_validators: usize,
    ) -> Vec<(TendermintValidatorPubKey, TendermintVotePower)> {
        let new = self.choose_validators(heap, max_validators);
        let updates = diff_validators(&self.chosen_validators, &new);
        self.chosen_validators = new;
        updates
            .into_iter()
            .map(|(addr, power)| (self.get_validator_pubkey(heap, &addr), power))
            .collect()
    }

    #[cfg(debug_assertions)]
    pub(crate) fn check_invariants(&mut self, heap: &impl GetStaking) {
        self.check_invariant2_1(heap);
        self.check_invariant2_2(heap);
        self.check_invariant2_3();

        self.check_validator_invariant(heap);
    }

    #[cfg(debug_assertions)]
    fn check_invariant2_1(&mut self, heap: &impl GetStaking) {
        // validator address is the same as stored in heap
        for (val_addr, addr) in self.idx_validator_address.iter() {
            let staking = heap
                .get(addr)
                .expect("idx_validator_address doesn't match heap");
            let val = staking
                .validator
                .as_ref()
                .expect("validator value not exists");
            assert!(
                val_addr.clone() == val.validator_address()
                    || val
                        .used_validator_addresses
                        .iter()
                        .any(|(addr, _)| addr == val_addr)
            );
        }
        // addresses in idx_sort are unique
        assert_eq!(
            self.idx_sort.len(),
            self.idx_sort
                .iter()
                .map(|key| key.address)
                .collect::<BTreeSet<_>>()
                .len()
        );
        // bonded coins are the same
        for key in self.idx_sort.iter() {
            let staking = heap
                .get(&key.address)
                .expect("idx_validator_address doesn't match heap");
            assert_eq!(key.bonded, staking.bonded);
        }
    }

    #[cfg(debug_assertions)]
    fn check_invariant2_2(&mut self, heap: &impl GetStaking) {
        for addr in self.idx_validator_address.values() {
            heap.get(addr)
                .expect("idx_validator_address doesn't match heap")
                .validator
                .as_ref()
                .expect("validator value not exists");
        }
        for key in self.idx_sort.iter() {
            heap.get(&key.address)
                .expect("idx_sort doesn't match heap")
                .validator
                .as_ref()
                .expect("validator value not exists");
        }
    }

    #[cfg(debug_assertions)]
    fn check_invariant2_3(&mut self) {
        assert_eq!(
            self.liveness.keys().collect::<BTreeSet<_>>(),
            self.idx_sort
                .iter()
                .map(|key| &key.address)
                .collect::<BTreeSet<_>>()
        );
    }

    #[cfg(debug_assertions)]
    fn check_validator_invariant(&mut self, heap: &impl GetStaking) {
        for addr in self.idx_validator_address.values() {
            heap.get(addr)
                .expect("idx_sort doesn't match heap")
                .validator
                .as_ref()
                .expect("validator value not exists")
                .check_invariants();
        }
    }

    /// Get validator pubkey by staking address
    fn get_validator_pubkey(
        &self,
        heap: &impl GetStaking,
        addr: &StakedStateAddress,
    ) -> TendermintValidatorPubKey {
        heap.get(addr)
            .unwrap()
            .validator
            .as_ref()
            .unwrap()
            .council_node
            .consensus_pubkey
            .clone()
    }

    /// get staking by staking address
    pub(crate) fn get_or_default(
        &self,
        heap: &impl GetStaking,
        addr: &StakedStateAddress,
    ) -> StakedState {
        let staking = heap.get_or_default(addr);
        #[cfg(debug_assertions)]
        assert_eq!(&staking.address, addr);
        #[cfg(debug_assertions)]
        staking.check_invariants(self.minimal_required_staking);
        staking
    }
}

pub(crate) fn set_staking(
    heap: &mut impl StoreStaking,
    staking: StakedState,
    _minimal_required_staking: Coin,
) {
    #[cfg(debug_assertions)]
    staking.check_invariants(_minimal_required_staking);
    heap.set_staking(staking)
}

/// generate validator updates
fn diff_validators(
    old: &BTreeMap<StakedStateAddress, TendermintVotePower>,
    new: &BTreeMap<StakedStateAddress, TendermintVotePower>,
) -> Vec<(StakedStateAddress, TendermintVotePower)> {
    // updates + removes
    new.iter()
        .filter_map(|(addr, power)| {
            if old.get(addr) != Some(power) {
                Some((*addr, *power))
            } else {
                None
            }
        })
        .chain(old.iter().filter_map(|(addr, _)| {
            if !new.contains_key(addr) {
                Some((*addr, TendermintVotePower::zero()))
            } else {
                None
            }
        }))
        .collect::<Vec<_>>()
}
