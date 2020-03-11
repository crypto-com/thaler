//! `ValidatorTable` combined with merkle trie is complete state of staking and validator,
//! so many methods here needs caller to provide access to external merkle trie
//! through traits `GetStaking` and `StoreStaking`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use parity_scale_codec::{Decode, Encode};
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{Deserialize, Serialize};
use thiserror::Error;

use chain_core::common::Timespec;
use chain_core::init::coin::{sum_coins, Coin, CoinError};
use chain_core::init::config::SlashRatio;
use chain_core::init::params::NetworkParameters;
use chain_core::state::account::{
    CouncilNodeMetadata, PunishmentKind, SlashRecord, StakedState, StakedStateAddress, UnbondTx,
    UnjailTx, Validator, ValidatorSortKey,
};
use chain_core::state::tendermint::{
    BlockHeight, TendermintValidatorAddress, TendermintValidatorPubKey, TendermintVotePower,
};
use chain_core::state::validator::NodeJoinRequestTx;
use chain_storage::buffer::{Get, GetStaking, StakingGetter, StoreStaking};

use crate::liveness::LivenessTracker;
use crate::tx::PublicTxError;

// FIXME use consensus parameter after upgrade to tendermint 0.33
const MAX_EVIDENCE_AGE: u64 = 10000;
// FIXME add a network parameter
const MAX_USED_VALIDATOR_ADDR: usize = 100;

#[derive(Error, Debug)]
pub enum UnjailError {
    #[error("the staking address is not jailed")]
    NotJailed,
    #[error("the jail duration is not reached yet")]
    JailTimeNotExpired,
}

#[derive(Error, Debug)]
pub enum NodeJoinError {
    #[error("bonded coins not enough to become validator")]
    BondedNotEnough,
    #[error("validator address already exists")]
    DuplicateValidatorAddress,
    #[error("the staking address is already active")]
    AlreadyJoined,
    #[error("the staking address is jailed")]
    IsJailed,
    #[error("the used_validator_addresses queue is full")]
    UsedValidatorAddrFull,
}

#[derive(Error, Debug)]
pub enum WithdrawError {
    #[error("unbonded amount {0} not equal to desired amount: {0}")]
    UnbondedSanityCheck(Coin, Coin),
    #[error("still in unbonding period")]
    InUnbondingPeriod,
    #[error("the staking address is jailed")]
    IsJailed,
}

#[derive(Error, Debug)]
pub enum UnbondError {
    #[error("nonce value don't match")]
    NonceNotMatch,
    #[error("coin error in unbond tx: {0}")]
    CoinError(#[from] CoinError),
    #[error("the staking address is jailed")]
    IsJailed,
    #[error("the value of tx is zero")]
    ZeroValue,
}

#[derive(Error, Debug)]
pub enum DepositError {
    #[error("coin error in deposit tx: {0}")]
    CoinError(#[from] CoinError),
    #[error("the staking address is jailed")]
    IsJailed,
}

/// StakedState indexes, and other tracking data structures.
/// The heap of records are stored outside.
/// Primary key is `StakedStateAddress`, secodary index reference the primary key.
///
/// Invarient 2.1: The secondary indexes should always be consistent with the heap
///
/// Invarient 2.2:
///   All the secondary indexes should be partial index with condition `validator is not null`
///   So there is no nothing-at-stake risk here, because there is a cost to become validator.
///   Combined with 2.1, it means that all addresses recorded in `idx_*` should also exist on heap,
///   and have validator record;
///   Proof: always update index when validator record created or removed.
///
/// Invarient 2.3:
///   Key set of `liveness` should be the same as addresses in `idx_*`.
///   Combined with 2.1, it means that all liveness tracking addresses should exist on heap, and have
///   validator record.
///   Proof: always update index when related validator fields changed.
#[derive(Clone, Debug, Default, Encode, Decode)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct StakingTable {
    // Selected validator voting powers of last executed end block
    pub validator_snapshot: BTreeMap<StakedStateAddress, TendermintVotePower>,
    liveness: BTreeMap<StakedStateAddress, LivenessTracker>,
    proposer_stats: BTreeMap<StakedStateAddress, u64>,

    // Call `initialize` to populate the indexes after deserialized.
    // Keep the recent value of minimal_required_staking to do sanity check on validator states.
    #[codec(skip)]
    minimal_required_staking: Coin,
    #[codec(skip)]
    idx_validator_address: BTreeMap<TendermintValidatorAddress, StakedStateAddress>,
    #[codec(skip)]
    idx_sort: BTreeSet<ValidatorSortKey>,
}

impl StakingTable {
    /// Init with genesis stakings, panic if:
    /// - addresses not exists on heap.
    /// - stakings don't have validator record.
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
        tbl.validator_snapshot = tbl.choose_validators(heap, max_validators);
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
            assert!(self.idx_sort.insert(staking.sort_key()));
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
    ) -> Vec<(StakedStateAddress, Coin, PunishmentKind)> {
        self.cleanup(heap, params.get_unbonding_period() as Timespec, block_time);

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
            tracker.resize(params.get_block_signing_window() as usize);
            tracker.update(block_height, signed);

            if tracker.count_false() >= params.get_missed_block_threshold() as usize {
                // non-live fault detected
                // panic: Invariant 2.3 + 2.1
                let mut staking = heap.get(addr).unwrap();
                // panic: Invariant 2.3 + 2.2
                let val = staking.validator.as_mut().unwrap();

                // slash and inactivate if it's active
                // panic: Invariant 2.3 + 2.2
                if val.is_active() {
                    val.inactivate(block_time, block_height);
                    slashes.push((*addr, PunishmentKind::NonLive));
                }

                tracker.reset();
                set_staking(heap, staking, self.minimal_required_staking);
            }
        }
        assert!(
            voters.is_empty(),
            "validator for vote not exists or is cleaned up"
        );

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
                    val.jail(
                        block_time,
                        block_height,
                        params.get_unbonding_period() as Timespec,
                    );
                    self.proposer_stats.remove(addr);
                    slashes.push((*addr, PunishmentKind::ByzantineFault));
                    set_staking(heap, staking, self.minimal_required_staking);
                }
            }
        }

        // execute slashes
        let slashes = slashes
            .into_iter()
            .map(|(addr, kind)| {
                let mut staking = heap.get(&addr).unwrap();
                let amount = self.slash(
                    block_time,
                    block_height,
                    &mut staking,
                    match kind {
                        PunishmentKind::NonLive => params.get_liveness_slash_percent(),
                        PunishmentKind::ByzantineFault => params.get_byzantine_slash_percent(),
                    },
                );
                // Update the last slash record for query
                staking.last_slash = Some(SlashRecord {
                    kind,
                    time: block_time,
                    amount,
                });
                staking.inc_nonce();
                set_staking(heap, staking, self.minimal_required_staking);
                (addr, amount, kind)
            })
            .collect::<Vec<_>>();

        #[cfg(debug_assertions)]
        self.check_invariants(heap);
        slashes
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

    /// Handle `NodeJoinTx`
    pub fn node_join(
        &mut self,
        heap: &mut impl StoreStaking,
        block_time: Timespec,
        tx: &NodeJoinRequestTx,
    ) -> Result<(), PublicTxError> {
        let mut staking = self.get_or_default(heap, &tx.address);
        if tx.nonce != staking.nonce {
            return Err(PublicTxError::IncorrectNonce);
        }
        if staking.bonded < self.minimal_required_staking {
            return Err(NodeJoinError::BondedNotEnough.into());
        }
        let val_addr = TendermintValidatorAddress::from(&tx.node_meta.consensus_pubkey);
        if let Some(val) = &mut staking.validator {
            if val.is_jailed() {
                return Err(NodeJoinError::IsJailed.into());
            }
            if !val.is_active() {
                let old_val_addr = val.validator_address();
                if old_val_addr != val_addr {
                    // Only check the duplicates if it's not our own.
                    if self.idx_validator_address.contains_key(&val_addr) {
                        return Err(NodeJoinError::DuplicateValidatorAddress.into());
                    }

                    // Add the old one to the used list.
                    let out_of_date = add_old_val_addr(
                        &mut val.used_validator_addresses,
                        block_time,
                        &old_val_addr,
                        MAX_USED_VALIDATOR_ADDR,
                    )
                    .ok_or(PublicTxError::NodeJoin(
                        NodeJoinError::UsedValidatorAddrFull,
                    ))?;

                    for used_addr in out_of_date.into_iter() {
                        assert_eq!(
                            self.idx_validator_address.remove(&used_addr),
                            Some(tx.address)
                        );
                    }
                    self.idx_validator_address.insert(val_addr, tx.address);
                }
                val.council_node = tx.node_meta.clone();
                val.inactive_time = None;
                val.inactive_block = None;
            } else {
                return Err(NodeJoinError::AlreadyJoined.into());
            }
        } else {
            if self.idx_validator_address.contains_key(&val_addr) {
                return Err(NodeJoinError::DuplicateValidatorAddress.into());
            }

            // insert
            staking.validator = Some(Validator::new(tx.node_meta.clone()));
            self.insert_validator(&staking);
        }
        staking.inc_nonce();
        set_staking(heap, staking, self.minimal_required_staking);
        #[cfg(debug_assertions)]
        self.check_invariants(heap);
        Ok(())
    }

    /// Handle `UnjailTx`
    pub fn unjail(
        &mut self,
        heap: &mut impl StoreStaking,
        block_time: Timespec,
        tx: &UnjailTx,
    ) -> Result<(), PublicTxError> {
        let mut staking = self.get_or_default(heap, &tx.address);
        if tx.nonce != staking.nonce {
            return Err(PublicTxError::IncorrectNonce);
        }

        if let Some(val) = staking.validator.as_mut() {
            if let Some(jailed_until) = val.jailed_until {
                if block_time >= jailed_until {
                    val.unjail();
                    staking.inc_nonce();
                    set_staking(heap, staking, self.minimal_required_staking);

                    #[cfg(debug_assertions)]
                    self.check_invariants(heap);
                    Ok(())
                } else {
                    Err(UnjailError::JailTimeNotExpired.into())
                }
            } else {
                Err(UnjailError::NotJailed.into())
            }
        } else {
            Err(UnjailError::NotJailed.into())
        }
    }

    /// Handle reward statistics record
    pub fn reward_record(
        &mut self,
        heap: &impl GetStaking,
        val_addr: &TendermintValidatorAddress,
    ) -> bool {
        if let Some(addr) = self.idx_validator_address.get(val_addr) {
            // Invarient 2.1
            let staking = heap.get(addr).unwrap();
            // Invarient 2.2
            let val = staking.validator.as_ref().unwrap();
            if val.is_active() {
                self.proposer_stats
                    .entry(*addr)
                    .and_modify(|count| *count = count.saturating_add(1))
                    .or_insert(1);
            }
            true
        } else {
            false
        }
    }

    /// The heap should not use the uncommited buffer.
    pub fn reward_total_staking(&self, heap: &StakingGetter) -> Coin {
        // Sum of all the coins should not overflow max supply, TODO proof.
        sum_coins(
            self.validator_snapshot
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
        let total_blocks = self.proposer_stats.iter().map(|(_, count)| count).sum();
        if total_blocks == 0 {
            return (total_rewards, vec![]);
        }
        // no panic, total_blocks is checked to be not zero.
        let share = (total_rewards / total_blocks).unwrap();

        let mut distributed = Vec::new();
        let mut remainder = total_rewards;
        let stats = std::mem::take(&mut self.proposer_stats);
        for (addr, count) in stats.into_iter() {
            let mut staking = self.get_or_default(heap, &addr);
            let amount = (share * count).unwrap();
            remainder = (remainder - amount).unwrap();
            distributed.push((addr, amount));
            self.add_bonded(amount, &mut staking).unwrap();
            staking.inc_nonce();
            set_staking(heap, staking, self.minimal_required_staking);
        }
        #[cfg(debug_assertions)]
        self.check_invariants(heap);
        assert_eq!(remainder, (total_rewards % total_blocks).unwrap());
        (remainder, distributed)
    }

    /// Handle deposit tx
    /// Enclave validation is done in enclave, only incomplete check here.
    pub fn deposit(
        &mut self,
        heap: &mut impl StoreStaking,
        addr: &StakedStateAddress,
        amount: Coin,
    ) -> Result<(), DepositError> {
        let mut staking = self.get_or_default(heap, addr);
        if staking.is_jailed() {
            return Err(DepositError::IsJailed);
        }

        self.add_bonded(amount, &mut staking)?;
        staking.inc_nonce();

        set_staking(heap, staking, self.minimal_required_staking);
        #[cfg(debug_assertions)]
        self.check_invariants(heap);
        Ok(())
    }

    /// Handle unbond tx
    pub fn unbond(
        &mut self,
        heap: &mut impl StoreStaking,
        unbonding_period: Timespec,
        block_time: Timespec,
        block_height: BlockHeight,
        tx: &UnbondTx,
    ) -> Result<(), PublicTxError> {
        let mut staking = self.get_or_default(heap, &tx.from_staked_account);
        if tx.nonce != staking.nonce {
            return Err(PublicTxError::IncorrectNonce);
        }
        if staking.is_jailed() {
            return Err(UnbondError::IsJailed.into());
        }
        if tx.value == Coin::zero() {
            return Err(UnbondError::ZeroValue.into());
        }
        let unbonded = (staking.unbonded + tx.value).map_err(UnbondError::CoinError)?;
        self.sub_bonded(block_time, block_height, tx.value, &mut staking)
            .map_err(UnbondError::CoinError)?;
        staking.unbonded = unbonded;
        staking.unbonded_from = block_time.saturating_add(unbonding_period);
        staking.inc_nonce();
        set_staking(heap, staking, self.minimal_required_staking);
        #[cfg(debug_assertions)]
        self.check_invariants(heap);
        Ok(())
    }

    /// Handle withdraw tx
    /// Enclave validation is done in enclave, only incomplete check here.
    pub fn withdraw(
        &mut self,
        heap: &mut impl StoreStaking,
        block_time: Timespec,
        addr: &StakedStateAddress,
        amount: Coin,
    ) -> Result<(), WithdrawError> {
        let mut staking = self.get_or_default(heap, addr);
        if staking.is_jailed() {
            return Err(WithdrawError::IsJailed);
        }
        if block_time < staking.unbonded_from {
            return Err(WithdrawError::InUnbondingPeriod);
        }
        if staking.unbonded != amount {
            return Err(WithdrawError::UnbondedSanityCheck(staking.unbonded, amount));
        }
        staking.unbonded = Coin::zero();
        staking.inc_nonce();
        set_staking(heap, staking, self.minimal_required_staking);
        #[cfg(debug_assertions)]
        self.check_invariants(heap);
        Ok(())
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

    /// Insert validator (genesis or join-node tx)
    /// Caller should do the validations:
    /// - StakedState has validator record
    /// - Both the staking address and validator address should not already exists in the indexing
    /// structures
    fn insert_validator(&mut self, staking: &StakedState) {
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
        assert_eq!(self.idx_sort.insert(staking.sort_key()), true);

        let tracker = LivenessTracker::new();
        assert!(self.liveness.insert(staking.address, tracker).is_none());
    }

    /// Change bonded, and related index, inactivate validator if not enough amount.
    fn sub_bonded(
        &mut self,
        block_time: Timespec,
        block_height: BlockHeight,
        amount: Coin,
        staking: &mut StakedState,
    ) -> Result<(), CoinError> {
        let bonded = (staking.bonded - amount)?;
        if staking.validator.is_some() {
            assert!(self.idx_sort.remove(&staking.sort_key()));
        }
        staking.bonded = bonded;
        if staking.validator.is_some() {
            assert!(self.idx_sort.insert(staking.sort_key()));
        }

        if let Some(val) = staking.validator.as_mut() {
            if val.is_active() && staking.bonded < self.minimal_required_staking {
                val.inactivate(block_time, block_height);
            }
        }
        Ok(())
    }
    fn add_bonded(&mut self, amount: Coin, staking: &mut StakedState) -> Result<(), CoinError> {
        let bonded = (staking.bonded + amount)?;
        if staking.validator.is_some() {
            assert!(self.idx_sort.remove(&staking.sort_key()));
        }
        staking.bonded = bonded;
        if staking.validator.is_some() {
            assert!(self.idx_sort.insert(staking.sort_key()));
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
    ) -> Coin {
        let bonded_slashed = staking.bonded * ratio;
        let unbonded_slashed = staking.unbonded * ratio;
        // no panic: SlashRatio invariant(<= 1.0)
        self.sub_bonded(block_time, block_height, bonded_slashed, staking)
            .unwrap();
        // no panic: SlashRatio invariant(<= 1.0)
        staking.unbonded = (staking.unbonded - unbonded_slashed).unwrap();
        // no panic: Invariant: 4.1 + SlashRatio invariant
        // slashed_amount <= bonded + unbonded <= max supply
        (bonded_slashed + unbonded_slashed).unwrap()
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
            assert!(self.idx_sort.remove(&staking.sort_key()));
            assert!(self.liveness.remove(addr).is_some());
            self.proposer_stats.remove(addr);

            staking.validator = None;
            staking.inc_nonce();
            set_staking(heap, staking, self.minimal_required_staking);
        }

        #[cfg(debug_assertions)]
        self.check_invariants(heap);
    }

    /// #generate-validator-updates
    fn update_validators(
        &mut self,
        heap: &impl GetStaking,
        max_validators: usize,
    ) -> Vec<(TendermintValidatorPubKey, TendermintVotePower)> {
        let new = self.choose_validators(heap, max_validators);
        let updates = diff_validators(&self.validator_snapshot, &new);
        self.validator_snapshot = new;
        updates
            .into_iter()
            .map(|(addr, power)| (self.get_validator_pubkey(heap, &addr), power))
            .collect()
    }

    #[cfg(debug_assertions)]
    fn check_invariants(&mut self, heap: &impl GetStaking) {
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

    fn get_or_default(&self, heap: &impl GetStaking, addr: &StakedStateAddress) -> StakedState {
        let staking = heap.get_or_default(addr);
        #[cfg(debug_assertions)]
        assert_eq!(&staking.address, addr);
        #[cfg(debug_assertions)]
        staking.check_invariants(self.minimal_required_staking);
        staking
    }
}

fn set_staking(heap: &mut impl StoreStaking, staking: StakedState, minimal_required_staking: Coin) {
    #[cfg(debug_assertions)]
    staking.check_invariants(minimal_required_staking);
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

/// Return success or not
fn add_old_val_addr(
    used: &mut Vec<(TendermintValidatorAddress, Timespec)>,
    block_time: Timespec,
    old_val_addr: &TendermintValidatorAddress,
    max_bound: usize,
) -> Option<Vec<TendermintValidatorAddress>> {
    // Move the out of date ones out
    let out_of_date = used
        .iter()
        .filter_map(|(addr, ts)| {
            if ts.saturating_add(MAX_EVIDENCE_AGE) <= block_time {
                Some(addr)
            } else {
                None
            }
        })
        .cloned()
        .collect::<Vec<_>>();
    if used.len() - out_of_date.len() < max_bound {
        used.retain(|(_, ts)| ts.saturating_add(MAX_EVIDENCE_AGE) > block_time);
        used.push((old_val_addr.clone(), block_time));
        Some(out_of_date)
    } else {
        None
    }
}

pub type RewardsDistribution = Vec<(StakedStateAddress, Coin)>;

#[cfg(test)]
mod tests {
    use secp256k1::{
        key::{PublicKey, SecretKey},
        Secp256k1,
    };

    use super::*;
    use chain_core::init::address::RedeemAddress;
    use chain_core::init::config::SlashRatio;
    use chain_core::init::params::NetworkParameters;
    use chain_core::state::account::{CouncilNode, StakedState, StakedStateAddress};
    use chain_core::state::tendermint::TendermintValidatorPubKey;
    use chain_core::state::validator::NodeJoinRequestTx;
    use chain_storage::buffer::MemStore;
    use test_common::chain_env::get_init_network_params;

    macro_rules! matches {
    ($expression:expr, $( $pattern:pat )|+ $( if $guard: expr )?) => {
        match $expression {
            $( $pattern )|+ $( if $guard )? => true,
            _ => false
        }
    }
}

    type StakingMemStore = MemStore<StakedStateAddress, StakedState>;

    fn staking_address(seed: &[u8; 32]) -> StakedStateAddress {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(seed).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        StakedStateAddress::BasicRedeem(RedeemAddress::from(&public_key))
    }

    fn validator_pubkey(seed: &[u8; 32]) -> TendermintValidatorPubKey {
        TendermintValidatorPubKey::Ed25519(seed.clone())
    }

    fn new_validator(seed: &[u8; 32], bonded: Coin) -> StakedState {
        let mut staking = StakedState::default(staking_address(seed));
        staking.bonded = bonded;
        staking.validator = Some(Validator::new(CouncilNode::new(
            TendermintValidatorPubKey::Ed25519(seed.clone()),
        )));
        staking
    }

    fn init_staking_table() -> (StakingTable, StakingMemStore) {
        let minimal = Coin::new(10_0000_0000).unwrap();
        let genesis_accounts = vec![
            new_validator(
                &[0xcc; 32],
                (minimal + Coin::new(1_0000_0000).unwrap()).unwrap(),
            ),
            new_validator(
                &[0xcd; 32],
                (minimal + Coin::new(2_0000_0000).unwrap()).unwrap(),
            ),
            new_validator(
                &[0xce; 32],
                (minimal + Coin::new(3_0000_0000).unwrap()).unwrap(),
            ),
        ];
        let mut store = StakingMemStore::new();
        for staking in genesis_accounts.iter() {
            #[cfg(debug_assertions)]
            staking.check_invariants(minimal);
            store.set_staking(staking.clone());
        }
        (
            StakingTable::from_genesis(
                &store,
                minimal,
                3,
                &genesis_accounts
                    .iter()
                    .map(|staking| staking.address)
                    .collect::<Vec<_>>(),
            ),
            store,
        )
    }

    #[test]
    fn check_choose_validators() {
        let (mut table, mut store) = init_staking_table();
        let addr4 = staking_address(&[0xcf; 32]);
        let val_pk4 = validator_pubkey(&[0xcf; 32]);
        let amount = Coin::new(10_0000_0000).unwrap();
        table.deposit(&mut store, &addr4, amount).unwrap();
        let node_join = NodeJoinRequestTx {
            nonce: 1,
            address: addr4,
            attributes: Default::default(),
            node_meta: CouncilNode::new(val_pk4.clone()),
        };
        table.node_join(&mut store, 10, &node_join).unwrap();
        assert_eq!(table.end_block(&store, 3), vec![]);

        // after deposit, replace one of the existing validator
        table
            .deposit(&mut store, &addr4, Coin::new(2_0000_0000).unwrap())
            .unwrap();
        let val_pk1 = validator_pubkey(&[0xcc; 32]);
        assert_eq!(
            table.end_block(&store, 3),
            vec![
                (val_pk4.clone(), Coin::new(12_0000_0000).unwrap().into()),
                (val_pk1.clone(), Coin::zero().into())
            ]
        );

        // after unbond, the previous validator recover
        let unbond = UnbondTx {
            from_staked_account: addr4,
            nonce: 3,
            value: Coin::new(2_0000_0000).unwrap(),
            attributes: Default::default(),
        };
        table
            .unbond(&mut store, 10, 0, BlockHeight::genesis(), &unbond)
            .unwrap();
        assert_eq!(
            table.end_block(&store, 3),
            vec![
                (val_pk1, Coin::new(11_0000_0000).unwrap().into()),
                (val_pk4, Coin::zero().into())
            ]
        );
    }

    #[test]
    fn check_jailing() {
        let mut init_params = get_init_network_params(Coin::zero());
        let slash_ratio: SlashRatio = "0.01".parse().unwrap();
        init_params.slashing_config.liveness_slash_percent = slash_ratio;
        init_params.slashing_config.byzantine_slash_percent = slash_ratio;
        let params = NetworkParameters::Genesis(init_params);

        let (mut table, mut store) = init_staking_table();
        let addr1 = staking_address(&[0xcc; 32]);
        let val_pk1 = validator_pubkey(&[0xcc; 32]);
        let evidence = (val_pk1.clone().into(), 1.into(), 0);
        let slashes = table.begin_block(&mut store, &params, 0, 1.into(), &[], &[evidence.clone()]);
        let slash = (
            addr1,
            Coin::new(11_0000_0000).unwrap() * slash_ratio,
            PunishmentKind::ByzantineFault,
        );
        assert_eq!(slashes, vec![slash]);
        let staking = store.get(&addr1).unwrap();
        assert!(staking.is_jailed());
        assert_eq!(
            table.end_block(&store, 3),
            vec![(val_pk1.clone(), Coin::zero().into())]
        );

        // byzantine faults won't slashed again.
        let slashes = table.begin_block(&mut store, &params, 1, 2.into(), &[], &[evidence]);
        assert_eq!(slashes, vec![]);

        // transaction denied after jailed
        let unbond = UnbondTx {
            from_staked_account: addr1,
            nonce: 1,
            value: staking.bonded,
            attributes: Default::default(),
        };
        assert!(matches!(
            table.unbond(&mut store, 10, 2, 3.into(), &unbond),
            Err(PublicTxError::Unbond(UnbondError::IsJailed))
        ));
        assert!(matches!(
            table.deposit(&mut store, &addr1, Coin::new(2_0000_0000).unwrap()),
            Err(DepositError::IsJailed)
        ));
        assert!(matches!(
            table.withdraw(&mut store, 0, &addr1, staking.unbonded),
            Err(WithdrawError::IsJailed)
        ));
        let val_pk_new = validator_pubkey(&[0xcf; 32]);
        let node_join = NodeJoinRequestTx {
            nonce: 1,
            address: addr1,
            attributes: Default::default(),
            node_meta: CouncilNode::new(val_pk_new),
        };
        assert!(matches!(
            table.node_join(&mut store, 3, &node_join),
            Err(PublicTxError::NodeJoin(NodeJoinError::IsJailed))
        ));
    }

    #[test]
    fn check_used_validator_key() {
        let (mut table, mut store) = init_staking_table();
        let addr1 = staking_address(&[0xcc; 32]);
        let val_pk1 = validator_pubkey(&[0xcc; 32]);
        let val_pk_new = validator_pubkey(&[0xcf; 32]);

        // unbond/deposit/re-join
        let staking = store.get(&addr1).unwrap();
        let unbond = UnbondTx {
            from_staked_account: addr1,
            nonce: 0,
            value: staking.bonded,
            attributes: Default::default(),
        };
        table.unbond(&mut store, 10, 0, 1.into(), &unbond).unwrap();
        assert_eq!(
            table.end_block(&store, 3),
            vec![(val_pk1.clone(), Coin::zero().into())]
        );
        table
            .deposit(&mut store, &addr1, Coin::new(11_0000_0000).unwrap())
            .unwrap();
        let node_join = NodeJoinRequestTx {
            nonce: 2,
            address: addr1,
            attributes: Default::default(),
            node_meta: CouncilNode::new(val_pk_new),
        };
        // change to new validator key
        table.node_join(&mut store, 1, &node_join).unwrap();

        let addr_new = staking_address(&[0xcf; 32]);
        table
            .deposit(&mut store, &addr_new, Coin::new(10_0000_0000).unwrap())
            .unwrap();
        let node_join = NodeJoinRequestTx {
            nonce: 1,
            address: addr_new,
            attributes: Default::default(),
            node_meta: CouncilNode::new(val_pk1),
        };
        // can't join with used key
        assert!(matches!(
            table.node_join(&mut store, 1, &node_join),
            Err(PublicTxError::NodeJoin(
                NodeJoinError::DuplicateValidatorAddress
            ))
        ),);
    }
}
