use chain_core::common::Timespec;
use chain_core::init::coin::Coin;
use chain_core::state::account::{StakedStateAddress, UnbondTx, UnjailTx, Validator};
use chain_core::state::tendermint::{BlockHeight, TendermintValidatorAddress};
use chain_core::state::validator::NodeJoinRequestTx;
use chain_storage::buffer::StoreStaking;

use super::table::{set_staking, StakingTable};
use crate::tx_error::{
    DepositError, NodeJoinError, PublicTxError, UnbondError, UnjailError, WithdrawError,
};

// FIXME use consensus parameter after upgrade to tendermint 0.33
const MAX_EVIDENCE_AGE: u64 = 10000;
const MAX_USED_VALIDATOR_ADDR: usize = 10;

impl StakingTable {
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
}

/// Return out of date addresses if success (not exceeds max bound),
/// otherwise None
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
