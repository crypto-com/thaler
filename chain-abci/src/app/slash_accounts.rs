use std::convert::TryInto;

use abci::{Event, KVPair};

use chain_core::common::{TendermintEventKey, TendermintEventType};
use chain_core::init::coin::Coin;
use chain_core::init::config::SlashRatio;
use chain_core::state::account::StakedStateAddress;
use chain_core::state::tendermint::TendermintVotePower;
use chain_core::tx::fee::Milli;
use chain_tx_validation::Error;

use crate::app::ChainNodeApp;
use crate::enclave_bridge::EnclaveProxy;
use chain_storage::buffer::{Get, StoreStaking};

impl<T: EnclaveProxy> ChainNodeApp<T> {
    /// Slashes all the eligible accounts currently in slashing queue
    pub fn slash_eligible_accounts(&mut self) -> Result<Event, Error> {
        let last_state = self
            .last_state
            .as_mut()
            .expect("Last state is not present, init_chain was not called");
        let root = Some(last_state.top_level.account_root);

        let current_time = last_state.block_time;

        let accounts_to_slash: Vec<StakedStateAddress> = last_state
            .validators
            .get_accounts_to_be_slashed(current_time);

        let mut slashing_event = Event::new();
        slashing_event.field_type = TendermintEventType::SlashValidators.to_string();

        for staking_address in accounts_to_slash {
            let mut kvpair = KVPair::new();
            kvpair.key = TendermintEventKey::Account.into();
            kvpair.value = staking_address.to_string().into_bytes();

            slashing_event.attributes.push(kvpair);

            let mut account = staking_getter!(self, root)
                .get(&staking_address)
                .ok_or(Error::AccountNotFound)?;

            if !account.is_jailed() {
                panic!("Account scheduled for slashing should already be jailed");
            }

            let schedule = last_state
                .validators
                .remove_slash_schedule(&staking_address);

            let slashed_amount = account
                .slash(schedule.slash_ratio, schedule.punishment_kind)
                .map_err(|_| Error::InvalidSum)?;

            last_state.top_level.rewards_pool.period_bonus =
                (last_state.top_level.rewards_pool.period_bonus + slashed_amount)
                    .map_err(|_| Error::InvalidSum)?;
            self.rewards_pool_updated = true;

            staking_store!(self, root).set_staking(account);
        }

        Ok(slashing_event)
    }
}

pub fn get_vote_power_in_milli(total_bonded: Coin) -> Milli {
    Milli::new(TendermintVotePower::from(total_bonded).into(), 0)
}

/// This is based on: https://github.com/cosmos/cosmos-sdk/blob/master/docs/architecture/adr-014-proportional-slashing.md
pub fn get_slashing_proportion<I: Iterator<Item = (StakedStateAddress, Coin)>>(
    accounts_to_slash: I,
    total_vote_power: Milli,
) -> SlashRatio {
    // TODO: no need to pass StakedStateAddress ?
    let slashing_proportion = Milli::from_millis(
        accounts_to_slash
            .map(|(_address, vp)| {
                let validator_voting_power = get_vote_power_in_milli(vp);

                let validator_voting_percent = validator_voting_power / total_vote_power;

                validator_voting_percent.sqrt().as_millis()
            })
            .sum(),
    );

    std::cmp::min(Milli::new(1, 0), slashing_proportion * slashing_proportion)
        .try_into()
        .unwrap() // This will never panic because input is always lower than 1.0
}
