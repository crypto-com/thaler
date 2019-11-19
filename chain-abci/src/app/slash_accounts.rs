use std::convert::TryInto;

use abci::{Event, KVPair};

use chain_core::common::{TendermintEventKey, TendermintEventType};
use chain_core::init::config::SlashRatio;
use chain_core::state::account::StakedStateAddress;
use chain_core::state::tendermint::TendermintVotePower;
use chain_core::tx::fee::Milli;
use chain_tx_validation::Error;

use crate::app::{update_account, ChainNodeApp};
use crate::enclave_bridge::EnclaveProxy;
use crate::storage::tx::get_account;

impl<T: EnclaveProxy> ChainNodeApp<T> {
    /// Slashes all the eligible accounts currently in slashing queue
    pub fn slash_eligible_accounts(&mut self) -> Result<Event, Error> {
        let last_state = self
            .last_state
            .as_mut()
            .expect("Last state is not present, init_chain was not called");

        let current_time = last_state.block_time;

        let accounts_to_slash: Vec<StakedStateAddress> = last_state
            .validators
            .punishment
            .slashing_schedule
            .iter()
            .filter_map(|(address, schedule)| {
                if schedule.can_slash(current_time) {
                    Some(*address)
                } else {
                    None
                }
            })
            .collect();

        let mut slashing_event = Event::new();
        slashing_event.field_type = TendermintEventType::SlashValidators.to_string();

        for staking_address in accounts_to_slash {
            let mut kvpair = KVPair::new();
            kvpair.key = TendermintEventKey::Account.into();
            kvpair.value = staking_address.to_string().into_bytes();

            slashing_event.attributes.push(kvpair);

            let mut account = get_account(
                &staking_address,
                &self.uncommitted_account_root_hash,
                &self.accounts,
            )?;

            if !account.is_jailed() {
                panic!("Account scheduled for slashing should already be jailed");
            }

            let schedule = last_state
                .validators
                .punishment
                .slashing_schedule
                .remove(&staking_address)
                .unwrap();

            let slashed_amount = account
                .slash(schedule.slash_ratio, schedule.punishment_kind)
                .map_err(|_| Error::InvalidSum)?;

            last_state.rewards_pool.remaining = (last_state.rewards_pool.remaining
                + slashed_amount)
                .map_err(|_| Error::InvalidSum)?;
            self.rewards_pool_updated = true;

            let (new_root, _) = update_account(
                account,
                &self.uncommitted_account_root_hash,
                &mut self.accounts,
            );
            self.uncommitted_account_root_hash = new_root;
        }

        Ok(slashing_event)
    }

    // TODO: maintain this value rather than recomputing it
    fn get_total_vote_power(&self) -> Milli {
        Milli::new(
            self.validator_voting_power
                .values()
                .map(|x| i64::from(*x))
                .sum::<i64>() as u64,
            0,
        )
    }

    // This is based on: https://github.com/cosmos/cosmos-sdk/blob/sunny/prop-slashing-adr/docs/architecture/adt-014-proportional-slashing.md
    pub fn get_slashing_proportion<I: Iterator<Item = StakedStateAddress>>(
        &self,
        accounts_to_slash: I,
    ) -> SlashRatio {
        let total_vote_power = self.get_total_vote_power();
        let last_state = self
            .last_state
            .as_ref()
            .expect("Last state is not present, init_chain was not called");

        let slashing_proportion = Milli::from_millis(
            accounts_to_slash
                .map(|address| {
                    let validator_voting_power = Milli::new(
                        TendermintVotePower::from(
                            get_account(
                                &address,
                                &last_state.last_account_root_hash,
                                &self.accounts,
                            )
                            .expect("Voting power for a validator not found")
                            .bonded,
                        )
                        .into(),
                        0,
                    );

                    let validator_voting_percent = validator_voting_power / total_vote_power;

                    validator_voting_percent.sqrt().as_millis()
                })
                .sum(),
        );

        std::cmp::min(Milli::new(1, 0), slashing_proportion * slashing_proportion)
            .try_into()
            .unwrap() // This will never panic because input is always lower than 1.0
    }
}
