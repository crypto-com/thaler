use abci::{Event, KVPair};

use chain_core::common::TendermintEventType;
use chain_core::state::account::StakedStateAddress;
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

        let failing_validators = last_state.punishment.slashing_schedule.len();
        let total_validators = last_state.council_nodes.len();

        for staking_address in accounts_to_slash {
            let mut kvpair = KVPair::new();
            kvpair.key = b"account".to_vec();
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
                .punishment
                .slashing_schedule
                .remove(&staking_address)
                .unwrap();

            let slashed_amount = account
                .slash(
                    schedule
                        .slash_ratio
                        .get_proportional(failing_validators, total_validators),
                )
                .map_err(|_| Error::InvalidSum)?;

            last_state.rewards_pool.remaining = (last_state.rewards_pool.remaining
                + slashed_amount)
                .map_err(|_| Error::InvalidSum)?;

            let (new_root, _) = update_account(
                account,
                &self.uncommitted_account_root_hash,
                &mut self.accounts,
            );
            self.uncommitted_account_root_hash = new_root;
        }

        Ok(slashing_event)
    }
}
