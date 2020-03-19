use chain_core::state::account::{PunishmentKind, StakedStateAddress};
use chain_tx_validation::Error;

use crate::app::{BufferType, ChainNodeApp};
use crate::enclave_bridge::EnclaveProxy;
use chain_storage::buffer::{Get, StoreStaking};

impl<T: EnclaveProxy> ChainNodeApp<T> {
    /// Jails staking account with given address
    /// TODO: isolate from ChainNodeApp
    pub fn jail_account(
        &mut self,
        staking_address: StakedStateAddress,
        punishment_kind: PunishmentKind,
    ) -> Result<(), Error> {
        let mut account = self
            .staking_getter(BufferType::Consensus)
            .get(&staking_address)
            .ok_or(Error::AccountNotFound)?;

        if account.is_jailed() {
            // Return early if account is already jailed
            return Ok(());
        }

        let last_state = self
            .last_state
            .as_mut()
            .expect("Last state not found. Init chain was not called.");

        let block_time = last_state.block_time;
        let jail_duration = last_state.top_level.network_params.get_jail_duration();

        account.jail_until(block_time + jail_duration, punishment_kind);

        last_state
            .validators
            .validator_state_helper
            .punish_update(staking_address);

        self.staking_store(BufferType::Consensus)
            .set_staking(account);
        Ok(())
    }
}
