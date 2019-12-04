use std::cmp::min;

use chain_core::common::fixed::{exp, FixedNumber};
use chain_core::init::{coin::Coin, params::NetworkParameters};
use chain_core::state::account::StakedStateAddress;
use chain_core::state::tendermint::{TendermintValidatorAddress, TendermintVotePower};
use chain_core::tx::fee::Milli;

use crate::app::{update_account, ChainNodeApp};
use crate::enclave_bridge::EnclaveProxy;
use crate::storage::tx::get_account;

fn milli_to_fixed(n: Milli) -> FixedNumber {
    FixedNumber::from_num(n.as_millis()) / 1000
}

pub fn monetary_expansion(
    tau: Milli,
    total_staking: Coin,
    minted: Coin,
    params: &NetworkParameters,
) -> Coin {
    let cap = params.get_rewards_monetary_expansion_cap();
    let r0 = milli_to_fixed(params.get_rewards_monetary_expansion_r0());
    let tau = milli_to_fixed(tau);
    let total_staking = FixedNumber::from_num(u64::from(total_staking)) / 1_0000_0000;
    let amount = total_staking * r0 * exp(-total_staking / tau) * 1_0000_0000;
    min(
        (cap - minted).unwrap_or_default(),
        Coin::new(amount.to_num()).unwrap(),
    )
}

type RewardsDistribution = Vec<(StakedStateAddress, Coin)>;
impl<T: EnclaveProxy> ChainNodeApp<T> {
    /// Distribute rewards pool
    pub fn rewards_try_distribute(&mut self) -> Option<(RewardsDistribution, Coin)> {
        let state = self.last_state.as_mut().unwrap();

        if state.block_time < state.genesis_time
            || state.block_time < state.rewards_pool.last_distribution_time
        {
            // FIXME use global overflow/underflow check.
            panic!("invalid block time");
        }

        if state.block_time - state.rewards_pool.last_distribution_time
            < state.network_params.get_rewards_distribution_period() as u64
        {
            return None;
        }
        self.rewards_pool_updated = true;

        let mut total_staking = Coin::zero();
        for (addr, _) in self.validator_voting_power.iter() {
            let account = get_account(addr, &state.last_account_root_hash, &self.accounts)
                .expect("io error or validator account not exists");
            total_staking = (total_staking + account.bonded).expect("coin overflow");
        }

        let minted = monetary_expansion(
            state.rewards_pool.tau,
            total_staking,
            state.rewards_pool.minted,
            &state.network_params,
        );

        // tau decay
        state.rewards_pool.tau = Milli::from_millis(
            state.rewards_pool.tau.as_millis()
                * state.network_params.get_rewards_monetary_expansion_decay() as u64
                / 1_000_000,
        );

        let total_rewards = (state.rewards_pool.period_bonus + minted).unwrap();
        state.rewards_pool.minted = (state.rewards_pool.minted + minted).unwrap();

        let total_blocks = state.proposer_stats.iter().map(|(_, count)| count).sum();
        let share = (total_rewards / total_blocks).unwrap();
        state.rewards_pool.period_bonus = (total_rewards % total_blocks).unwrap();

        let mut root = self.uncommitted_account_root_hash;
        let mut distributed: RewardsDistribution = vec![];
        if share > Coin::zero() {
            for (addr, &count) in state.proposer_stats.iter() {
                let mut state = get_account(addr, &root, &self.accounts)
                    .expect("io error or validator account not exists");

                let amount = (share * count).unwrap();
                let balance = state.add_reward(amount).unwrap();
                root = update_account(state, &root, &mut self.accounts).0;
                distributed.push((*addr, amount));
                self.power_changed_in_block
                    .insert(*addr, TendermintVotePower::from(balance));
            }
        }

        self.uncommitted_account_root_hash = root;
        state.proposer_stats.clear();
        Some((distributed, minted))
    }

    pub fn rewards_record_proposer(&mut self, addr: &TendermintValidatorAddress) {
        let state = self.last_state.as_mut().unwrap();
        let staking_address = state
            .validators
            .tendermint_validator_addresses
            .get(addr)
            .expect("block proposer is not found");
        state
            .proposer_stats
            .entry(*staking_address)
            .and_modify(|count| *count += 1)
            .or_insert_with(|| 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abci::*;
    use chain_core::common::Timespec;
    use protobuf::well_known_types::Timestamp;
    use test_common::chain_env::{get_account, ChainEnv};

    fn seconds_to_timestamp(secs: Timespec) -> Timestamp {
        let mut ts = Timestamp::new();
        ts.set_seconds(secs as i64);
        ts
    }

    #[test]
    fn check_rewards_distribution() {
        let expansion_cap = Coin::new(10_0000_0000_0000_0000).unwrap();
        let dist = Coin::new(10_0000_0000_0000_0000).unwrap();
        let (env, storage, account_storage) = ChainEnv::new(dist, expansion_cap, 2);
        let mut app = env.chain_node(storage, account_storage);
        let _rsp = app.init_chain(&env.req_init_chain());

        let total_staking = dist;

        // propose block by first validator.
        let state = app.last_state.as_ref().unwrap();
        let reward1 = monetary_expansion(
            state.rewards_pool.tau,
            total_staking,
            state.rewards_pool.minted,
            &state.network_params,
        );
        let mut req = env.req_begin_block(1, 0);
        req.mut_header().set_time(seconds_to_timestamp(
            state.block_time + state.network_params.get_rewards_distribution_period() as Timespec,
        ));
        app.begin_block(&req);
        app.end_block(&RequestEndBlock::new());
        app.commit(&RequestCommit::new());

        // check the rewards
        let state = app.last_state.as_ref().unwrap();
        let staking = state
            .validators
            .tendermint_validator_addresses
            .get(&env.validator_address(0))
            .unwrap();
        let acct = get_account(staking, &app);
        assert_eq!(acct.bonded, (env.share() + reward1).unwrap());

        // propose block by second validator.
        let reward2 = monetary_expansion(
            state.rewards_pool.tau,
            (total_staking + reward1).unwrap(),
            state.rewards_pool.minted,
            &state.network_params,
        );
        let mut req = env.req_begin_block(2, 1);
        req.mut_header().set_time(seconds_to_timestamp(
            state.block_time + state.network_params.get_rewards_distribution_period() as u64,
        ));
        req.set_last_commit_info(env.last_commit_info_signed());
        app.begin_block(&req);
        app.end_block(&RequestEndBlock::new());
        app.commit(&RequestCommit::new());

        // check the rewards
        let state = app.last_state.as_ref().unwrap();
        let staking = state
            .validators
            .tendermint_validator_addresses
            .get(&env.validator_address(1))
            .unwrap();
        let acct = get_account(staking, &app);
        assert_eq!(acct.bonded, (env.share() + reward2).unwrap());

        // rewards decrease
        assert!(reward2 > Coin::zero() && reward2 < reward1);
    }
}
