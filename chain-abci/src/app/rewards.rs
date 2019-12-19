use std::cmp::{max, min};

use chain_core::common::fixed::{exp, FixedNumber, EXP_LOWER_BOUND};
use chain_core::init::{coin::Coin, params::NetworkParameters};
use chain_core::state::account::StakedStateAddress;
use chain_core::state::tendermint::{TendermintValidatorAddress, TendermintVotePower};

use crate::app::{update_account, ChainNodeApp};
use crate::enclave_bridge::EnclaveProxy;
use crate::storage::tx::get_account;

pub fn monetary_expansion(
    tau: u64,
    total_staking: Coin,
    minted: Coin,
    params: &NetworkParameters,
) -> Coin {
    let cap = params.get_rewards_monetary_expansion_cap();
    let r0 = FixedNumber::from_num(params.get_rewards_monetary_expansion_r0().as_millis()) / 1000;
    let tau = FixedNumber::from_num(tau);
    let total_staking = FixedNumber::from_num(u64::from(total_staking));
    let amount = total_staking
        * r0
        * exp(max(
            FixedNumber::from_num(EXP_LOWER_BOUND),
            -total_staking / tau,
        ));
    min(
        (cap - minted).unwrap_or_default(),
        Coin::new(amount.to_num()).unwrap(),
    )
}

// rate < 1_000_000, no overflow.
fn mul_micro(n: u64, rate: u64) -> u64 {
    assert!(rate <= 1_000_000);
    let div = n / 1_000_000;
    let rem = n % 1_000_000;
    div * rate + rem * rate / 1_000_000
}

type RewardsDistribution = Vec<(StakedStateAddress, Coin)>;
impl<T: EnclaveProxy> ChainNodeApp<T> {
    /// Distribute rewards pool
    pub fn rewards_try_distribute(&mut self) -> Option<(RewardsDistribution, Coin)> {
        let state = self.last_state.as_mut().unwrap();
        let top_level = &mut state.top_level;

        if state.block_time < state.genesis_time
            || state.block_time < top_level.rewards_pool.last_distribution_time
        {
            // FIXME use global overflow/underflow check.
            panic!("invalid block time");
        }

        if state.block_time - top_level.rewards_pool.last_distribution_time
            < top_level.network_params.get_rewards_distribution_period() as u64
        {
            return None;
        }
        top_level.rewards_pool.last_distribution_time = state.block_time;
        self.rewards_pool_updated = true;

        let mut total_staking = Coin::zero();
        for (addr, _) in self.validator_voting_power.iter() {
            let account = get_account(addr, &top_level.account_root, &self.accounts)
                .expect("io error or validator account not exists");
            total_staking = (total_staking + account.bonded).expect("coin overflow");
        }

        let minted = monetary_expansion(
            top_level.rewards_pool.tau,
            total_staking,
            top_level.rewards_pool.minted,
            &top_level.network_params,
        );

        // tau decay
        top_level.rewards_pool.tau = mul_micro(
            top_level.rewards_pool.tau,
            top_level
                .network_params
                .get_rewards_monetary_expansion_decay() as u64,
        );

        let total_rewards = (top_level.rewards_pool.period_bonus + minted).unwrap();
        top_level.rewards_pool.minted = (top_level.rewards_pool.minted + minted).unwrap();

        let total_blocks = state.proposer_stats.iter().map(|(_, count)| count).sum();
        let share = (total_rewards / total_blocks).unwrap();
        top_level.rewards_pool.period_bonus = (total_rewards % total_blocks).unwrap();

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
        let top_level = &state.top_level;
        let reward1 = monetary_expansion(
            top_level.rewards_pool.tau,
            total_staking,
            top_level.rewards_pool.minted,
            &top_level.network_params,
        );
        let mut req = env.req_begin_block(1, 0);
        req.mut_header().set_time(seconds_to_timestamp(
            state.block_time
                + top_level.network_params.get_rewards_distribution_period() as Timespec,
        ));
        app.begin_block(&req);
        app.end_block(&RequestEndBlock::new());
        app.commit(&RequestCommit::new());

        // check the rewards
        let state = app.last_state.as_ref().unwrap();
        let top_level = &state.top_level;
        let staking = state
            .validators
            .tendermint_validator_addresses
            .get(&env.validator_address(0))
            .unwrap();
        let acct = get_account(staking, &app);
        assert_eq!(acct.bonded, (env.share() + reward1).unwrap());

        // propose block by second validator.
        let reward2 = monetary_expansion(
            top_level.rewards_pool.tau,
            (total_staking + reward1).unwrap(),
            top_level.rewards_pool.minted,
            &top_level.network_params,
        );
        let mut req = env.req_begin_block(2, 1);
        req.mut_header().set_time(seconds_to_timestamp(
            state.block_time + top_level.network_params.get_rewards_distribution_period() as u64,
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

    #[test]
    fn empty_block_should_not_change_app_hash() {
        let (env, storage, account_storage) = ChainEnv::new(Coin::max(), Coin::zero(), 1);
        let mut app = env.chain_node(storage, account_storage);
        let _rsp_init_chain = app.init_chain(&env.req_init_chain());

        let mut req = env.req_begin_block(1, 0);
        let start_block_time = env
            .init_config
            .network_params
            .rewards_config
            .distribution_period as u64;
        req.mut_header()
            .set_time(seconds_to_timestamp(start_block_time));
        app.begin_block(&req);
        app.end_block(&RequestEndBlock::new());
        app.commit(&RequestCommit::new());
        let start_app_hash = app.last_state.as_ref().unwrap().last_apphash;
        assert_ne!(start_app_hash, env.genesis_app_hash);

        for i in 2..10 {
            let mut req = env.req_begin_block(i, 0);
            req.mut_header()
                .set_time(seconds_to_timestamp(start_block_time));
            req.set_last_commit_info(env.last_commit_info_signed());
            app.begin_block(&req);
            app.end_block(&RequestEndBlock::new());
            app.commit(&RequestCommit::new());
            assert_eq!(
                app.last_state.as_ref().unwrap().last_apphash,
                start_app_hash
            );
        }
    }
}
