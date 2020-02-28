use std::cmp::min;
use std::convert::TryInto;

use crate::app::ChainNodeApp;
use crate::enclave_bridge::EnclaveProxy;
use crate::storage::get_account;
use chain_core::common::fixed::monetary_expansion;
use chain_core::init::coin::Coin;
use chain_core::state::account::StakedStateAddress;
use chain_storage::account::update_staked_state;

// When rate <= 1_000_000, no overflow.
fn mul_micro(n: u64, rate: u64) -> u64 {
    assert!(rate <= 1_000_000);
    let div = n / 1_000_000;
    let rem = n % 1_000_000;
    div * rate + rem * rate / 1_000_000
}

pub type RewardsDistribution = Vec<(StakedStateAddress, Coin)>;

impl<T: EnclaveProxy> ChainNodeApp<T> {
    /// Distribute the rewards pool
    pub fn rewards_try_distribute(&mut self) -> Option<(RewardsDistribution, Coin)> {
        // Current block time
        let block_time = self.state().block_time;
        if self
            .rewards_pool()
            .last_distribution_time
            .saturating_add(self.network_params().get_rewards_reward_period_seconds())
            > block_time
        {
            // nothing to do if reward period not reached yet
            return None;
        }

        self.rewards_pool_mut().last_distribution_time = block_time;
        self.rewards_pool_updated = true;

        // Compute newly minted coins
        let can_mint = self
            .network_params()
            .get_rewards_monetary_expansion_cap()
            .saturating_sub(self.rewards_pool().minted);
        let minted = min(
            monetary_expansion(
                self.total_staking(),
                self.rewards_pool().current_tau,
                self.network_params().get_rewards_monetary_expansion_r0(),
                self.network_params().get_rewards_reward_period_seconds(),
            ),
            can_mint,
        );
        log::info!("minted for rewards: {}", minted);

        // Decay the tau parameter
        // `mul_micro` computes `a * b / 1000` without risk of overflow
        self.rewards_pool_mut().current_tau = mul_micro(
            self.rewards_pool().current_tau,
            self.network_params().get_rewards_monetary_expansion_decay() as u64,
        );

        // Update the minted record
        self.rewards_pool_mut().minted = (self.rewards_pool().minted + minted).unwrap();

        // Total reward pool for this period
        let reward_pool = (self.rewards_pool().period_bonus + minted).unwrap();

        // Compute `reward_pool * power / sum_power` for each participator
        let sum_power = self
            .validator_state()
            .signed_voters
            .values()
            .fold(0u64, |acc, n| acc.saturating_add(*n));

        // Compute the rewards distribution,
        // compute `reward_pool * power / sum_power` for each participator
        let mut distribution: RewardsDistribution = vec![];
        let remains = if sum_power > 0 {
            // Remaining coins after distribution
            let mut remains = reward_pool;

            for (addr, &power) in self.validator_state().signed_voters.iter() {
                // Use u128 to prevent overflow of intermidiate results
                let amount: u128 =
                    u128::from(reward_pool) * u128::from(power) / u128::from(sum_power);
                let amount = Coin::new(amount.try_into().unwrap()).unwrap();
                remains = remains.saturating_sub(amount);
                distribution.push((*addr, amount));
            }
            remains
        } else {
            Coin::zero()
        };

        // Add the rewards to the accounts
        self.add_rewards(&distribution);

        // Remains of distribution goes back to the reward pool
        self.rewards_pool_mut().period_bonus = remains;

        // Clear rewards statistics
        self.validator_state_mut().signed_voters.clear();

        // Result will be written into block result event list
        Some((distribution, minted))
    }

    fn add_rewards(&mut self, distribution: &[(StakedStateAddress, Coin)]) {
        let mut account_root = self.uncommitted_account_root_hash;
        for (addr, amount) in distribution.iter() {
            let mut account = get_account(addr, &account_root, &self.accounts)
                .expect("io error or validator account not exists");

            if account.is_jailed() {
                log::error!(
                    "Jailed validator should not have reward stats, will cause coins burned"
                );
                continue;
            }
            account.add_reward(*amount).unwrap();
            account_root =
                update_staked_state(account.clone(), &account_root, &mut self.accounts).0;
            self.update_voting_power(&account);
        }
        self.uncommitted_account_root_hash = account_root;
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
            total_staking.into(),
            top_level.rewards_pool.current_tau,
            top_level.network_params.get_rewards_monetary_expansion_r0(),
            top_level.network_params.get_rewards_reward_period_seconds(),
        );
        // signed by one voters
        let mut req = env.req_begin_block(1, 0);
        req.mut_header().set_time(seconds_to_timestamp(
            state.block_time + top_level.network_params.get_rewards_reward_period_seconds(),
        ));
        app.begin_block(&req);
        app.end_block(&RequestEndBlock::new());
        app.commit(&RequestCommit::new());

        // check the rewards
        let state = app.last_state.as_ref().unwrap();
        let top_level = &state.top_level;
        let staking = state.validators.lookup_address(&env.validator_address(0));
        let acct = get_account(staking, &app);
        assert_eq!(acct.bonded, (env.share() + reward1).unwrap());
        assert_eq!(acct.nonce, 1);

        // propose block by second validator.
        let reward2 = monetary_expansion(
            (total_staking + reward1).unwrap().into(),
            top_level.rewards_pool.current_tau,
            top_level.network_params.get_rewards_monetary_expansion_r0(),
            top_level.network_params.get_rewards_reward_period_seconds(),
        );
        let mut req = env.req_begin_block(2, 1);
        req.mut_header().set_time(seconds_to_timestamp(
            state.block_time + top_level.network_params.get_rewards_reward_period_seconds(),
        ));
        // signed by two voters
        req.set_last_commit_info(env.last_commit_info_signed());
        app.begin_block(&req);
        app.end_block(&RequestEndBlock::new());
        app.commit(&RequestCommit::new());

        // check the rewards
        let state = app.last_state.as_ref().unwrap();
        let staking = state.validators.lookup_address(&env.validator_address(1));
        let acct = get_account(staking, &app);
        assert_eq!(
            acct.bonded,
            (env.share()
                + Coin::new(
                    (u128::from(reward2) * (u128::from(env.share()) / 10000_0000_u128)
                        / ((u128::from(total_staking) + u128::from(reward1)) / 10000_0000_u128))
                        .try_into()
                        .unwrap()
                )
                .unwrap())
            .unwrap()
        );
        assert_eq!(acct.nonce, 1);

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
            .reward_period_seconds as u64;
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
