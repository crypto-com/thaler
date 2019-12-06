use abci::*;
use parity_scale_codec::Encode;
use protobuf::well_known_types::Timestamp;

use chain_core::init::coin::Coin;
use chain_core::state::account::PunishmentKind;
use chain_core::state::tendermint::TendermintVotePower;
use test_common::chain_env::{get_account, ChainEnv};

#[test]
fn end_block_should_update_liveness_tracker() {
    // Init Chain
    let (env, storage, account_storage) = ChainEnv::new(Coin::max(), Coin::zero(), 1);
    let mut app = env.chain_node(storage, account_storage);
    let _rsp = app.init_chain(&env.req_init_chain());

    // Begin Block
    app.begin_block(&env.req_begin_block(1, 0));

    // Unbond Transaction (this'll change voting power to zero)
    let tx_aux = env.unbond_tx(Coin::new(10_000_000_000).unwrap(), 0);
    let rsp_tx = app.deliver_tx(&RequestDeliverTx {
        tx: tx_aux.encode(),
        ..Default::default()
    });

    assert_eq!(0, rsp_tx.code);
    assert_eq!(
        0,
        i64::from(
            *app.power_changed_in_block
                .get(&env.accounts[0].staking_address())
                .expect("Power did not change after unbonding funds")
        )
    );

    // End Block (this'll remove validator from liveness tracker)
    let validator_address = env.validator_address(0);
    assert!(app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .validator_liveness
        .contains_key(&validator_address));

    let response_end_block = app.end_block(&RequestEndBlock {
        height: 1,
        ..Default::default()
    });

    assert_eq!(1, response_end_block.validator_updates.to_vec().len());
    assert_eq!(0, response_end_block.validator_updates.to_vec()[0].power);
    // no longer in the current set of validators
    assert!(!app
        .validator_voting_power
        .contains_key(&env.accounts[0].staking_address()));
    let zero_key = (
        TendermintVotePower::zero(),
        env.accounts[0].staking_address(),
    );
    assert!(app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .council_nodes_by_power
        .contains_key(&zero_key));
    assert!(!app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .validator_liveness
        .contains_key(&validator_address));
}

#[test]
fn begin_block_should_jail_byzantine_validators() {
    // Init Chain
    let (env, storage, account_storage) = ChainEnv::new(Coin::max(), Coin::zero(), 1);
    let mut app = env.chain_node(storage, account_storage);
    let _rsp_init_chain = app.init_chain(&env.req_init_chain());

    // Begin Block
    app.begin_block(&RequestBeginBlock {
        byzantine_validators: vec![env.byzantine_evidence(0)].into(),
        ..env.req_begin_block(1, 0)
    });
    assert_eq!(
        TendermintVotePower::zero(),
        *app.power_changed_in_block
            .get(&env.accounts[0].staking_address())
            .unwrap()
    );

    let account = get_account(&env.accounts[0].staking_address(), &app);
    assert!(account.is_jailed());
}

#[test]
fn begin_block_should_jail_non_live_validators() {
    // Init Chain
    let (env, storage, account_storage) = ChainEnv::new(Coin::max(), Coin::zero(), 1);
    let mut app = env.chain_node(storage, account_storage);
    let _rsp_init_chain = app.init_chain(&env.req_init_chain());

    // Begin Block
    app.begin_block(&RequestBeginBlock {
        last_commit_info: Some(env.last_commit_info(0, false)).into(),
        ..env.req_begin_block(2, 0)
    });

    assert_eq!(
        TendermintVotePower::zero(),
        *app.power_changed_in_block
            .get(&env.accounts[0].staking_address())
            .unwrap()
    );

    let account = get_account(&env.accounts[0].staking_address(), &app);
    assert!(account.is_jailed());
}

#[test]
fn begin_block_should_slash_byzantine_validators() {
    // Init Chain
    let (env, storage, account_storage) = ChainEnv::new(Coin::max(), Coin::zero(), 1);
    let mut app = env.chain_node(storage, account_storage);
    let _rsp_init_chain = app.init_chain(&env.req_init_chain());

    // Begin Block
    app.begin_block(&RequestBeginBlock {
        byzantine_validators: vec![env.byzantine_evidence(0)].into(),
        ..env.req_begin_block(1, 0)
    });

    assert_eq!(
        TendermintVotePower::zero(),
        *app.power_changed_in_block
            .get(&env.accounts[0].staking_address())
            .unwrap()
    );
    assert!(get_account(&env.accounts[0].staking_address(), &app).is_jailed());
    assert!(app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .slashing_schedule
        .contains_key(&env.accounts[0].staking_address()));

    // End Block
    app.end_block(&RequestEndBlock::new());
    assert_eq!(
        Coin::zero(),
        app.last_state
            .as_ref()
            .unwrap()
            .top_level
            .rewards_pool
            .period_bonus
    );

    // Begin Block
    let mut time = Timestamp::new();
    time.seconds = 10;
    let mut req = env.req_begin_block(1, 0);
    req.header.get_mut_ref().time = Some(time).into();
    app.begin_block(&req);

    assert!(!app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .slashing_schedule
        .contains_key(&env.accounts[0].staking_address()));
    assert_eq!(
        Coin::new((u64::from(env.dist_coin) / 10) * 2).unwrap(), // 0.2 * account_balance
        app.last_state
            .as_ref()
            .unwrap()
            .top_level
            .rewards_pool
            .period_bonus
    );
}

#[test]
fn begin_block_should_slash_non_live_validators() {
    // Init Chain
    let (env, storage, account_storage) = ChainEnv::new(Coin::max(), Coin::zero(), 1);
    let mut app = env.chain_node(storage, account_storage);
    let _rsp_init_chain = app.init_chain(&env.req_init_chain());

    // Begin Block
    app.begin_block(&RequestBeginBlock {
        last_commit_info: Some(env.last_commit_info(0, false)).into(),
        ..env.req_begin_block(2, 0)
    });

    assert_eq!(
        TendermintVotePower::zero(),
        *app.power_changed_in_block
            .get(&env.accounts[0].staking_address())
            .unwrap()
    );

    let account = get_account(&env.accounts[0].staking_address(), &app);
    assert!(account.is_jailed());
    assert!(app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .slashing_schedule
        .contains_key(&env.accounts[0].staking_address()));

    // End Block
    app.end_block(&RequestEndBlock::new());
    assert_eq!(
        Coin::zero(),
        app.last_state
            .as_ref()
            .unwrap()
            .top_level
            .rewards_pool
            .period_bonus
    );

    // Begin Block
    let mut time = Timestamp::new();
    time.seconds = 10;
    let mut req = env.req_begin_block(1, 0);
    req.header.get_mut_ref().time = Some(time).into();
    app.begin_block(&req);

    assert!(!app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .slashing_schedule
        .contains_key(&env.accounts[0].staking_address()));
    assert_eq!(
        Coin::new(u64::from(env.dist_coin) / 10).unwrap(), // 0.1 * account_balance
        app.last_state
            .as_ref()
            .unwrap()
            .top_level
            .rewards_pool
            .period_bonus
    );
}

#[test]
fn begin_block_should_update_slash_ratio_for_multiple_punishments() {
    // Init Chain
    let (env, storage, account_storage) = ChainEnv::new(Coin::max(), Coin::zero(), 2);
    let mut app = env.chain_node(storage, account_storage);
    let _rsp_init_chain = app.init_chain(&env.req_init_chain());

    // Begin Block
    app.begin_block(&RequestBeginBlock {
        last_commit_info: Some(env.last_commit_info(0, false)).into(),
        ..env.req_begin_block(2, 0)
    });
    assert_eq!(
        TendermintVotePower::zero(),
        *app.power_changed_in_block
            .get(&env.accounts[0].staking_address())
            .unwrap()
    );

    let account = get_account(&env.accounts[0].staking_address(), &app);
    assert!(account.is_jailed());

    assert!(app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .slashing_schedule
        .contains_key(&env.accounts[0].staking_address()));

    // End Block
    app.end_block(&RequestEndBlock::new());
    assert_eq!(
        Coin::zero(),
        app.last_state
            .as_ref()
            .unwrap()
            .top_level
            .rewards_pool
            .period_bonus
    );

    // Begin Block
    app.begin_block(&RequestBeginBlock {
        byzantine_validators: vec![env.byzantine_evidence(0), env.byzantine_evidence(1)].into(),
        ..env.req_begin_block(1, 0)
    });

    assert!(get_account(&env.accounts[0].staking_address(), &app).is_jailed());
    assert!(app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .slashing_schedule
        .contains_key(&env.accounts[0].staking_address()));

    // End Block
    app.end_block(&RequestEndBlock::new());
    assert_eq!(
        Coin::zero(),
        app.last_state
            .as_ref()
            .unwrap()
            .top_level
            .rewards_pool
            .period_bonus
    );

    // Begin Block
    let mut time = Timestamp::new();
    time.seconds = 10;
    let mut req = env.req_begin_block(1, 0);
    req.header.get_mut_ref().time = Some(time).into();
    app.begin_block(&req);

    assert!(!app
        .last_state
        .as_ref()
        .unwrap()
        .validators
        .punishment
        .slashing_schedule
        .contains_key(&env.accounts[0].staking_address()));
    assert_eq!(
        Coin::new(u64::from(Coin::max()) / 5).unwrap(), // 0.1 * account_balance
        app.last_state
            .as_ref()
            .unwrap()
            .top_level
            .rewards_pool
            .period_bonus
    );
}

#[test]
fn check_successful_jailing() {
    // Init Chain
    let (env, storage, account_storage) = ChainEnv::new(Coin::max(), Coin::zero(), 1);
    let mut app = env.chain_node(storage, account_storage);
    let _rsp_init_chain = app.init_chain(&env.req_init_chain());

    app.jail_account(env.accounts[0].staking_address(), PunishmentKind::NonLive)
        .expect("Unable to jail account");

    let account = get_account(&env.accounts[0].staking_address(), &app);
    assert!(account.is_jailed());
    assert_eq!(
        TendermintVotePower::zero(),
        *app.power_changed_in_block
            .get(&env.accounts[0].staking_address())
            .unwrap()
    );
}
