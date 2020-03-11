use abci::*;
use parity_scale_codec::Encode;

use chain_core::init::coin::Coin;
use test_common::chain_env::{get_account, ChainEnv};

#[test]
fn end_block_should_update_liveness_tracker() {
    // Init Chain
    let (env, storage, account_storage) =
        ChainEnv::new_with_customizer(Coin::max(), Coin::zero(), 1, |parameters| {
            parameters.required_council_node_stake = Coin::max();
        });
    let mut app = env.chain_node(storage, account_storage);
    let _rsp = app.init_chain(&env.req_init_chain());

    // Begin Block
    app.begin_block(&env.req_begin_block(1, 0));

    // Unbond Transaction (this'll change voting power to zero)
    let tx_aux = env.unbond_tx(Coin::new(10_000_000_000).unwrap(), 0, 0);
    let rsp_tx = app.deliver_tx(&RequestDeliverTx {
        tx: tx_aux.encode(),
        ..Default::default()
    });

    assert_eq!(0, rsp_tx.code);

    // End Block (this'll remove validator from liveness tracker)

    let response_end_block = app.end_block(&RequestEndBlock {
        height: 1,
        ..Default::default()
    });

    assert_eq!(1, response_end_block.validator_updates.to_vec().len());
    assert_eq!(0, response_end_block.validator_updates.to_vec()[0].power);
    let state = app
        .last_state
        .as_ref()
        .expect("there should be state after end block");
    // no longer in the current set of validators
    assert!(!state
        .staking_table
        .validator_snapshot
        .contains_key(&env.accounts[0].staking_address()));
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

    let account = get_account(&env.accounts[0].staking_address(), &app);
    assert!(account.is_jailed());
    let response_end_block = app.end_block(&RequestEndBlock {
        height: 1,
        ..Default::default()
    });

    assert_eq!(1, response_end_block.validator_updates.to_vec().len());
    assert_eq!(0, response_end_block.validator_updates.to_vec()[0].power);
}

#[test]
fn begin_block_should_punish_non_live_validators() {
    // Init Chain
    let (env, storage, account_storage) = ChainEnv::new(Coin::max(), Coin::zero(), 1);
    let mut app = env.chain_node(storage, account_storage);
    let _rsp_init_chain = app.init_chain(&env.req_init_chain());

    // Begin Block
    app.begin_block(&RequestBeginBlock {
        last_commit_info: Some(env.last_commit_info(0, false)).into(),
        ..env.req_begin_block(2, 0)
    });

    let val = get_account(&env.accounts[0].staking_address(), &app)
        .validator
        .unwrap();
    assert!(!val.is_jailed());
    assert!(!val.is_active());
    let response_end_block = app.end_block(&RequestEndBlock {
        height: 1,
        ..Default::default()
    });

    assert_eq!(1, response_end_block.validator_updates.to_vec().len());
    assert_eq!(0, response_end_block.validator_updates.to_vec()[0].power);
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

    let account = get_account(&env.accounts[0].staking_address(), &app);
    assert!(account.is_jailed());
    let slash_amount = Coin::new((u64::from(env.dist_coin) / 10) * 2).unwrap();
    assert_eq!(account.last_slash.unwrap().amount, slash_amount);
    assert_eq!(
        slash_amount, // 0.2 * account_balance
        app.last_state
            .as_ref()
            .unwrap()
            .top_level
            .rewards_pool
            .period_bonus
    );

    // End Block
    let response_end_block = app.end_block(&RequestEndBlock::new());
    assert_eq!(1, response_end_block.validator_updates.to_vec().len());
    assert_eq!(0, response_end_block.validator_updates.to_vec()[0].power);
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

    let account = get_account(&env.accounts[0].staking_address(), &app);
    assert!(!account.is_jailed());
    let slash_amount = Coin::new(u64::from(env.dist_coin) / 10).unwrap();
    assert_eq!(account.last_slash.unwrap().amount, slash_amount);
    assert_eq!(
        slash_amount, // 0.1 * account_balance
        app.last_state
            .as_ref()
            .unwrap()
            .top_level
            .rewards_pool
            .period_bonus
    );

    // End Block
    let response_end_block = app.end_block(&RequestEndBlock::new());
    assert_eq!(1, response_end_block.validator_updates.to_vec().len());
    assert_eq!(0, response_end_block.validator_updates.to_vec()[0].power);
}
