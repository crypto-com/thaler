use abci::*;
use chain_abci::app::BufferType;
use chain_core::init::coin::Coin;
use chain_core::state::account::{NodeState, StakedState, Validator as ChainValidator};
use chain_core::state::tendermint::TendermintVotePower;
use chain_core::tx::fee::Milli;
use chain_storage::buffer::Get;
use parity_scale_codec::Encode;
use test_common::chain_env::{get_account, get_validator, ChainEnv, DEFAULT_GENESIS_TIME};

/// Scenario 1: Unbond stake from a validator so that remaining bonded amount is still greater than
/// `required_council_node_stake`. This should not remove validator from validator set.
#[test]
fn check_unbonding_without_removing_validator() {
    // Init Chain
    let (env, storage) =
        ChainEnv::new_with_customizer(Coin::max(), Coin::zero(), 2, |parameters| {
            parameters.required_council_node_stake = (Coin::max() / 10).unwrap();
        });
    let mut app = env.chain_node(storage);
    let _rsp = app.init_chain(&env.req_init_chain());

    // Note: At this point, there are two validators with `Coin::max() / 2` staked amount each.
    // Also, `required_council_node_stake` is set to `Coin::max() / 10`.

    // Scenario 1: Unbond stake from validator 1 so that remaining bonded amount is still greater than
    // `required_council_node_stake`. This should not remove validator from validator set.

    // Begin Block
    app.begin_block(&env.req_begin_block(1, 0));

    // Unbond Transaction
    let tx_aux = env.unbond_tx((Coin::max() / 10).unwrap(), 0, 0);
    let rsp_tx = app.deliver_tx(&RequestDeliverTx {
        tx: tx_aux.encode(),
        ..Default::default()
    });

    assert_eq!(0, rsp_tx.code);

    // End block
    // Note: This should not remove validator from validator set. This should only change voting power of validator 1
    let response_end_block = app.end_block(&RequestEndBlock {
        height: 1,
        ..Default::default()
    });

    assert_eq!(1, response_end_block.validator_updates.to_vec().len());
    assert_eq!(
        i64::from(TendermintVotePower::from(
            ((Coin::max() / 2).unwrap() - (Coin::max() / 10).unwrap()).unwrap()
        )),
        response_end_block.validator_updates.to_vec()[0].power
    );
}

/// Scenario 2: Unbond stake from validator 2 so that the remaining bonded amount becomes less than
/// `required_council_node_stake`. This should remove validator from validator set.
#[test]
fn check_unbonding_with_removing_validator() {
    // Init Chain
    let (mut env, storage) =
        ChainEnv::new_with_customizer(Coin::max(), Coin::zero(), 2, |parameters| {
            parameters.required_council_node_stake = (Coin::max() / 10).unwrap();
        });
    env.max_evidence_age = 61;
    let mut app = env.chain_node(storage);
    let _rsp = app.init_chain(&env.req_init_chain());
    let state = app.last_state.as_ref().unwrap();
    let tm_address = &env.validator_address(0);
    let staking_address = *state.staking_table.lookup_address(&tm_address).unwrap();
    // Note: At this point, there are two validators with `Coin::max() / 2` staked amount each.
    // Also, `required_council_node_stake` is set to `Coin::max() / 10`.

    // Begin Block
    app.begin_block(&env.req_begin_block(1, 0));

    // Unbond Transaction (this'll change voting power to zero)
    let amount = ((Coin::max() / 2).unwrap() - (Coin::max() / 100).unwrap()).unwrap();
    let tx_aux = env.unbond_tx(amount, 0, 0);
    let rsp_tx = app.deliver_tx(&RequestDeliverTx {
        tx: tx_aux.encode(),
        ..Default::default()
    });

    assert_eq!(0, rsp_tx.code);

    // End block
    // Note: This should remove validator from validator set.
    let response_end_block = app.end_block(&RequestEndBlock {
        height: 1,
        ..Default::default()
    });

    assert_eq!(1, response_end_block.validator_updates.to_vec().len());
    assert_eq!(0, response_end_block.validator_updates.to_vec()[0].power);

    app.commit(&RequestCommit::new());
    // Scenario 3: Unbond some stake from validator 2. Since validator 2 was already removed from validator set in
    // scenario 2, this should not trigger any updates
    // Begin Block
    app.begin_block(&RequestBeginBlock {
        last_commit_info: Some(env.last_commit_info(1, true)).into(),
        ..env.req_begin_block(2, 1)
    });

    let amount = Coin::one();
    let tx_aux = env.unbond_tx(amount, 1, 0);
    let rsp_tx = app.deliver_tx(&RequestDeliverTx {
        tx: tx_aux.encode(),
        ..Default::default()
    });

    assert_eq!(0, rsp_tx.code);

    // End block
    // Note: This should not do any updates
    let response_end_block = app.end_block(&RequestEndBlock {
        height: 2,
        ..Default::default()
    });

    assert_eq!(0, response_end_block.validator_updates.to_vec().len());
    app.commit(&RequestCommit::new());
    // as default Timestamp in these block headers is 0 (< time + unbonding period), some validator metadata should still be there
    assert!(!get_validator(&staking_address, &app).is_active());
    let state = app.last_state.as_ref().expect("state");
    // not validator anymore
    assert!(!&state.staking_table.get_chosen_validators().contains_key(
        state
            .staking_table
            .lookup_address(&env.validator_address(0))
            .unwrap()
    ));
    // after unbonding period (in unit testing -- 61), it should be cleaned
    app.begin_block(&RequestBeginBlock {
        last_commit_info: Some(env.last_commit_info(1, true)).into(),
        ..env.req_begin_block_with_time(3, 1, DEFAULT_GENESIS_TIME as i64 + 120)
    });
    assert!(get_account(&staking_address, &app).node_meta.is_none());
}

fn validator_unwrap(state: &StakedState) -> &ChainValidator {
    match &state.node_meta {
        Some(NodeState::CouncilNode(v)) => &v,
        _ => unreachable!(),
    }
}

/// Scenario 4: Unbond stake from validator 2 so that the remaining bonded amount becomes less than
/// `required_council_node_stake` after it proposed block(s). This should remove validator from validator set.
/// After it has received reward, its bonded amount should be > the required one --
/// at that time, it should be possible for the validator to rejoin + validator metadata shouldn't be deleted after unbonding period
#[test]
fn check_rejoin() {
    // Init Chain
    let (mut env, storage) = ChainEnv::new_with_customizer(
        (Coin::max() / 2).unwrap(),
        (Coin::max() / 2).unwrap(),
        2,
        |parameters| {
            // tweaking times + parameters, something more than 0.0... gets minted
            parameters.rewards_config.reward_period_seconds = 365 * 24 * 3600;
            parameters.required_council_node_stake = (Coin::max() / 4).unwrap();
            parameters.rewards_config.monetary_expansion_r0 = Milli::try_new(1, 0).unwrap();
            parameters.rewards_config.monetary_expansion_tau = 1000_0000_0000_0000_0000;
            parameters.rewards_config.monetary_expansion_decay = 0;
        },
    );
    env.max_evidence_age = 3600 * 24 * 10000;
    let mut app = env.chain_node(storage);
    let _rsp = app.init_chain(&env.req_init_chain());
    let state = app.last_state.as_ref().unwrap();
    let tm_address = &env.validator_address(0);
    let staking_address = *state.staking_table.lookup_address(&tm_address).unwrap();
    // Begin Block
    let mut req = env.req_begin_block(1, 0);
    req.set_last_commit_info(env.last_commit_info_signed_by(0));
    app.begin_block(&req);

    // Unbond Transaction (this'll change voting power to zero)
    let amount = Coin::one();
    let tx_aux = env.unbond_tx(amount, 0, 0);
    let rsp_tx = app.deliver_tx(&RequestDeliverTx {
        tx: tx_aux.encode(),
        ..Default::default()
    });

    assert_eq!(0, rsp_tx.code);

    // End block
    // Note: This should not remove validator from validator set. This should only change voting power of validator 1
    let response_end_block = app.end_block(&RequestEndBlock {
        height: 1,
        ..Default::default()
    });
    let required_stake = (Coin::max() / 4).unwrap();
    let acct = get_account(&staking_address, &app);
    assert!(acct.bonded < required_stake);

    assert_eq!(1, response_end_block.validator_updates.to_vec().len());
    assert_eq!(0, response_end_block.validator_updates.to_vec()[0].power);
    app.commit(&RequestCommit::new());
    assert!(!validator_unwrap(&get_account(&staking_address, &app)).is_active());

    // Begin block -- there should be a reward after this one
    app.begin_block(&RequestBeginBlock {
        last_commit_info: Some(env.last_commit_info(1, true)).into(),
        ..env.req_begin_block_with_time(2, 1, DEFAULT_GENESIS_TIME as i64 + 365 * 24 * 3600 + 1)
    });

    let acct = get_account(&staking_address, &app);
    assert!(acct.bonded > required_stake);

    // node join should be ok
    assert!(!validator_unwrap(&get_account(&staking_address, &app)).is_active());

    let tx_aux = env.join_tx(1, 0);
    let rsp_tx = app.deliver_tx(&RequestDeliverTx {
        tx: tx_aux.encode(),
        ..Default::default()
    });
    assert_eq!(0, rsp_tx.code, "{}", rsp_tx.log);
    // it should no longer be planned to be deleted
    assert!(validator_unwrap(
        &app.staking_getter(BufferType::Consensus)
            .get(&staking_address)
            .unwrap()
    )
    .is_active());
    // End block
    // Note: This should bring back the validator to the validator set.
    let response_end_block = app.end_block(&RequestEndBlock {
        height: 2,
        ..Default::default()
    });

    // validator bonded amount changed after rewards + node join
    assert_eq!(2, response_end_block.validator_updates.to_vec().len());
    assert_ne!(0, response_end_block.validator_updates.to_vec()[0].power);
    assert_ne!(0, response_end_block.validator_updates.to_vec()[1].power);
}
