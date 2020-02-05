use abci::*;
use chain_core::init::coin::Coin;
use chain_core::state::tendermint::TendermintVotePower;
use parity_scale_codec::Encode;
use test_common::chain_env::ChainEnv;

/// Scenario 1: Unbond stake from a validator so that remaining bonded amount is still greater than
/// `required_council_node_stake`. This should not remove validator from validator set.
#[test]
fn check_unbonding_without_removing_validator() {
    // Init Chain
    let (env, storage, account_storage) =
        ChainEnv::new_with_customizer(Coin::max(), Coin::zero(), 2, |parameters| {
            parameters.required_council_node_stake = (Coin::max() / 10).unwrap();
        });
    let mut app = env.chain_node(storage, account_storage);
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
    let (env, storage, account_storage) =
        ChainEnv::new_with_customizer(Coin::max(), Coin::zero(), 2, |parameters| {
            parameters.required_council_node_stake = (Coin::max() / 10).unwrap();
        });
    let mut app = env.chain_node(storage, account_storage);
    let _rsp = app.init_chain(&env.req_init_chain());

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
    // Note: This should not remove validator from validator set. This should only change voting power of validator 1
    let response_end_block = app.end_block(&RequestEndBlock {
        height: 1,
        ..Default::default()
    });

    assert_eq!(1, response_end_block.validator_updates.to_vec().len());
    assert_eq!(0, response_end_block.validator_updates.to_vec()[0].power);

    // Scenario 3: Unbond some stake from validator 2. Since validator 2 was already removed from validator set in
    // scenario 2, this should not trigger and `power_changed_in_block`.
}
