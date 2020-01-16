use abci::*;
use parity_scale_codec::Encode;
use protobuf::well_known_types::Timestamp;

use chain_core::init::coin::Coin;
use chain_core::state::account::PunishmentKind;
use chain_core::state::tendermint::TendermintVotePower;
use test_common::chain_env::{get_account, ChainEnv};

fn check_unbonding_flow() {
    // Init Chain
    let (env, storage, account_storage) =
        ChainEnv::new_with_customizer(Coin::max(), Coin::zero(), 2, |parameters| {
            parameters.required_council_node_stake = (Coin::max() / 10).unwrap();
        });
    let mut app = env.chain_node(storage, account_storage);
    let _rsp = app.init_chain(&env.req_init_chain());

    // Begin Block
    app.begin_block(&env.req_begin_block(1, 0));

    // At this point, there are two validators with `Coin::max() / 2` staked amount each.
    // Also, `required_council_node_stake` is set to `Coin::max() / 10`.
}
