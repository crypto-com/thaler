#![no_main]
use abci::Application;
use abci::{
    ConsensusParams, EvidenceParams, PubKey, Request, RequestInitChain, Request_oneof_value,
    ValidatorUpdate,
};
use chain_abci::app::check_validators;
use chain_abci::app::*;
use chain_abci::enclave_bridge::mock::MockClient;
use chain_core::common::MerkleTree;
use chain_core::compute_app_hash;
use chain_core::init::coin::Coin;
use chain_core::init::config::InitConfig;
use chain_core::init::config::NetworkParameters;
use chain_core::state::tendermint::{TendermintValidatorPubKey, TendermintVotePower};
use chain_storage::{Storage, NUM_COLUMNS};
use kvdb::KeyValueDB;
use kvdb_memorydb::create;
use libfuzzer_sys::fuzz_target;
use parity_scale_codec::Decode;
use protobuf;
use std::convert::TryInto;
use std::sync::Arc;
use test_common::chain_env::KEYPACKAGE_VECTOR;

pub fn get_enclave_bridge_mock() -> MockClient {
    MockClient::new(0)
}

fn create_db() -> Arc<dyn KeyValueDB> {
    Arc::new(create(NUM_COLUMNS))
}

const TEST_CHAIN_ID: &str = "test-00";

const TEST_GENESIS: &str = "{
    \"distribution\": {
      \"0x0e7c045110b8dbf29765047380898919c5cb56f4\": [
        \"Bonded\",
        \"1\"
      ],
      \"0x89aef553a06ab0c3173e79de1ce241a9ed3b992c\": [
        \"UnbondedFromGenesis\",
        \"9999999999999999999\"
      ]
    },
    \"network_params\": {
      \"initial_fee_policy\": {
        \"constant\": 1001,
        \"coefficient\": 1001
      },
      \"required_council_node_stake\": \"1\",
      \"required_community_node_stake\": \"1\",
      \"jailing_config\": {
        \"block_signing_window\": 100,
        \"missed_block_threshold\": 50
      },
      \"slashing_config\": {
        \"liveness_slash_percent\": \"0.100\",
        \"byzantine_slash_percent\": \"0.200\",
        \"invalid_commit_slash_percent\": \"0.300\"
      },
      \"rewards_config\": {
        \"monetary_expansion_cap\": \"0\",
        \"reward_period_seconds\": 86400,
        \"monetary_expansion_r0\": 500,
        \"monetary_expansion_tau\": 166666600,
        \"monetary_expansion_decay\": 999860
      },
      \"max_validators\": 2
    },
    \"council_nodes\": {
      \"0x0e7c045110b8dbf29765047380898919c5cb56f4\": [
        \"test\",
        null,
        {
          \"type\": \"tendermint/PubKeyEd25519\",
          \"value\": \"MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=\"
        },
        {
          \"keypackage\": \"$KEYPACKAGE\"
        }
      ]
    }
  }";

fn init_request() -> RequestInitChain {
    let pub_key =
        TendermintValidatorPubKey::from_base64(b"MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
            .unwrap();

    let validator = ValidatorUpdate {
        pub_key: Some(PubKey {
            field_type: "ed25519".to_owned(),
            data: pub_key.as_bytes().to_vec(),
            ..Default::default()
        })
        .into(),
        power: TendermintVotePower::from(Coin::unit()).into(),
        ..Default::default()
    };
    let t = ::protobuf::well_known_types::Timestamp::new();
    let mut req = RequestInitChain::default();
    req.set_time(t);
    req.set_app_state_bytes(
        TEST_GENESIS
            .replace("$KEYPACKAGE", &base64::encode(KEYPACKAGE_VECTOR))
            .as_bytes()
            .to_vec(),
    );
    req.set_chain_id(String::from(TEST_CHAIN_ID));
    req.set_validators(vec![validator].into());
    req.set_consensus_params(ConsensusParams {
        evidence: Some(EvidenceParams {
            max_age_duration: Some(::protobuf::well_known_types::Duration {
                seconds: 172_800,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    });

    req
}

fn has_valid_consensus_params(req: &RequestInitChain) -> bool {
    req.has_consensus_params()
        && req.get_consensus_params().has_evidence()
        && req
            .get_consensus_params()
            .get_evidence()
            .has_max_age_duration()
}

fuzz_target!(|data: &[u8]| {
    std::env::set_var("CRYPTO_CHAIN_ENABLE_SANITY_CHECKS", "1");
    let stuff: Result<Vec<Vec<u8>>, _> = Vec::decode(&mut data.to_owned().as_slice());

    let mut messages = Vec::<Request>::new();
    if let Ok(msgs) = stuff {
        for msg in msgs.iter() {
            if let Ok(req) = protobuf::parse_from_bytes(&msg) {
                messages.push(req)
            }
        }
        if !messages.is_empty() {
            let defaultinit = (
                init_request(),
                "d413e7e7e1a11e960b2677d0b37060cab71cf6c7e506cfe7ee50221daedc1f6c".to_owned(),
                TEST_CHAIN_ID.to_owned(),
                get_enclave_bridge_mock(),
            );
            let (init, example_hash, chain_id, mock_bridge) = match messages[0].value {
                Some(Request_oneof_value::init_chain(ref req))
                    if has_valid_consensus_params(req) =>
                {
                    match (
                        serde_json::from_slice::<InitConfig>(&req.app_state_bytes),
                        req.time.as_ref(),
                    ) {
                        (Ok(c), Some(t)) => {
                            let result =
                                c.validate_config_get_genesis(t.get_seconds().try_into().unwrap());
                            if let Ok(state) = result {
                                let network_params = NetworkParameters::Genesis(c.network_params);
                                let r = check_validators(
                                    &state.validators,
                                    req.validators.clone().into_vec(),
                                    &c.distribution,
                                );
                                if r.is_err() {
                                    defaultinit
                                } else {
                                    let tx_tree = MerkleTree::empty();
                                    let mut storage = Storage::new_db(create_db());
                                    let new_account_root = storage.put_stakings(0, &state.accounts);

                                    let genesis_app_hash = compute_app_hash(
                                        &tx_tree,
                                        &new_account_root,
                                        &state.rewards_pool,
                                        &network_params,
                                    );
                                    if req.chain_id.len() > 3 {
                                        if let Ok(netid) =
                                            hex::decode(&req.chain_id[req.chain_id.len() - 2..])
                                        {
                                            (
                                                req.clone(),
                                                hex::encode_upper(genesis_app_hash).to_owned(),
                                                req.chain_id.clone(),
                                                MockClient::new(netid[0]),
                                            )
                                        } else {
                                            defaultinit
                                        }
                                    } else {
                                        defaultinit
                                    }
                                }
                            } else {
                                defaultinit
                            }
                        }
                        _ => defaultinit,
                    }
                }

                _ => defaultinit,
            };

            let mut app = ChainNodeApp::new_with_storage(
                mock_bridge,
                &example_hash,
                &chain_id,
                Storage::new_db(create_db()),
                None,
                "".to_string(),
            );
            app.init_chain(&init);
            let mut last_height = 0;
            let mut last_committed_height = 0;

            for msg in messages.iter() {
                match msg.value {
                    // Info
                    Some(Request_oneof_value::info(ref r)) => {
                        app.info(r);
                        ()
                    }
                    // Set option
                    Some(Request_oneof_value::set_option(ref r)) => {
                        app.set_option(r);
                        ()
                    }
                    // Query
                    Some(Request_oneof_value::query(ref r)) => {
                        app.query(r);
                        ()
                    }
                    // Check tx
                    Some(Request_oneof_value::check_tx(ref r)) => {
                        app.check_tx(r);
                        ()
                    }
                    // Begin block
                    Some(Request_oneof_value::begin_block(ref r)) => {
                        if r.has_header()
                            && r.get_header().time.is_some()
                            && r.get_header().height == last_committed_height + 1
                        {
                            app.begin_block(r);
                            last_height = r.get_header().height;
                        }
                    }
                    // Deliver Tx
                    Some(Request_oneof_value::deliver_tx(ref r)) => {
                        app.deliver_tx(r);
                        ()
                    }
                    // End block
                    Some(Request_oneof_value::end_block(ref r)) => {
                        app.end_block(r);
                        ()
                    }
                    // Commit
                    Some(Request_oneof_value::commit(ref r)) => {
                        app.commit(r);
                        last_committed_height = last_height;
                    }
                    _ => {}
                };
            }
        }
    }
});
