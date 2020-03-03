#![no_main]
use abci::Application;
use abci::{Request, RequestInitChain, Request_oneof_value};
use chain_abci::app::*;
use chain_abci::enclave_bridge::mock::MockClient;
use chain_core::common::MerkleTree;
use chain_core::compute_app_hash;
use chain_core::init::config::InitConfig;
use chain_core::init::config::NetworkParameters;
use chain_storage::account::AccountWrapper;
use chain_storage::account::StarlingFixedKey;
use chain_storage::{account::AccountStorage, Storage, NUM_COLUMNS};
use kvdb::KeyValueDB;
use kvdb_memorydb::create;
use libfuzzer_sys::fuzz_target;
use parity_scale_codec::Decode;
use protobuf;
use std::convert::TryInto;
use std::sync::Arc;

pub fn get_enclave_bridge_mock() -> MockClient {
    MockClient::new(0)
}

fn create_db() -> Arc<dyn KeyValueDB> {
    Arc::new(create(NUM_COLUMNS))
}

fn create_account_db() -> AccountStorage {
    AccountStorage::new(Storage::new_db(Arc::new(create(1))), 20).expect("account db")
}

const TEST_CHAIN_ID: &str = "test-00";

fuzz_target!(|data: &[u8]| {
    let stuff: Result<Vec<Vec<u8>>, _> = Vec::decode(&mut data.to_owned().as_slice());
    // TODO: construct InitConfig?
    const INIT_REQ: [u8; 937] = [
        10, 0, 18, 7, 116, 101, 115, 116, 45, 48, 48, 34, 45, 10, 43, 10, 7, 101, 100, 50, 53, 53,
        49, 57, 18, 32, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 42, 236, 6, 123, 34, 100, 105, 115,
        116, 114, 105, 98, 117, 116, 105, 111, 110, 34, 58, 123, 34, 48, 120, 48, 101, 55, 99, 48,
        52, 53, 49, 49, 48, 98, 56, 100, 98, 102, 50, 57, 55, 54, 53, 48, 52, 55, 51, 56, 48, 56,
        57, 56, 57, 49, 57, 99, 53, 99, 98, 53, 54, 102, 52, 34, 58, 91, 34, 66, 111, 110, 100,
        101, 100, 34, 44, 34, 49, 34, 93, 44, 34, 48, 120, 56, 57, 97, 101, 102, 53, 53, 51, 97,
        48, 54, 97, 98, 48, 99, 51, 49, 55, 51, 101, 55, 57, 100, 101, 49, 99, 101, 50, 52, 49, 97,
        57, 101, 100, 51, 98, 57, 57, 50, 99, 34, 58, 91, 34, 85, 110, 98, 111, 110, 100, 101, 100,
        70, 114, 111, 109, 71, 101, 110, 101, 115, 105, 115, 34, 44, 34, 57, 57, 57, 57, 57, 57,
        57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 34, 93, 125, 44, 34, 110, 101, 116,
        119, 111, 114, 107, 95, 112, 97, 114, 97, 109, 115, 34, 58, 123, 34, 105, 110, 105, 116,
        105, 97, 108, 95, 102, 101, 101, 95, 112, 111, 108, 105, 99, 121, 34, 58, 123, 34, 99, 111,
        110, 115, 116, 97, 110, 116, 34, 58, 49, 48, 48, 49, 44, 34, 99, 111, 101, 102, 102, 105,
        99, 105, 101, 110, 116, 34, 58, 49, 48, 48, 49, 125, 44, 34, 114, 101, 113, 117, 105, 114,
        101, 100, 95, 99, 111, 117, 110, 99, 105, 108, 95, 110, 111, 100, 101, 95, 115, 116, 97,
        107, 101, 34, 58, 34, 49, 34, 44, 34, 117, 110, 98, 111, 110, 100, 105, 110, 103, 95, 112,
        101, 114, 105, 111, 100, 34, 58, 56, 54, 52, 48, 48, 44, 34, 106, 97, 105, 108, 105, 110,
        103, 95, 99, 111, 110, 102, 105, 103, 34, 58, 123, 34, 106, 97, 105, 108, 95, 100, 117,
        114, 97, 116, 105, 111, 110, 34, 58, 56, 54, 52, 48, 48, 44, 34, 98, 108, 111, 99, 107, 95,
        115, 105, 103, 110, 105, 110, 103, 95, 119, 105, 110, 100, 111, 119, 34, 58, 49, 48, 48,
        44, 34, 109, 105, 115, 115, 101, 100, 95, 98, 108, 111, 99, 107, 95, 116, 104, 114, 101,
        115, 104, 111, 108, 100, 34, 58, 53, 48, 125, 44, 34, 115, 108, 97, 115, 104, 105, 110,
        103, 95, 99, 111, 110, 102, 105, 103, 34, 58, 123, 34, 108, 105, 118, 101, 110, 101, 115,
        115, 95, 115, 108, 97, 115, 104, 95, 112, 101, 114, 99, 101, 110, 116, 34, 58, 34, 48, 46,
        49, 48, 48, 34, 44, 34, 98, 121, 122, 97, 110, 116, 105, 110, 101, 95, 115, 108, 97, 115,
        104, 95, 112, 101, 114, 99, 101, 110, 116, 34, 58, 34, 48, 46, 50, 48, 48, 34, 44, 34, 115,
        108, 97, 115, 104, 95, 119, 97, 105, 116, 95, 112, 101, 114, 105, 111, 100, 34, 58, 49, 48,
        56, 48, 48, 125, 44, 34, 114, 101, 119, 97, 114, 100, 115, 95, 99, 111, 110, 102, 105, 103,
        34, 58, 123, 34, 109, 111, 110, 101, 116, 97, 114, 121, 95, 101, 120, 112, 97, 110, 115,
        105, 111, 110, 95, 99, 97, 112, 34, 58, 34, 48, 34, 44, 34, 114, 101, 119, 97, 114, 100,
        95, 112, 101, 114, 105, 111, 100, 95, 115, 101, 99, 111, 110, 100, 115, 34, 58, 56, 54, 52,
        48, 48, 44, 34, 109, 111, 110, 101, 116, 97, 114, 121, 95, 101, 120, 112, 97, 110, 115,
        105, 111, 110, 95, 114, 48, 34, 58, 53, 48, 48, 44, 34, 109, 111, 110, 101, 116, 97, 114,
        121, 95, 101, 120, 112, 97, 110, 115, 105, 111, 110, 95, 116, 97, 117, 34, 58, 49, 54, 54,
        54, 54, 54, 54, 48, 48, 44, 34, 109, 111, 110, 101, 116, 97, 114, 121, 95, 101, 120, 112,
        97, 110, 115, 105, 111, 110, 95, 100, 101, 99, 97, 121, 34, 58, 57, 57, 57, 56, 54, 48,
        125, 44, 34, 109, 97, 120, 95, 118, 97, 108, 105, 100, 97, 116, 111, 114, 115, 34, 58, 50,
        125, 44, 34, 99, 111, 117, 110, 99, 105, 108, 95, 110, 111, 100, 101, 115, 34, 58, 123, 34,
        48, 120, 48, 101, 55, 99, 48, 52, 53, 49, 49, 48, 98, 56, 100, 98, 102, 50, 57, 55, 54, 53,
        48, 52, 55, 51, 56, 48, 56, 57, 56, 57, 49, 57, 99, 53, 99, 98, 53, 54, 102, 52, 34, 58,
        91, 34, 116, 101, 115, 116, 34, 44, 110, 117, 108, 108, 44, 123, 34, 116, 121, 112, 101,
        34, 58, 34, 116, 101, 110, 100, 101, 114, 109, 105, 110, 116, 47, 80, 117, 98, 75, 101,
        121, 69, 100, 50, 53, 53, 49, 57, 34, 44, 34, 118, 97, 108, 117, 101, 34, 58, 34, 77, 68,
        65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65,
        119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 119, 77, 68, 65, 61,
        34, 125, 93, 125, 125,
    ];

    let mut messages = Vec::<Request>::new();
    if let Ok(msgs) = stuff {
        for msg in msgs.iter() {
            if let Ok(req) = protobuf::parse_from_bytes(&msg) {
                messages.push(req)
            }
        }
        if !messages.is_empty() {
            let defaultinit = (
                protobuf::parse_from_bytes(&INIT_REQ[..]).unwrap(),
                "0512AD829B78F1395E6DFFAEA4005B0AD356C5CCD4BC97D4B461B21FFBFBECE4".to_owned(),
            );
            let (init, example_hash): (RequestInitChain, String) = match messages[0].value {
                Some(Request_oneof_value::init_chain(ref req)) => {
                    match (
                        serde_json::from_slice::<InitConfig>(&req.app_state_bytes),
                        req.time.as_ref(),
                    ) {
                        (Ok(c), Some(t)) => {
                            let result =
                                c.validate_config_get_genesis(t.get_seconds().try_into().unwrap());
                            if let Ok((accounts, rp, _)) = result {
                                let tx_tree = MerkleTree::empty();
                                let mut account_tree =
                                    AccountStorage::new(Storage::new_db(Arc::new(create(1))), 20)
                                        .expect("account db");
                                let wrapped: Vec<AccountWrapper> =
                                        accounts.iter().map(|x| AccountWrapper(x.clone())).collect();
                                let mut keys: Vec<StarlingFixedKey> =
                                    accounts.iter().map(|x| x.key()).collect();
                                let new_account_root = account_tree
                                    .insert(None, &mut keys, &wrapped)
                                    .expect("initial insert");

                                let genesis_app_hash = compute_app_hash(
                                    &tx_tree,
                                    &new_account_root,
                                    &rp,
                                    &NetworkParameters::Genesis(c.network_params),
                                );

                                (req.clone(), hex::encode_upper(genesis_app_hash).to_owned())
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
                get_enclave_bridge_mock(),
                &example_hash,
                TEST_CHAIN_ID,
                Storage::new_db(create_db()),
                create_account_db(),
                None,
                None,
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
