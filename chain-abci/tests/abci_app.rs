use abci::Application;
use abci::*;
use bit_vec::BitVec;
use chain_abci::app::*;
use chain_abci::enclave_bridge::mock::MockClient;
use chain_abci::storage::account::AccountStorage;
use chain_abci::storage::account::AccountWrapper;
use chain_abci::storage::tx::StarlingFixedKey;
use chain_abci::storage::*;
use chain_core::common::{MerkleTree, Proof, H256, HASH_SIZE_256};
use chain_core::compute_app_hash;
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::init::config::InitConfig;
use chain_core::init::config::InitNetworkParameters;
use chain_core::init::config::StakedStateDestination;
use chain_core::init::config::{
    JailingParameters, SlashRatio, SlashingParameters, ValidatorKeyType, ValidatorPubkey,
};
use chain_core::state::account::{
    to_stake_key, DepositBondTx, StakedState, StakedStateAddress, StakedStateOpAttributes,
    StakedStateOpWitness, UnbondTx, WithdrawUnbondedTx,
};
use chain_core::state::tendermint::TendermintVotePower;
use chain_core::state::RewardsPoolState;
use chain_core::tx::fee::{LinearFee, Milli};
use chain_core::tx::witness::tree::RawPubkey;
use chain_core::tx::witness::EcdsaSignature;
use chain_core::tx::PlainTxAux;
use chain_core::tx::TransactionId;
use chain_core::tx::TxObfuscated;
use chain_core::tx::{
    data::{
        access::{TxAccess, TxAccessPolicy},
        address::ExtendedAddr,
        attribute::TxAttributes,
        input::{TxoIndex, TxoPointer},
        output::TxOut,
        txid_hash, Tx, TxId,
    },
    witness::{TxInWitness, TxWitness},
    TxAux, TxEnclaveAux,
};
use chain_tx_filter::BlockFilter;
use chain_tx_validation::TxWithOutputs;
use hex::decode;
use kvdb::KeyValueDB;
use kvdb_memorydb::create;
use parity_scale_codec::{Decode, Encode};
use secp256k1::schnorrsig::schnorr_sign;
use secp256k1::{key::PublicKey, key::SecretKey, Message, Secp256k1, Signing};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Arc;

fn get_enclave_bridge_mock() -> MockClient {
    MockClient::new(0)
}

pub fn get_ecdsa_witness<C: Signing>(
    secp: &Secp256k1<C>,
    txid: &TxId,
    secret_key: &SecretKey,
) -> EcdsaSignature {
    let message = Message::from_slice(&txid[..]).expect("32 bytes");
    let sig = secp.sign_recoverable(&message, &secret_key);
    return sig;
}

fn create_db() -> Arc<dyn KeyValueDB> {
    Arc::new(create(NUM_COLUMNS.unwrap()))
}

fn create_account_db() -> AccountStorage {
    AccountStorage::new(Storage::new_db(Arc::new(create(1))), 20).expect("account db")
}

const TEST_CHAIN_ID: &str = "test-00";

#[test]
fn proper_hash_and_chainid_should_be_stored() {
    let db = create_db();
    let example_hash = "F5E8DFBF717082D6E9508E1A5A5C9B8EAC04A39F69C40262CB733C920DA10962";
    let _app = ChainNodeApp::new_with_storage(
        get_enclave_bridge_mock(),
        example_hash,
        TEST_CHAIN_ID,
        Storage::new_db(db.clone()),
        create_account_db(),
    );
    let decoded_gah = decode(example_hash).unwrap();
    let stored_gah = db
        .get(COL_NODE_INFO, GENESIS_APP_HASH_KEY)
        .unwrap()
        .unwrap();
    let mut stored_genesis = [0u8; HASH_SIZE_256];
    stored_genesis.copy_from_slice(&stored_gah[..]);
    assert_eq!(decoded_gah, stored_genesis);
    let chain_id = db.get(COL_EXTRA, CHAIN_ID_KEY).unwrap().unwrap();
    assert_eq!(chain_id, TEST_CHAIN_ID.as_bytes());
}

#[test]
#[should_panic]
fn too_long_hash_should_panic() {
    let db = create_db();
    let example_hash = "F5E8DFBF717082D6E9508E1A5A5C9B8EAC04A39F69C40262CB733C920DA10962F5E8DFBF717082D6E9508E1A5A5C9B8EAC04A39F69C40262CB733C920DA10962";
    let _app = ChainNodeApp::new_with_storage(
        get_enclave_bridge_mock(),
        example_hash,
        TEST_CHAIN_ID,
        Storage::new_db(db.clone()),
        create_account_db(),
    );
}

#[test]
#[should_panic]
fn chain_id_without_hex_digits_should_panic() {
    let db = create_db();
    let example_hash = "F5E8DFBF717082D6E9508E1A5A5C9B8EAC04A39F69C40262CB733C920DA10962";
    let _app = ChainNodeApp::new_with_storage(
        get_enclave_bridge_mock(),
        example_hash,
        "test",
        Storage::new_db(db.clone()),
        create_account_db(),
    );
}

#[test]
#[should_panic]
fn nonhex_hash_should_panic() {
    let db = create_db();
    let example_hash = "EOWNEOIWFNOPXZ./32";
    let _app = ChainNodeApp::new_with_storage(
        get_enclave_bridge_mock(),
        example_hash,
        TEST_CHAIN_ID,
        Storage::new_db(db.clone()),
        create_account_db(),
    );
}

fn get_dummy_app_state(app_hash: H256) -> ChainNodeState {
    ChainNodeState {
        last_block_height: 0,
        last_apphash: app_hash,
        block_time: 0,
        rewards_pool: RewardsPoolState::new(1.into(), 0),
        fee_policy: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1)),
        last_account_root_hash: [0u8; 32],
        council_nodes: vec![],
        required_council_node_stake: Coin::unit(),
        unbonding_period: 1,
        jailing_config: JailingParameters {
            jail_duration: 86400,
            block_signing_window: 100,
            missed_block_threshold: 50,
        },
        slashing_config: SlashingParameters {
            liveness_slash_percent: SlashRatio::from_str("0.1").unwrap(),
            byzantine_slash_percent: SlashRatio::from_str("0.2").unwrap(),
            slash_wait_period: 10800,
        },
        punishment: Default::default(),
    }
}

#[test]
#[should_panic]
fn previously_stored_hash_should_match() {
    let db = create_db();
    let example_hash = "F5E8DFBF717082D6E9508E1A5A5C9B8EAC04A39F69C40262CB733C920DA10962";
    let decoded_gah = decode(example_hash).unwrap();
    let mut genesis_app_hash = [0u8; HASH_SIZE_256];
    genesis_app_hash.copy_from_slice(&decoded_gah[..]);
    let mut inittx = db.transaction();
    inittx.put(COL_NODE_INFO, GENESIS_APP_HASH_KEY, &genesis_app_hash);
    inittx.put(
        COL_NODE_INFO,
        LAST_STATE_KEY,
        &get_dummy_app_state(genesis_app_hash).encode(),
    );
    db.write(inittx).unwrap();
    let example_hash2 = "F5E8DFBF717082D6E9508E1A5A5C9B8EAC04A39F69C40262CB733C920DA10963";
    let _app = ChainNodeApp::new_with_storage(
        get_enclave_bridge_mock(),
        example_hash2,
        TEST_CHAIN_ID,
        Storage::new_db(db.clone()),
        create_account_db(),
    );
}

fn init_chain_for(address: RedeemAddress) -> ChainNodeApp<MockClient> {
    let db = create_db();
    let rewards_pool = Coin::zero();
    let total = (Coin::max() - Coin::unit()).unwrap();
    let validator_addr = "0x0e7c045110b8dbf29765047380898919c5cb56f4"
        .parse::<RedeemAddress>()
        .unwrap();

    let distribution = [
        (
            address,
            (StakedStateDestination::UnbondedFromGenesis, total),
        ),
        (
            validator_addr,
            (StakedStateDestination::Bonded, Coin::unit()),
        ),
    ]
    .iter()
    .cloned()
    .collect();
    let params = InitNetworkParameters {
        initial_fee_policy: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1)),
        required_council_node_stake: Coin::unit(),
        unbonding_period: 1,
        jailing_config: JailingParameters {
            jail_duration: 86400,
            block_signing_window: 100,
            missed_block_threshold: 50,
        },
        slashing_config: SlashingParameters {
            liveness_slash_percent: SlashRatio::from_str("0.1").unwrap(),
            byzantine_slash_percent: SlashRatio::from_str("0.2").unwrap(),
            slash_wait_period: 10800,
        },
    };
    let mut nodes = BTreeMap::new();
    let node_pubkey = ValidatorPubkey {
        consensus_pubkey_type: ValidatorKeyType::Ed25519,
        consensus_pubkey_b64: "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=".to_string(),
    };
    nodes.insert(validator_addr, node_pubkey);
    let c = InitConfig::new(rewards_pool, distribution, params, nodes);
    let t = ::protobuf::well_known_types::Timestamp::new();
    let result = c.validate_config_get_genesis(t.get_seconds());
    if let Ok((accounts, rp, _nodes)) = result {
        let tx_tree = MerkleTree::empty();
        let mut account_tree =
            AccountStorage::new(Storage::new_db(Arc::new(create(1))), 20).expect("account db");

        let mut keys: Vec<StarlingFixedKey> = accounts.iter().map(|x| x.key()).collect();
        // TODO: get rid of the extra allocations
        let mut wrapped: Vec<AccountWrapper> =
            accounts.iter().map(|x| AccountWrapper(x.clone())).collect();
        let new_account_root = account_tree
            .insert(None, &mut keys, &mut wrapped)
            .expect("initial insert");

        let genesis_app_hash = compute_app_hash(&tx_tree, &new_account_root, &rp);

        let example_hash = hex::encode_upper(genesis_app_hash);
        let mut app = ChainNodeApp::new_with_storage(
            get_enclave_bridge_mock(),
            &example_hash,
            TEST_CHAIN_ID,
            Storage::new_db(db.clone()),
            create_account_db(),
        );
        let mut req = RequestInitChain::default();
        req.set_time(t);
        req.set_app_state_bytes(serde_json::to_vec(&c).unwrap());
        req.set_chain_id(String::from(TEST_CHAIN_ID));
        app.init_chain(&req);
        app
    } else {
        panic!("distribution validation error: {}", result.err().unwrap());
    }
}

#[test]
fn init_chain_should_create_db_items() {
    let address = "0xfe7c045110b8dbf29765047380898919c5cb56f9"
        .parse()
        .unwrap();
    let app = init_chain_for(address);
    let genesis_app_hash = app.genesis_app_hash;
    let db = app.storage.db;
    let state = ChainNodeState::decode(
        &mut db
            .get(COL_NODE_INFO, LAST_STATE_KEY)
            .unwrap()
            .unwrap()
            .to_vec()
            .as_slice(),
    )
    .unwrap();

    assert_eq!(genesis_app_hash, state.last_apphash);
    let key = to_stake_key(&address.into());
    assert_eq!(
        1,
        app.accounts
            .get(&state.last_account_root_hash, &mut [key])
            .expect("account")
            .iter()
            .count()
    );
}

#[test]
#[should_panic]
fn init_chain_panics_with_different_app_hash() {
    let db = create_db();
    let rewards_pool = Coin::zero();
    let distribution = [(
        "0x0e7c045110b8dbf29765047380898919c5cb56f4"
            .parse()
            .unwrap(),
        (StakedStateDestination::Bonded, Coin::max()),
    )]
    .iter()
    .cloned()
    .collect();
    let params = InitNetworkParameters {
        initial_fee_policy: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1)),
        required_council_node_stake: Coin::unit(),
        unbonding_period: 1,
        jailing_config: JailingParameters {
            jail_duration: 86400,
            block_signing_window: 100,
            missed_block_threshold: 50,
        },
        slashing_config: SlashingParameters {
            liveness_slash_percent: SlashRatio::from_str("0.1").unwrap(),
            byzantine_slash_percent: SlashRatio::from_str("0.2").unwrap(),
            slash_wait_period: 10800,
        },
    };
    let c = InitConfig::new(rewards_pool, distribution, params, BTreeMap::new());

    let example_hash = "F5E8DFBF717082D6E9508E1A5A5C9B8EAC04A39F69C40262CB733C920DA10963";
    let mut app = ChainNodeApp::new_with_storage(
        get_enclave_bridge_mock(),
        &example_hash,
        TEST_CHAIN_ID,
        Storage::new_db(db.clone()),
        create_account_db(),
    );
    let mut req = RequestInitChain::default();
    req.set_app_state_bytes(serde_json::to_vec(&c).unwrap());
    req.set_time(::protobuf::well_known_types::Timestamp::new());
    req.set_chain_id(String::from(TEST_CHAIN_ID));
    app.init_chain(&req);
}

#[test]
#[should_panic]
fn init_chain_panics_with_empty_app_bytes() {
    let db = create_db();
    let example_hash = "F5E8DFBF717082D6E9508E1A5A5C9B8EAC04A39F69C40262CB733C920DA10963";
    let mut app = ChainNodeApp::new_with_storage(
        get_enclave_bridge_mock(),
        &example_hash,
        TEST_CHAIN_ID,
        Storage::new_db(db.clone()),
        create_account_db(),
    );
    let req = RequestInitChain::default();
    app.init_chain(&req);
}

#[test]
fn check_tx_should_reject_empty_tx() {
    let mut app = init_chain_for(
        "0xfe7c045110b8dbf29765047380898919c5cb56f9"
            .parse()
            .unwrap(),
    );
    let creq = RequestCheckTx::default();
    let cresp = app.check_tx(&creq);
    assert_ne!(0, cresp.code);
}

#[test]
fn check_tx_should_reject_invalid_tx() {
    let mut app = init_chain_for(
        "0xfe7c045110b8dbf29765047380898919c5cb56f9"
            .parse()
            .unwrap(),
    );
    let mut creq = RequestCheckTx::default();
    let tx = PlainTxAux::new(Tx::new(), TxWitness::new());
    creq.set_tx(tx.encode());
    let cresp = app.check_tx(&creq);
    assert_ne!(0, cresp.code);
}

fn prepare_app_valid_tx() -> (ChainNodeApp<MockClient>, TxAux, WithdrawUnbondedTx) {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let addr = RedeemAddress::from(&public_key);
    let app = init_chain_for(addr);

    let tx = WithdrawUnbondedTx::new(
        0,
        vec![
            TxOut::new_with_timelock(ExtendedAddr::OrTree([0; 32]), Coin::one(), 0),
            TxOut::new_with_timelock(ExtendedAddr::OrTree([1; 32]), Coin::unit(), 0),
        ],
        TxAttributes::new_with_access(0, vec![TxAccessPolicy::new(public_key, TxAccess::AllData)]),
    );

    let witness = StakedStateOpWitness::new(get_ecdsa_witness(&secp, &tx.id(), &secret_key));
    // TODO: mock enc
    let txaux = TxAux::EnclaveTx(TxEnclaveAux::WithdrawUnbondedStakeTx {
        no_of_outputs: tx.outputs.len() as TxoIndex,
        witness: witness.clone(),
        payload: TxObfuscated {
            txid: tx.id(),
            key_from: 0,
            init_vector: [0; 12],
            txpayload: PlainTxAux::WithdrawUnbondedStakeTx(tx.clone()).encode(),
        },
    });
    (app, txaux, tx)
}

#[test]
fn check_tx_should_accept_valid_tx() {
    let (mut app, txaux, _) = prepare_app_valid_tx();
    let mut creq = RequestCheckTx::default();
    creq.set_tx(txaux.encode());
    let cresp = app.check_tx(&creq);
    assert_eq!(0, cresp.code);
}

#[test]
#[should_panic]
fn two_beginblocks_should_panic() {
    let mut app = init_chain_for(
        "0x0e7c045110b8dbf29765047380898919c5cb56f4"
            .parse()
            .unwrap(),
    );
    let bbreq = RequestBeginBlock::default();
    app.begin_block(&bbreq);
    app.begin_block(&bbreq);
}

fn begin_block(app: &mut ChainNodeApp<MockClient>) {
    let mut bbreq = RequestBeginBlock::default();
    let mut header = Header::default();
    header.set_time(::protobuf::well_known_types::Timestamp::new());
    bbreq.set_header(header);
    app.begin_block(&bbreq);
}

#[test]
fn deliver_tx_should_reject_empty_tx() {
    let mut app = init_chain_for(
        "0xfe7c045110b8dbf29765047380898919c5cb56f9"
            .parse()
            .unwrap(),
    );
    assert_eq!(0, app.delivered_txs.len());
    begin_block(&mut app);
    let creq = RequestDeliverTx::default();
    let cresp = app.deliver_tx(&creq);
    assert_ne!(0, cresp.code);
    assert_eq!(0, app.delivered_txs.len());
    assert_eq!(0, cresp.events.len());
}

#[test]
fn deliver_tx_should_reject_invalid_tx() {
    let mut app = init_chain_for(
        "0xfe7c045110b8dbf29765047380898919c5cb56f9"
            .parse()
            .unwrap(),
    );
    assert_eq!(0, app.delivered_txs.len());
    begin_block(&mut app);
    let mut creq = RequestDeliverTx::default();
    let tx = PlainTxAux::new(Tx::new(), TxWitness::new());
    creq.set_tx(tx.encode());
    let cresp = app.deliver_tx(&creq);
    assert_ne!(0, cresp.code);
    assert_eq!(0, app.delivered_txs.len());
    assert_eq!(0, cresp.events.len());
}

fn deliver_valid_tx() -> (
    ChainNodeApp<MockClient>,
    WithdrawUnbondedTx,
    StakedStateOpWitness,
    ResponseDeliverTx,
) {
    let (mut app, txaux, tx) = prepare_app_valid_tx();
    let rewards_pool_remaining_old = app.last_state.as_ref().unwrap().rewards_pool.remaining;
    assert_eq!(0, app.delivered_txs.len());
    begin_block(&mut app);
    let mut creq = RequestDeliverTx::default();
    creq.set_tx(txaux.encode());
    let cresp = app.deliver_tx(&creq);
    let rewards_pool_remaining_new = app.last_state.as_ref().unwrap().rewards_pool.remaining;
    assert!(rewards_pool_remaining_new > rewards_pool_remaining_old);
    match txaux {
        TxAux::EnclaveTx(TxEnclaveAux::WithdrawUnbondedStakeTx { witness, .. }) => {
            (app, tx, witness, cresp)
        }
        _ => unreachable!("prepare_app_valid_tx should prepare stake withdrawal tx"),
    }
}

#[test]
fn deliver_tx_should_add_valid_tx() {
    let (app, tx, _, cresp) = deliver_valid_tx();
    assert_eq!(0, cresp.code);
    assert_eq!(1, app.delivered_txs.len());
    assert_eq!(1, cresp.events.len());
    assert_eq!(3, cresp.events[0].attributes.len());
    // the unit test transaction just has two outputs: 1 CRO + 1 carson / base unit, the rest goes to a fee
    assert_eq!(
        &b"99999999998.99999998".to_vec(),
        &cresp.events[0].attributes[0].value
    );
    assert_eq!(
        &b"0x89aef553a06ab0c3173e79de1ce241a9ed3b992c".to_vec(),
        &cresp.events[0].attributes[1].value
    );
    assert_eq!(
        &hex::encode(&tx.id()).as_bytes().to_vec(),
        &cresp.events[0].attributes[2].value
    );
}

#[test]
#[should_panic]
#[ignore]
fn delivertx_without_beginblocks_should_panic() {
    // TODO: sanity checks in abci https://github.com/tendermint/rust-abci/issues/49
    let mut app = init_chain_for(
        "0x0e7c045110b8dbf29765047380898919c5cb56f4"
            .parse()
            .unwrap(),
    );
    let creq = RequestDeliverTx::default();
    app.deliver_tx(&creq);
}

#[test]
#[should_panic]
#[ignore]
fn endblock_without_beginblocks_should_panic() {
    // TODO: sanity checks in abci https://github.com/tendermint/rust-abci/issues/49
    let mut app = init_chain_for(
        "0x0e7c045110b8dbf29765047380898919c5cb56f4"
            .parse()
            .unwrap(),
    );
    let creq = RequestEndBlock::default();
    let _cresp = app.end_block(&creq);
}

#[test]
fn endblock_should_change_block_height() {
    let mut app = init_chain_for(
        "0xfe7c045110b8dbf29765047380898919c5cb56f9"
            .parse()
            .unwrap(),
    );
    begin_block(&mut app);
    let mut creq = RequestEndBlock::default();
    creq.set_height(10);
    assert_ne!(
        10,
        i64::from(app.last_state.as_ref().unwrap().last_block_height)
    );
    let cresp = app.end_block(&creq);
    assert_eq!(
        10,
        i64::from(app.last_state.as_ref().unwrap().last_block_height)
    );
    assert_eq!(0, cresp.events.len());
}

#[test]
#[should_panic]
#[ignore]
fn commit_without_beginblocks_should_panic() {
    // TODO: sanity checks in abci https://github.com/tendermint/rust-abci/issues/49
    let mut app = init_chain_for(
        "crms1le7qg5gshrdl99m9q3ecpzvfr8zuk4heu7q420"
            .parse()
            .unwrap(),
    );
    let creq = RequestCommit::default();
    let _cresp = app.commit(&creq);
}

#[test]
fn valid_commit_should_persist() {
    let (mut app, tx, _, _) = deliver_valid_tx();

    let old_app_hash = app.last_state.as_ref().unwrap().last_apphash;
    let mut endreq = RequestEndBlock::default();
    endreq.set_height(10);
    let cresp = app.end_block(&endreq);
    assert_eq!(1, cresp.events.len());
    assert_eq!(1, cresp.events[0].attributes.len());
    assert_eq!(1, app.delivered_txs.len());
    let filter = BlockFilter::try_from(cresp.events[0].attributes[0].value.as_slice())
        .expect("there should be a block filter");

    assert!(filter.check_view_key(&tx.attributes.allowed_view[0].view_key));
    let sample = PublicKey::from_slice(&[
        3, 23, 183, 225, 206, 31, 159, 148, 195, 42, 67, 115, 146, 41, 248, 140, 11, 3, 51, 41,
        111, 180, 110, 143, 114, 134, 88, 73, 198, 174, 52, 184, 78,
    ])
    .expect("sample pk");
    assert!(!filter.check_view_key(&sample));

    assert!(app
        .storage
        .db
        .get(COL_BODIES, &tx.id()[..])
        .unwrap()
        .is_none());
    assert!(app
        .storage
        .db
        .get(COL_WITNESS, &tx.id()[..])
        .unwrap()
        .is_none());
    let persisted_state = ChainNodeState::decode(
        &mut app
            .storage
            .db
            .get(COL_NODE_INFO, LAST_STATE_KEY)
            .unwrap()
            .unwrap()
            .to_vec()
            .as_slice(),
    )
    .unwrap();
    assert_ne!(10, i64::from(persisted_state.last_block_height));
    assert_ne!(
        10,
        i64::from(persisted_state.rewards_pool.last_block_height)
    );
    let cresp = app.commit(&RequestCommit::default());
    assert_eq!(0, app.delivered_txs.len());
    assert!(app
        .storage
        .db
        .get(COL_BODIES, &tx.id()[..])
        .unwrap()
        .is_some());
    assert!(app
        .storage
        .db
        .get(COL_WITNESS, &tx.id()[..])
        .unwrap()
        .is_some());
    assert_eq!(
        10,
        i64::from(app.last_state.as_ref().unwrap().last_block_height)
    );
    assert_eq!(
        10,
        i64::from(
            app.last_state
                .as_ref()
                .unwrap()
                .rewards_pool
                .last_block_height
        )
    );
    assert_ne!(old_app_hash, app.last_state.as_ref().unwrap().last_apphash);
    assert_eq!(
        &app.last_state.as_ref().unwrap().last_apphash[..],
        &cresp.data[..]
    );
    assert!(app
        .storage
        .db
        .get(COL_MERKLE_PROOFS, &cresp.data[..])
        .unwrap()
        .is_some());
    // TODO: check account
    let new_utxos = BitVec::from_bytes(
        &app.storage
            .db
            .get(COL_TX_META, &tx.id()[..])
            .unwrap()
            .unwrap()
            .to_vec(),
    );
    assert!(!new_utxos.any());
}

#[test]
fn no_delivered_tx_commit_should_keep_apphash() {
    let mut app = init_chain_for(
        "0xfe7c045110b8dbf29765047380898919c5cb56f9"
            .parse()
            .unwrap(),
    );
    let old_app_hash = app.genesis_app_hash;
    begin_block(&mut app);
    app.end_block(&RequestEndBlock::default());
    let cresp = app.commit(&RequestCommit::default());
    assert_eq!(old_app_hash, app.last_state.as_ref().unwrap().last_apphash);
    assert_eq!(&old_app_hash[..], &cresp.data[..]);
}

#[test]
fn query_should_return_an_account() {
    let addr = "fe7c045110b8dbf29765047380898919c5cb56f9";
    let mut app = init_chain_for(addr.parse().unwrap());
    let mut qreq = RequestQuery::new();
    qreq.data = hex::decode(&addr).unwrap();
    qreq.path = "account".into();
    let qresp = app.query(&qreq);
    let account = StakedState::decode(&mut qresp.value.as_slice());
    assert!(account.is_ok());
}

#[test]
fn query_should_return_proof_for_committed_tx() {
    let (mut app, tx, witness, _) = deliver_valid_tx();
    let mut endreq = RequestEndBlock::default();
    endreq.set_height(10);
    app.end_block(&endreq);
    let cresp = app.commit(&RequestCommit::default());
    let mut qreq = RequestQuery::new();
    qreq.data = tx.id().to_vec();
    qreq.path = "store".into();
    qreq.prove = true;
    let qresp = app.query(&qreq);
    let returned_tx = TxWithOutputs::decode(&mut qresp.value.as_slice()).unwrap();
    match returned_tx {
        TxWithOutputs::StakeWithdraw(stx) => {
            assert_eq!(tx, stx);
        }
        _ => panic!("expected stake withdrawal to be returned to a query"),
    }

    let proof = qresp.proof.unwrap();

    assert_eq!(proof.ops.len(), 2);

    let mut transaction_root_hash = [0u8; 32];
    transaction_root_hash.copy_from_slice(proof.ops[0].key.as_slice());

    let mut transaction_proof_data = proof.ops[0].data.as_slice();
    let transaction_proof = <Proof<H256>>::decode(&mut transaction_proof_data).unwrap();

    assert!(transaction_proof.verify(&transaction_root_hash));

    let rewards_pool_part = app.last_state.clone().unwrap().rewards_pool.hash();
    let mut bs = Vec::new();
    bs.extend(transaction_root_hash.to_vec());
    bs.extend(&app.last_state.clone().unwrap().last_account_root_hash[..]);
    bs.extend(&rewards_pool_part);

    assert_eq!(txid_hash(&bs).to_vec(), cresp.data);
    let mut qreq2 = RequestQuery::new();
    qreq2.data = tx.id().to_vec();
    qreq2.path = "witness".into();
    let qresp = app.query(&qreq2);
    assert_eq!(qresp.value, witness.encode());
    assert_eq!(proof.ops[1].data, txid_hash(&qresp.value));
}

fn block_commit(app: &mut ChainNodeApp<MockClient>, tx: TxAux, block_height: i64) {
    let mut creq = RequestCheckTx::default();
    creq.set_tx(tx.encode());
    println!("checktx: {:?}", app.check_tx(&creq));
    println!("beginblock: {:?}", begin_block(app));
    let mut dreq = RequestDeliverTx::default();
    dreq.set_tx(tx.encode());
    println!("delivertx: {:?}", app.deliver_tx(&dreq));
    let mut breq = RequestEndBlock::default();
    breq.set_height(block_height);
    println!("endblock: {:?}", app.end_block(&breq));
    println!("commit: {:?}", app.commit(&RequestCommit::default()));
}

fn get_account(account_address: &RedeemAddress, app: &ChainNodeApp<MockClient>) -> StakedState {
    println!(
        "uncommitted root hash: {}",
        hex::encode(app.uncommitted_account_root_hash)
    );
    let account_key = to_stake_key(&StakedStateAddress::from(*account_address));
    let state = app.last_state.clone().expect("app state");
    println!(
        "committed root hash: {}",
        hex::encode(&state.last_account_root_hash)
    );
    let account = app
        .accounts
        .get_one(&app.uncommitted_account_root_hash, &account_key)
        .expect("account lookup problem");

    match account {
        None => panic!("account not found"),
        Some(AccountWrapper(a)) => a,
    }
}

fn get_tx_meta(txid: &TxId, app: &ChainNodeApp<MockClient>) -> BitVec {
    BitVec::from_bytes(&app.storage.db.get(COL_TX_META, &txid[..]).unwrap().unwrap())
}

#[test]
fn all_valid_tx_types_should_commit() {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let addr = RedeemAddress::from(&public_key);
    let mut app = init_chain_for(addr);

    let merkle_tree = MerkleTree::new(vec![RawPubkey::from(public_key.serialize())]);

    let eaddr = ExtendedAddr::OrTree(merkle_tree.root_hash());
    let tx0 = WithdrawUnbondedTx::new(
        0,
        vec![
            TxOut::new_with_timelock(eaddr.clone(), Coin::one(), 0),
            TxOut::new_with_timelock(eaddr.clone(), Coin::one(), 0),
        ],
        TxAttributes::new_with_access(
            0,
            vec![TxAccessPolicy::new(public_key.clone(), TxAccess::AllData)],
        ),
    );
    let txid = &tx0.id();
    let witness0 = StakedStateOpWitness::new(get_ecdsa_witness(&secp, &txid, &secret_key));
    let withdrawtx = TxAux::EnclaveTx(TxEnclaveAux::WithdrawUnbondedStakeTx {
        no_of_outputs: tx0.outputs.len() as TxoIndex,
        witness: witness0,
        payload: TxObfuscated {
            txid: tx0.id(),
            key_from: 0,
            init_vector: [0u8; 12],
            txpayload: PlainTxAux::WithdrawUnbondedStakeTx(tx0).encode(),
        },
    });
    {
        let account = get_account(&addr, &app);
        // TODO: more precise amount assertions
        assert!(account.unbonded > Coin::zero());
        assert_eq!(account.nonce, 0);
    }
    block_commit(&mut app, withdrawtx, 1);
    {
        let account = get_account(&addr, &app);
        assert_eq!(account.unbonded, Coin::zero());
        assert_eq!(account.nonce, 1);
        let spend_utxos = get_tx_meta(&txid, &app);
        assert!(!spend_utxos.any());
    }
    let halfcoin = Coin::from(5000_0000u32);
    let utxo1 = TxoPointer::new(*txid, 0);
    let mut tx1 = Tx::new();
    tx1.add_input(utxo1);
    tx1.add_output(TxOut::new(eaddr.clone(), halfcoin));
    let txid1 = tx1.id();
    let witness1 = vec![TxInWitness::TreeSig(
        schnorr_sign(&secp, &Message::from_slice(&txid1).unwrap(), &secret_key).0,
        merkle_tree
            .generate_proof(RawPubkey::from(public_key.serialize()))
            .unwrap(),
    )]
    .into();
    let plain_txaux = PlainTxAux::TransferTx(tx1.clone(), witness1);
    let transfertx = TxAux::EnclaveTx(TxEnclaveAux::TransferTx {
        inputs: tx1.inputs.clone(),
        no_of_outputs: tx1.outputs.len() as TxoIndex,
        payload: TxObfuscated {
            txid: tx1.id(),
            key_from: 0,
            init_vector: [0u8; 12],
            txpayload: plain_txaux.encode(),
        },
    });
    {
        let spent_utxos = get_tx_meta(&txid, &app);
        assert!(!spent_utxos.any());
    }
    block_commit(&mut app, transfertx, 2);
    {
        let spent_utxos0 = get_tx_meta(&txid, &app);
        assert!(spent_utxos0[0] && !spent_utxos0[1]);
        let spent_utxos1 = get_tx_meta(&txid1, &app);
        assert!(!spent_utxos1.any());
    }
    let utxo2 = TxoPointer::new(*txid, 1);
    let tx2 = DepositBondTx::new(vec![utxo2], addr.into(), StakedStateOpAttributes::new(0));
    let witness2 = vec![TxInWitness::TreeSig(
        schnorr_sign(&secp, &Message::from_slice(&tx2.id()).unwrap(), &secret_key).0,
        merkle_tree
            .generate_proof(RawPubkey::from(public_key.serialize()))
            .unwrap(),
    )]
    .into();
    let depositx = TxAux::EnclaveTx(TxEnclaveAux::DepositStakeTx {
        tx: tx2.clone(),
        payload: TxObfuscated {
            txid: tx2.id(),
            key_from: 0,
            init_vector: [0u8; 12],
            txpayload: PlainTxAux::DepositStakeTx(witness2).encode(),
        },
    });
    {
        let spent_utxos0 = get_tx_meta(&txid, &app);
        assert!(spent_utxos0[0] && !spent_utxos0[1]);
        let account = get_account(&addr, &app);
        assert_eq!(account.bonded, Coin::zero());
        assert_eq!(account.nonce, 1);
    }
    block_commit(&mut app, depositx, 3);
    {
        let spent_utxos0 = get_tx_meta(&txid, &app);
        assert!(spent_utxos0[0] && spent_utxos0[1]);
        let account = get_account(&addr, &app);
        // TODO: more precise amount assertions
        assert!(account.bonded > Coin::zero());
        assert_eq!(account.nonce, 2);
    }

    let tx3 = UnbondTx::new(addr.into(), 2, halfcoin, StakedStateOpAttributes::new(0));
    let witness3 = StakedStateOpWitness::new(get_ecdsa_witness(&secp, &tx3.id(), &secret_key));
    let unbondtx = TxAux::UnbondStakeTx(tx3, witness3);
    {
        let account = get_account(&addr, &app);
        assert_eq!(account.unbonded, Coin::zero());
        assert_eq!(account.nonce, 2);
    }
    block_commit(&mut app, unbondtx, 4);
    {
        let account = get_account(&addr, &app);
        // TODO: more precise amount assertions
        assert!(account.unbonded > Coin::zero());
        assert_eq!(account.nonce, 3);
    }
}

#[test]
fn end_block_should_update_liveness_tracker() {
    use chain_abci::app::into_tendermint_validator_pub_key;
    use chain_core::state::tendermint::TendermintValidatorAddress;
    use protobuf::well_known_types::Timestamp;

    let storage = Storage::new_db(create_db());
    let mut account_storage =
        AccountStorage::new(Storage::new_db(Arc::new(create(1))), 20).expect("account db");

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let address = RedeemAddress::from(&public_key);
    let staking_account_address = StakedStateAddress::BasicRedeem(address);

    let mut validator_pubkey = PubKey::new();
    validator_pubkey.field_type = "Ed25519".to_string();
    validator_pubkey.data = base64::decode("EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE=").unwrap();

    let mut validator_voting_power = BTreeMap::new();
    validator_voting_power.insert(staking_account_address, TendermintVotePower::zero());

    let rewards_pool = Coin::zero();
    let mut distribution = BTreeMap::new();
    distribution.insert(address, (StakedStateDestination::Bonded, Coin::max()));

    let mut nodes = BTreeMap::new();
    let node_pubkey = ValidatorPubkey {
        consensus_pubkey_type: ValidatorKeyType::Ed25519,
        consensus_pubkey_b64: "EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE=".to_string(),
    };
    nodes.insert(address, node_pubkey);

    let init_network_params = InitNetworkParameters {
        initial_fee_policy: LinearFee::new(Milli::new(0, 0), Milli::new(0, 0)),
        required_council_node_stake: Coin::max(),
        unbonding_period: 1,
        jailing_config: JailingParameters {
            jail_duration: 60,
            block_signing_window: 5,
            missed_block_threshold: 1,
        },
        slashing_config: SlashingParameters {
            liveness_slash_percent: SlashRatio::from_str("0.1").unwrap(),
            byzantine_slash_percent: SlashRatio::from_str("0.2").unwrap(),
            slash_wait_period: 10800,
        },
    };

    let init_config = InitConfig::new(rewards_pool, distribution, init_network_params, nodes);

    let timestamp = Timestamp::new();

    let (accounts, rewards_pool_state, _) = init_config
        .validate_config_get_genesis(timestamp.get_seconds())
        .expect("Error while validating distribution");

    let mut keys: Vec<StarlingFixedKey> = accounts.iter().map(|account| account.key()).collect();
    let mut wrapped: Vec<AccountWrapper> = accounts
        .iter()
        .map(|account| AccountWrapper(account.clone()))
        .collect();
    let new_account_root = account_storage
        .insert(None, &mut keys, &mut wrapped)
        .expect("initial insert");

    let transaction_tree = MerkleTree::empty();

    let genesis_app_hash =
        compute_app_hash(&transaction_tree, &new_account_root, &rewards_pool_state);

    let mut app = ChainNodeApp::new_with_storage(
        get_enclave_bridge_mock(),
        &hex::encode_upper(genesis_app_hash),
        TEST_CHAIN_ID,
        storage,
        account_storage,
    );

    // Init Chain

    let mut request_init_chain = RequestInitChain::default();
    request_init_chain.set_time(timestamp);
    request_init_chain.set_app_state_bytes(serde_json::to_vec(&init_config).unwrap());
    request_init_chain.set_chain_id(String::from(TEST_CHAIN_ID));
    let response_init_chain = app.init_chain(&request_init_chain);

    let validators = response_init_chain.validators.to_vec();

    assert_eq!(1, validators.len());
    assert_eq!(
        100000000000,
        i64::from(
            *app.validator_voting_power
                .get(&staking_account_address)
                .unwrap()
        )
    );

    // Begin Block

    let mut request_begin_block = RequestBeginBlock::default();
    let mut header = Header::default();
    header.time = Some(Timestamp::new()).into();
    header.chain_id = TEST_CHAIN_ID.to_owned();
    header.height = 1;

    request_begin_block.set_header(header);
    app.begin_block(&request_begin_block);

    // Unbond Transaction (this'll change voting power to zero)

    let transaction = UnbondTx::new(
        staking_account_address,
        0,
        Coin::new(10000000000).unwrap(),
        StakedStateOpAttributes::new(0),
    );
    let witness =
        StakedStateOpWitness::new(get_ecdsa_witness(&secp, &transaction.id(), &secret_key));
    let tx_aux = TxAux::UnbondStakeTx(transaction, witness);

    let mut request_deliver_tx = RequestDeliverTx::default();
    request_deliver_tx.set_tx(tx_aux.encode());
    let response_deliver_tx = app.deliver_tx(&request_deliver_tx);

    assert_eq!(0, response_deliver_tx.code);
    assert_eq!(
        0,
        i64::from(
            *app.power_changed_in_block
                .get(&staking_account_address)
                .expect("Power did not change after unbonding funds")
        )
    );

    // End Block (this'll remove validator from liveness tracker)

    let validator_address: TendermintValidatorAddress = into_tendermint_validator_pub_key(
        app.validator_pubkeys.get(&staking_account_address).unwrap(),
    )
    .into();
    assert!(app
        .last_state
        .as_ref()
        .unwrap()
        .punishment
        .validator_liveness
        .contains_key(&validator_address));

    let mut request_end_block = RequestEndBlock::default();
    request_end_block.height = 1;
    let response_end_block = app.end_block(&request_end_block);

    assert_eq!(1, response_end_block.validator_updates.to_vec().len());
    assert_eq!(0, response_end_block.validator_updates.to_vec()[0].power);
    assert_eq!(
        0,
        i64::from(
            *app.validator_voting_power
                .get(&staking_account_address)
                .unwrap()
        )
    );
    assert!(!app
        .last_state
        .as_ref()
        .unwrap()
        .punishment
        .validator_liveness
        .contains_key(&validator_address));
}

#[test]
fn begin_block_should_jail_byzantine_validators() {
    use chain_abci::app::into_tendermint_validator_pub_key;
    use chain_core::state::tendermint::TendermintValidatorAddress;
    use protobuf::well_known_types::Timestamp;

    let storage = Storage::new_db(create_db());
    let mut account_storage =
        AccountStorage::new(Storage::new_db(Arc::new(create(1))), 20).expect("account db");

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let address = RedeemAddress::from(&public_key);
    let staking_account_address = StakedStateAddress::BasicRedeem(address);

    let mut distribution = BTreeMap::new();
    let rewards_pool = Coin::zero();
    distribution.insert(address, (StakedStateDestination::Bonded, Coin::max()));

    let init_network_params = InitNetworkParameters {
        initial_fee_policy: LinearFee::new(Milli::new(0, 0), Milli::new(0, 0)),
        required_council_node_stake: Coin::max(),
        unbonding_period: 1,
        jailing_config: JailingParameters {
            jail_duration: 60,
            block_signing_window: 5,
            missed_block_threshold: 1,
        },
        slashing_config: SlashingParameters {
            liveness_slash_percent: SlashRatio::from_str("0.1").unwrap(),
            byzantine_slash_percent: SlashRatio::from_str("0.2").unwrap(),
            slash_wait_period: 10800,
        },
    };

    let mut nodes = BTreeMap::new();
    let node_pubkey = ValidatorPubkey {
        consensus_pubkey_type: ValidatorKeyType::Ed25519,
        consensus_pubkey_b64: "EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE=".to_string(),
    };
    nodes.insert(address, node_pubkey);

    let init_config = InitConfig::new(rewards_pool, distribution, init_network_params, nodes);

    let timestamp = Timestamp::new();

    let (accounts, rewards_pool_state, _) = init_config
        .validate_config_get_genesis(timestamp.get_seconds())
        .expect("Error while validating distribution");

    let mut keys: Vec<StarlingFixedKey> = accounts.iter().map(|account| account.key()).collect();
    let mut wrapped: Vec<AccountWrapper> = accounts
        .iter()
        .map(|account| AccountWrapper(account.clone()))
        .collect();
    let new_account_root = account_storage
        .insert(None, &mut keys, &mut wrapped)
        .expect("initial insert");

    let transaction_tree = MerkleTree::empty();

    let genesis_app_hash =
        compute_app_hash(&transaction_tree, &new_account_root, &rewards_pool_state);

    let mut app = ChainNodeApp::new_with_storage(
        get_enclave_bridge_mock(),
        &hex::encode_upper(genesis_app_hash),
        TEST_CHAIN_ID,
        storage,
        account_storage,
    );

    // Init Chain

    let mut request_init_chain = RequestInitChain::default();
    request_init_chain.set_time(timestamp);
    request_init_chain.set_app_state_bytes(serde_json::to_vec(&init_config).unwrap());
    request_init_chain.set_chain_id(String::from(TEST_CHAIN_ID));
    let response_init_chain = app.init_chain(&request_init_chain);

    let validators = response_init_chain.validators.to_vec();

    assert_eq!(1, validators.len());
    assert_eq!(
        100000000000,
        i64::from(
            *app.validator_voting_power
                .get(&staking_account_address)
                .unwrap()
        )
    );

    // Begin Block

    let validator_address: TendermintValidatorAddress = into_tendermint_validator_pub_key(
        app.validator_pubkeys.get(&staking_account_address).unwrap(),
    )
    .into();

    let mut request_begin_block = RequestBeginBlock::default();
    let mut header = Header::default();
    header.time = Some(Timestamp::new()).into();
    header.chain_id = TEST_CHAIN_ID.to_owned();
    header.height = 1;

    let mut validator = Validator::new();
    validator.address = <[u8; 20]>::from(&validator_address).to_vec();

    let mut evidence = Evidence::new();
    evidence.validator = Some(validator).into();

    request_begin_block.header = Some(header).into();
    request_begin_block.byzantine_validators = vec![evidence].into();
    app.begin_block(&request_begin_block);

    assert_eq!(
        TendermintVotePower::zero(),
        *app.power_changed_in_block
            .get(&staking_account_address)
            .unwrap()
    );

    let account = get_account(&address, &app);
    assert!(account.is_jailed());
}

#[test]
fn begin_block_should_jail_non_live_validators() {
    use chain_abci::app::into_tendermint_validator_pub_key;
    use chain_core::state::tendermint::TendermintValidatorAddress;
    use protobuf::well_known_types::Timestamp;

    let storage = Storage::new_db(create_db());
    let mut account_storage =
        AccountStorage::new(Storage::new_db(Arc::new(create(1))), 20).expect("account db");

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let address = RedeemAddress::from(&public_key);
    let staking_account_address = StakedStateAddress::BasicRedeem(address);

    let mut validator_pubkey = PubKey::new();
    validator_pubkey.field_type = "Ed25519".to_string();
    validator_pubkey.data = base64::decode("EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE=").unwrap();

    let mut validator_voting_power = BTreeMap::new();
    validator_voting_power.insert(staking_account_address, TendermintVotePower::zero());

    let rewards_pool = Coin::zero();
    let mut distribution = BTreeMap::new();
    distribution.insert(address, (StakedStateDestination::Bonded, Coin::max()));

    let init_network_params = InitNetworkParameters {
        initial_fee_policy: LinearFee::new(Milli::new(0, 0), Milli::new(0, 0)),
        required_council_node_stake: Coin::max(),
        unbonding_period: 1,
        jailing_config: JailingParameters {
            jail_duration: 60,
            block_signing_window: 5,
            missed_block_threshold: 1,
        },
        slashing_config: SlashingParameters {
            liveness_slash_percent: SlashRatio::from_str("0.1").unwrap(),
            byzantine_slash_percent: SlashRatio::from_str("0.2").unwrap(),
            slash_wait_period: 10800,
        },
    };
    let mut nodes = BTreeMap::new();
    let node_pubkey = ValidatorPubkey {
        consensus_pubkey_type: ValidatorKeyType::Ed25519,
        consensus_pubkey_b64: "EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE=".to_string(),
    };
    nodes.insert(address, node_pubkey);
    let init_config = InitConfig::new(rewards_pool, distribution, init_network_params, nodes);

    let timestamp = Timestamp::new();

    let (accounts, rewards_pool_state, _) = init_config
        .validate_config_get_genesis(timestamp.get_seconds())
        .expect("Error while validating distribution");

    let mut keys: Vec<StarlingFixedKey> = accounts.iter().map(|account| account.key()).collect();
    let mut wrapped: Vec<AccountWrapper> = accounts
        .iter()
        .map(|account| AccountWrapper(account.clone()))
        .collect();
    let new_account_root = account_storage
        .insert(None, &mut keys, &mut wrapped)
        .expect("initial insert");

    let transaction_tree = MerkleTree::empty();

    let genesis_app_hash =
        compute_app_hash(&transaction_tree, &new_account_root, &rewards_pool_state);

    let mut app = ChainNodeApp::new_with_storage(
        get_enclave_bridge_mock(),
        &hex::encode_upper(genesis_app_hash),
        TEST_CHAIN_ID,
        storage,
        account_storage,
    );

    // Init Chain

    let mut request_init_chain = RequestInitChain::default();
    request_init_chain.set_time(timestamp);
    request_init_chain.set_app_state_bytes(serde_json::to_vec(&init_config).unwrap());
    request_init_chain.set_chain_id(String::from(TEST_CHAIN_ID));
    let response_init_chain = app.init_chain(&request_init_chain);

    let validators = response_init_chain.validators.to_vec();

    assert_eq!(1, validators.len());
    assert_eq!(
        100000000000,
        i64::from(
            *app.validator_voting_power
                .get(&staking_account_address)
                .unwrap()
        )
    );

    // Begin Block

    let validator_address: TendermintValidatorAddress = into_tendermint_validator_pub_key(
        app.validator_pubkeys.get(&staking_account_address).unwrap(),
    )
    .into();

    let mut request_begin_block = RequestBeginBlock::default();
    let mut header = Header::default();
    header.time = Some(Timestamp::new()).into();
    header.chain_id = TEST_CHAIN_ID.to_owned();
    header.height = 2;

    let mut validator = Validator::new();
    validator.address = <[u8; 20]>::from(&validator_address).to_vec();

    let mut vote_info = VoteInfo::new();
    vote_info.validator = Some(validator).into();
    vote_info.signed_last_block = false;

    let mut last_commit_info = LastCommitInfo::new();
    last_commit_info.votes = vec![vote_info].into();

    request_begin_block.header = Some(header).into();
    request_begin_block.last_commit_info = Some(last_commit_info).into();
    app.begin_block(&request_begin_block);

    assert_eq!(
        TendermintVotePower::zero(),
        *app.power_changed_in_block
            .get(&staking_account_address)
            .unwrap()
    );

    let account = get_account(&address, &app);
    assert!(account.is_jailed());
}

#[test]
fn begin_block_should_slash_byzantine_validators() {
    use chain_abci::app::into_tendermint_validator_pub_key;
    use chain_core::state::tendermint::TendermintValidatorAddress;
    use protobuf::well_known_types::Timestamp;

    let storage = Storage::new_db(create_db());
    let mut account_storage =
        AccountStorage::new(Storage::new_db(Arc::new(create(1))), 20).expect("account db");

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let address = RedeemAddress::from(&public_key);
    let staking_account_address = StakedStateAddress::BasicRedeem(address);

    let mut validator_pubkey = PubKey::new();
    validator_pubkey.field_type = "Ed25519".to_string();
    validator_pubkey.data = base64::decode("EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE=").unwrap();

    let mut validator_voting_power = BTreeMap::new();
    validator_voting_power.insert(staking_account_address, TendermintVotePower::zero());

    let rewards_pool = Coin::zero();
    let mut distribution = BTreeMap::new();
    distribution.insert(address, (StakedStateDestination::Bonded, Coin::max()));

    let init_network_params = InitNetworkParameters {
        initial_fee_policy: LinearFee::new(Milli::new(0, 0), Milli::new(0, 0)),
        required_council_node_stake: Coin::max(),
        unbonding_period: 1,
        jailing_config: JailingParameters {
            jail_duration: 60,
            block_signing_window: 5,
            missed_block_threshold: 1,
        },
        slashing_config: SlashingParameters {
            liveness_slash_percent: SlashRatio::from_str("0.1").unwrap(),
            byzantine_slash_percent: SlashRatio::from_str("0.2").unwrap(),
            slash_wait_period: 5,
        },
    };

    let mut nodes = BTreeMap::new();
    let node_pubkey = ValidatorPubkey {
        consensus_pubkey_type: ValidatorKeyType::Ed25519,
        consensus_pubkey_b64: "EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE=".to_string(),
    };
    nodes.insert(address, node_pubkey);
    let init_config = InitConfig::new(rewards_pool, distribution, init_network_params, nodes);

    let timestamp = Timestamp::new();

    let (accounts, rewards_pool_state, _) = init_config
        .validate_config_get_genesis(timestamp.get_seconds())
        .expect("Error while validating distribution");

    let mut keys: Vec<StarlingFixedKey> = accounts.iter().map(|account| account.key()).collect();
    let mut wrapped: Vec<AccountWrapper> = accounts
        .iter()
        .map(|account| AccountWrapper(account.clone()))
        .collect();
    let new_account_root = account_storage
        .insert(None, &mut keys, &mut wrapped)
        .expect("initial insert");

    let transaction_tree = MerkleTree::empty();

    let genesis_app_hash =
        compute_app_hash(&transaction_tree, &new_account_root, &rewards_pool_state);

    let mut app = ChainNodeApp::new_with_storage(
        get_enclave_bridge_mock(),
        &hex::encode_upper(genesis_app_hash),
        TEST_CHAIN_ID,
        storage,
        account_storage,
    );

    // Init Chain

    let mut request_init_chain = RequestInitChain::default();
    request_init_chain.set_time(timestamp);
    request_init_chain.set_app_state_bytes(serde_json::to_vec(&init_config).unwrap());
    request_init_chain.set_chain_id(String::from(TEST_CHAIN_ID));
    let response_init_chain = app.init_chain(&request_init_chain);

    let validators = response_init_chain.validators.to_vec();

    assert_eq!(1, validators.len());
    assert_eq!(
        100000000000,
        i64::from(
            *app.validator_voting_power
                .get(&staking_account_address)
                .unwrap()
        )
    );

    // Begin Block

    let validator_address: TendermintValidatorAddress = into_tendermint_validator_pub_key(
        app.validator_pubkeys.get(&staking_account_address).unwrap(),
    )
    .into();

    let mut request_begin_block = RequestBeginBlock::default();
    let mut header = Header::default();
    header.time = Some(Timestamp::new()).into();
    header.chain_id = TEST_CHAIN_ID.to_owned();
    header.height = 1;

    let mut validator = Validator::new();
    validator.address = <[u8; 20]>::from(&validator_address).to_vec();

    let mut evidence = Evidence::new();
    evidence.validator = Some(validator).into();

    request_begin_block.header = Some(header).into();
    request_begin_block.byzantine_validators = vec![evidence].into();
    app.begin_block(&request_begin_block);

    assert_eq!(
        TendermintVotePower::zero(),
        *app.power_changed_in_block
            .get(&staking_account_address)
            .unwrap()
    );

    let account = get_account(&address, &app);
    assert!(account.is_jailed());

    assert!(app
        .last_state
        .as_ref()
        .unwrap()
        .punishment
        .slashing_schedule
        .contains_key(&staking_account_address));

    // End Block

    let request_end_block = RequestEndBlock::new();
    app.end_block(&request_end_block);

    assert_eq!(
        Coin::zero(),
        app.last_state.as_ref().unwrap().rewards_pool.remaining
    );

    // Begin Block

    let mut request_begin_block = RequestBeginBlock::default();

    let mut time = Timestamp::new();
    time.seconds = 10;

    let mut header = Header::default();
    header.time = Some(time).into();
    header.chain_id = TEST_CHAIN_ID.to_owned();
    header.height = 1;

    request_begin_block.header = Some(header).into();

    app.begin_block(&request_begin_block);

    assert!(!app
        .last_state
        .as_ref()
        .unwrap()
        .punishment
        .slashing_schedule
        .contains_key(&staking_account_address));

    assert_eq!(
        Coin::new((u64::from(Coin::max()) / 10) * 2).unwrap(), // 0.2 * account_balance
        app.last_state.as_ref().unwrap().rewards_pool.remaining
    );
}

#[test]
fn begin_block_should_slash_non_live_validators() {
    use chain_abci::app::into_tendermint_validator_pub_key;
    use chain_core::state::tendermint::TendermintValidatorAddress;
    use protobuf::well_known_types::Timestamp;

    let storage = Storage::new_db(create_db());
    let mut account_storage =
        AccountStorage::new(Storage::new_db(Arc::new(create(1))), 20).expect("account db");

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let address = RedeemAddress::from(&public_key);
    let staking_account_address = StakedStateAddress::BasicRedeem(address);

    let mut validator_pubkey = PubKey::new();
    validator_pubkey.field_type = "Ed25519".to_string();
    validator_pubkey.data = base64::decode("EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE=").unwrap();

    let mut validator_voting_power = BTreeMap::new();
    validator_voting_power.insert(staking_account_address, TendermintVotePower::zero());

    let rewards_pool = Coin::zero();
    let mut distribution = BTreeMap::new();
    distribution.insert(address, (StakedStateDestination::Bonded, Coin::max()));

    let init_network_params = InitNetworkParameters {
        initial_fee_policy: LinearFee::new(Milli::new(0, 0), Milli::new(0, 0)),
        required_council_node_stake: Coin::max(),
        unbonding_period: 1,
        jailing_config: JailingParameters {
            jail_duration: 60,
            block_signing_window: 5,
            missed_block_threshold: 1,
        },
        slashing_config: SlashingParameters {
            liveness_slash_percent: SlashRatio::from_str("0.1").unwrap(),
            byzantine_slash_percent: SlashRatio::from_str("0.2").unwrap(),
            slash_wait_period: 5,
        },
    };
    let mut nodes = BTreeMap::new();
    let node_pubkey = ValidatorPubkey {
        consensus_pubkey_type: ValidatorKeyType::Ed25519,
        consensus_pubkey_b64: "EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE=".to_string(),
    };
    nodes.insert(address, node_pubkey);

    let init_config = InitConfig::new(rewards_pool, distribution, init_network_params, nodes);

    let timestamp = Timestamp::new();

    let (accounts, rewards_pool_state, _) = init_config
        .validate_config_get_genesis(timestamp.get_seconds())
        .expect("Error while validating distribution");

    let mut keys: Vec<StarlingFixedKey> = accounts.iter().map(|account| account.key()).collect();
    let mut wrapped: Vec<AccountWrapper> = accounts
        .iter()
        .map(|account| AccountWrapper(account.clone()))
        .collect();
    let new_account_root = account_storage
        .insert(None, &mut keys, &mut wrapped)
        .expect("initial insert");

    let transaction_tree = MerkleTree::empty();

    let genesis_app_hash =
        compute_app_hash(&transaction_tree, &new_account_root, &rewards_pool_state);

    let mut app = ChainNodeApp::new_with_storage(
        get_enclave_bridge_mock(),
        &hex::encode_upper(genesis_app_hash),
        TEST_CHAIN_ID,
        storage,
        account_storage,
    );

    // Init Chain

    let mut request_init_chain = RequestInitChain::default();
    request_init_chain.set_time(timestamp);
    request_init_chain.set_app_state_bytes(serde_json::to_vec(&init_config).unwrap());
    request_init_chain.set_chain_id(String::from(TEST_CHAIN_ID));
    let response_init_chain = app.init_chain(&request_init_chain);

    let validators = response_init_chain.validators.to_vec();

    assert_eq!(1, validators.len());
    assert_eq!(
        100000000000,
        i64::from(
            *app.validator_voting_power
                .get(&staking_account_address)
                .unwrap()
        )
    );

    // Begin Block

    let validator_address: TendermintValidatorAddress = into_tendermint_validator_pub_key(
        app.validator_pubkeys.get(&staking_account_address).unwrap(),
    )
    .into();

    let mut request_begin_block = RequestBeginBlock::default();
    let mut header = Header::default();
    header.time = Some(Timestamp::new()).into();
    header.chain_id = TEST_CHAIN_ID.to_owned();
    header.height = 2;

    let mut validator = Validator::new();
    validator.address = <[u8; 20]>::from(&validator_address).to_vec();

    let mut vote_info = VoteInfo::new();
    vote_info.validator = Some(validator).into();
    vote_info.signed_last_block = false;

    let mut last_commit_info = LastCommitInfo::new();
    last_commit_info.votes = vec![vote_info].into();

    request_begin_block.header = Some(header).into();
    request_begin_block.last_commit_info = Some(last_commit_info).into();
    app.begin_block(&request_begin_block);

    assert_eq!(
        TendermintVotePower::zero(),
        *app.power_changed_in_block
            .get(&staking_account_address)
            .unwrap()
    );

    let account = get_account(&address, &app);
    assert!(account.is_jailed());

    assert!(app
        .last_state
        .as_ref()
        .unwrap()
        .punishment
        .slashing_schedule
        .contains_key(&staking_account_address));

    // End Block

    let request_end_block = RequestEndBlock::new();
    app.end_block(&request_end_block);

    assert_eq!(
        Coin::zero(),
        app.last_state.as_ref().unwrap().rewards_pool.remaining
    );

    // Begin Block

    let mut request_begin_block = RequestBeginBlock::default();

    let mut time = Timestamp::new();
    time.seconds = 10;

    let mut header = Header::default();
    header.time = Some(time).into();
    header.chain_id = TEST_CHAIN_ID.to_owned();
    header.height = 1;

    request_begin_block.header = Some(header).into();

    app.begin_block(&request_begin_block);

    assert!(!app
        .last_state
        .as_ref()
        .unwrap()
        .punishment
        .slashing_schedule
        .contains_key(&staking_account_address));

    assert_eq!(
        Coin::new(u64::from(Coin::max()) / 10).unwrap(), // 0.1 * account_balance
        app.last_state.as_ref().unwrap().rewards_pool.remaining
    );
}
