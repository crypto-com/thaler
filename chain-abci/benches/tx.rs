use abci::{Application, RequestCheckTx, RequestInitChain};
use chain_abci::app::ChainNodeApp;
use chain_abci::storage::{Storage, NUM_COLUMNS};
use chain_core::common::merkle::MerkleTree;
use chain_core::init::{
    address::RedeemAddress,
    coin::Coin,
    config::{ERC20Owner, InitConfig},
};
use chain_core::tx::witness::{redeem::EcdsaSignature, tree::pk_to_raw, TxInWitness};
use chain_core::tx::{
    data::{
        access::{TxAccess, TxAccessPolicy},
        address::ExtendedAddr,
        attribute::TxAttributes,
        input::TxoPointer,
        output::TxOut,
        Tx, TxId,
    },
    TxAux,
};
use criterion::Criterion;
use criterion::{criterion_group, criterion_main};
use kvdb::KeyValueDB;
use kvdb_memorydb::create;
use secp256k1::{
    key::{PublicKey, SecretKey},
    Message, Secp256k1, Signing,
};
use std::sync::Arc;

fn create_db() -> Arc<KeyValueDB> {
    Arc::new(create(NUM_COLUMNS.unwrap()))
}

const TEST_CHAIN_ID: &str = "test-00";

pub fn get_tx_witness<C: Signing>(
    secp: &Secp256k1<C>,
    tx: &Tx,
    secret_key: &SecretKey,
) -> TxInWitness {
    let message = Message::from_slice(&tx.id()).expect("32 bytes");
    let sig = secp.sign_recoverable(&message, &secret_key);
    let (v, ss) = sig.serialize_compact();
    let r = &ss[0..32];
    let s = &ss[32..64];
    let mut sign = EcdsaSignature::default();
    sign.v = v.to_i32() as u8;
    sign.r.copy_from_slice(r);
    sign.s.copy_from_slice(s);
    return TxInWitness::BasicRedeem(sign);
}

fn init_chain_for(addresses: &Vec<RedeemAddress>) -> (ChainNodeApp, Vec<TxId>) {
    let db = create_db();
    let total = Coin::from(addresses.len() as u32);
    let remaining = (Coin::max() - total).unwrap();
    let mut initial: Vec<ERC20Owner> = addresses
        .iter()
        .map(|address| ERC20Owner::new(*address, Coin::unit()))
        .collect();
    initial.push(ERC20Owner::new(RedeemAddress::default(), remaining));

    let c = InitConfig::new(initial);
    let utxos = c.generate_utxos(&TxAttributes::new(0));
    let txids: Vec<TxId> = utxos.iter().map(|x| x.id()).collect();
    let tree = MerkleTree::new(&txids);
    let genesis_app_hash = tree.get_root_hash();
    let example_hash = hex::encode_upper(genesis_app_hash);
    let mut app =
        ChainNodeApp::new_with_storage(&example_hash, TEST_CHAIN_ID, Storage::new_db(db.clone()));
    let mut req = RequestInitChain::default();
    req.set_app_state_bytes(serde_json::to_vec(&c).unwrap());
    req.set_chain_id(String::from(TEST_CHAIN_ID));
    req.set_time(::protobuf::well_known_types::Timestamp::new());
    app.init_chain(&req);
    return (app, txids);
}

fn prepare_app_valid_txs(upper: u8) -> (ChainNodeApp, Vec<TxAux>) {
    let secp = Secp256k1::new();
    let dummy_keys = 0x01..upper;
    let secret_keys: Vec<SecretKey> = dummy_keys
        .map(|x| SecretKey::from_slice(&[x; 32]).unwrap())
        .collect();
    let public_keys: Vec<PublicKey> = secret_keys
        .iter()
        .map(|secret_key| PublicKey::from_secret_key(&secp, &secret_key))
        .collect();
    let addrs = public_keys
        .iter()
        .map(|public_key| RedeemAddress::from(public_key))
        .collect();
    let (app, txids) = init_chain_for(&addrs);
    let mut txs = Vec::new();
    for i in 0..addrs.len() {
        let txp = TxoPointer::new(txids[i], 0);
        let mut tx = Tx::new();
        tx.attributes.allowed_view.push(TxAccessPolicy::new(
            pk_to_raw(public_keys[i]),
            TxAccess::AllData,
        ));
        let eaddr = ExtendedAddr::BasicRedeem(addrs[i].0);
        tx.add_input(txp);
        tx.add_output(TxOut::new(eaddr, Coin::unit()));
        let witness: Vec<TxInWitness> = vec![get_tx_witness(&secp, &tx, &secret_keys[i])];
        let txaux = TxAux::new(tx, witness.into());
        txs.push(txaux)
    }

    (app, txs)
}

fn check_x_tx(app: &mut ChainNodeApp, reqs: &Vec<RequestCheckTx>) {
    for creq in reqs.iter() {
        let _cresp = app.check_tx(&creq);
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let (mut app, txs) = prepare_app_valid_txs(0x05);
    let reqs = txs
        .iter()
        .map(|txaux| {
            let mut creq = RequestCheckTx::default();
            creq.set_tx(serde_cbor::ser::to_vec_packed(&txaux).unwrap());
            creq
        })
        .collect();
    c.bench_function("checktx x", move |b| b.iter(|| check_x_tx(&mut app, &reqs)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
