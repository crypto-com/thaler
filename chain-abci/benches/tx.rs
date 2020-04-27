use abci::{Application, RequestCheckTx, RequestInitChain};
use chain_abci::app::ChainNodeApp;
use chain_abci::storage::account::AccountStorage;
use chain_abci::storage::account::AccountWrapper;
use chain_abci::storage::tx::StarlingFixedKey;
use chain_abci::storage::{Storage, NUM_COLUMNS};
use chain_core::common::MerkleTree;
use chain_core::compute_app_hash;
use chain_core::init::config::AccountType;
use chain_core::init::config::InitNetworkParameters;
use chain_core::init::config::{InitialValidator, ValidatorKeyType};
use chain_core::init::{address::RedeemAddress, coin::Coin, config::InitConfig};
use chain_core::state::account::*;
use chain_core::tx::fee::{LinearFee, Milli};
use chain_core::tx::witness::EcdsaSignature;
use chain_core::tx::witness::TxInWitness;
use chain_core::tx::TransactionId;
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
use parity_scale_codec::Encode;
use secp256k1::{
    key::{PublicKey, SecretKey},
    Message, Secp256k1, Signing,
};
use std::collections::BTreeMap;
use std::sync::Arc;

fn create_db() -> Arc<dyn KeyValueDB> {
    Arc::new(create(NUM_COLUMNS.unwrap()))
}

fn create_account_db() -> AccountStorage {
    AccountStorage::new(Storage::new_db(Arc::new(create(1))), 20).expect("account db")
}

const TEST_CHAIN_ID: &str = "test-00";

pub fn get_ecdsa_witness<C: Signing>(
    secp: &Secp256k1<C>,
    txid: &TxId,
    secret_key: &SecretKey,
) -> EcdsaSignature {
    let message = Message::from_slice(&txid[..]).expect("32 bytes");
    let sig = secp.sign_recoverable(&message, &secret_key);
    return sig;
}

fn init_chain_for(addresses: &Vec<RedeemAddress>) -> ChainNodeApp {
    let total = Coin::from((addresses.len() * 1_0000_0000usize) as u32);
    let remaining = (Coin::max() - total).unwrap();
    let validator_addr = "0x0e7c045110b8dbf29765047380898919c5cc56f4"
        .parse::<RedeemAddress>()
        .unwrap();
    let mut distribution: BTreeMap<RedeemAddress, (Coin, AccountType)> = addresses
        .iter()
        .map(|address| {
            (
                *address,
                (
                    Coin::from(1_0000_0000 as u32),
                    AccountType::ExternallyOwnedAccount,
                ),
            )
        })
        .collect();
    distribution.insert(
        RedeemAddress::default(),
        (Coin::zero(), AccountType::ExternallyOwnedAccount),
    );
    distribution.insert(
        validator_addr,
        (remaining, AccountType::ExternallyOwnedAccount),
    );

    let params = InitNetworkParameters {
        initial_fee_policy: LinearFee::new(
            Milli::try_new(1, 1).unwrap(),
            Milli::try_new(1, 1).unwrap(),
        ),
        required_council_node_stake: remaining,
        unbonding_period: 1,
    };
    let c = InitConfig::new(
        distribution,
        RedeemAddress::default(),
        RedeemAddress::default(),
        RedeemAddress::default(),
        params,
        vec![InitialValidator {
            staking_account_address: validator_addr,
            consensus_pubkey_type: ValidatorKeyType::Ed25519,
            consensus_pubkey_b64: "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=".to_string(),
        }],
    );
    let t = ::protobuf::well_known_types::Timestamp::new();
    let result = c.validate_config_get_genesis(t.get_seconds());
    if let Ok((accounts, rp, _nodes)) = result {
        let tx_tree = MerkleTree::empty();
        let mut account_tree =
            AccountStorage::new(Storage::new_db(Arc::new(create(1))), 20).expect("account db");

        let keys: Vec<StarlingFixedKey> = accounts.iter().map(|x| x.key()).collect();
        // TODO: get rid of the extra allocations
        let wrapped: Vec<AccountWrapper> =
            accounts.iter().map(|x| AccountWrapper(x.clone())).collect();
        let new_account_root = account_tree
            .insert(
                None,
                &mut keys.iter().collect::<Vec<_>>(),
                &mut wrapped.iter().collect::<Vec<_>>(),
            )
            .expect("initial insert");

        let genesis_app_hash = compute_app_hash(&tx_tree, &new_account_root, &rp);

        let example_hash = hex::encode_upper(genesis_app_hash);
        let mut app = ChainNodeApp::new_with_storage(
            &example_hash,
            TEST_CHAIN_ID,
            Storage::new_db(create_db()),
            create_account_db(),
        );
        let mut req = RequestInitChain::default();
        req.set_time(t);
        req.set_app_state_bytes(serde_json::to_vec(&c).unwrap());
        req.set_chain_id(String::from(TEST_CHAIN_ID));
        app.init_chain(&req);
        return app;
    } else {
        panic!("distribution validation error: {}", result.err().unwrap());
    }
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
    let app = init_chain_for(&addrs);
    let mut txs = Vec::new();
    for i in 0..addrs.len() {
        let tx = WithdrawUnbondedTx::new(
            0,
            vec![TxOut::new_with_timelock(
                ExtendedAddr::BasicRedeem(addrs[i]),
                Coin::unit(),
                0,
            )],
            TxAttributes::new_with_access(
                0,
                vec![TxAccessPolicy::new(public_keys[i], TxAccess::AllData)],
            ),
        );

        let witness =
            StakedStateOpWitness::new(get_ecdsa_witness(&secp, &tx.id(), &secret_keys[i]));
        let txaux = TxAux::WithdrawUnbondedStakeTx(tx, witness);
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
            creq.set_tx(txaux.encode());
            creq
        })
        .collect();
    c.bench_function("checktx x", move |b| b.iter(|| check_x_tx(&mut app, &reqs)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
