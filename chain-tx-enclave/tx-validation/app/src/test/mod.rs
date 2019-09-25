use crate::enclave_u::{check_initchain, check_tx, end_block};
use crate::enclave_u::{get_token, store_token};
use chain_core::common::MerkleTree;
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::state::account::{
    StakedState, StakedStateAddress, StakedStateOpWitness, WithdrawUnbondedTx,
};
use chain_core::tx::fee::Fee;
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
        Tx, TxId,
    },
    witness::TxInWitness,
    TxAux,
};
use chain_core::ChainInfo;
use chain_tx_validation::Error;
use enclave_protocol::{IntraEnclaveRequest, VerifyTxRequest};
use enclave_u_common::enclave_u::{init_enclave, VALIDATION_TOKEN_KEY};
use env_logger::{Builder, WriteStyle};
use log::LevelFilter;
use log::{debug, error, info};
use parity_scale_codec::Encode;
use secp256k1::{
    key::PublicKey, key::SecretKey, schnorrsig::schnorr_sign, Message, Secp256k1, Signing,
};
use sled::Db;

pub fn get_ecdsa_witness<C: Signing>(
    secp: &Secp256k1<C>,
    txid: &TxId,
    secret_key: &SecretKey,
) -> EcdsaSignature {
    let message = Message::from_slice(&txid[..]).expect("32 bytes");
    let sig = secp.sign_recoverable(&message, &secret_key);
    return sig;
}

fn get_account(account_address: &RedeemAddress) -> StakedState {
    StakedState::new_init(
        Coin::one(),
        0,
        StakedStateAddress::from(*account_address),
        false,
    )
}

const TEST_NETWORK_ID: u8 = 0xab;

fn cleanup(db: &mut Db) {
    db.drop_tree(crate::META_KEYSPACE).expect("test meta tx");
    db.drop_tree(crate::TX_KEYSPACE).expect("test cleanup tx");
}

/// Unfortunately the usual Rust unit-test facility can't be used with Baidu SGX SDK,
/// so this has to be run as a normal app
pub fn test_sealing() {
    let mut builder = Builder::new();

    builder
        .filter(None, LevelFilter::Debug)
        .write_style(WriteStyle::Always)
        .init();
    let mut db = Db::open(".enclave-test").expect("failed to open a storage path");
    let mut metadb = db
        .open_tree(crate::META_KEYSPACE)
        .expect("failed to open a meta keyspace");
    let mut txdb = db
        .open_tree(crate::TX_KEYSPACE)
        .expect("failed to open a tx keyspace");

    let token = get_token(&metadb, VALIDATION_TOKEN_KEY);
    let enclave = match init_enclave(true, token) {
        (Ok(r), new_token) => {
            info!("[+] Init Enclave Successful {}!", r.geteid());
            if let Some(launch_token) = new_token {
                store_token(&mut metadb, VALIDATION_TOKEN_KEY, launch_token.to_vec());
            }
            r
        }
        (Err(x), _) => {
            error!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };
    assert!(check_initchain(enclave.geteid(), TEST_NETWORK_ID, None).is_ok());

    let end_b = end_block(enclave.geteid(), IntraEnclaveRequest::EndBlock);
    match end_b {
        Ok(b) => {
            debug!("request filter in the beginning");
            assert!(b.iter().all(|x| *x == 0u8), "empty filter");
        }
        _ => {
            cleanup(&mut db);
            assert!(false, "filter not returned");
        }
    };

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let addr = RedeemAddress::from(&public_key);

    let merkle_tree = MerkleTree::new(vec![RawPubkey::from(public_key.serialize())]);

    let eaddr = ExtendedAddr::OrTree(merkle_tree.root_hash());
    let tx0 = WithdrawUnbondedTx::new(
        0,
        vec![TxOut::new_with_timelock(eaddr.clone(), Coin::one(), 0)],
        TxAttributes::new_with_access(
            TEST_NETWORK_ID,
            vec![TxAccessPolicy::new(public_key.clone(), TxAccess::AllData)],
        ),
    );
    let txid = &tx0.id();
    let witness0 = StakedStateOpWitness::new(get_ecdsa_witness(&secp, &txid, &secret_key));
    let withdrawtx = TxAux::WithdrawUnbondedStakeTx {
        txid: tx0.id(),
        no_of_outputs: tx0.outputs.len() as TxoIndex,
        witness: witness0,
        payload: TxObfuscated {
            key_from: 0,
            nonce: [0u8; 12],
            txpayload: PlainTxAux::WithdrawUnbondedStakeTx(tx0).encode(),
        },
    };
    let account = get_account(&addr);
    let info = ChainInfo {
        min_fee_computed: Fee::new(Coin::zero()),
        chain_hex_id: TEST_NETWORK_ID,
        previous_block_time: 1,
        unbonding_period: 0,
    };
    let tb = txdb.get(&txid);
    match tb {
        Ok(None) => {
            debug!("new tx not in DB yet");
        }
        _ => {
            cleanup(&mut db);
            assert!(false, "new tx already in db");
        }
    };
    let mut request0 = IntraEnclaveRequest::ValidateTx {
        request: Box::new(VerifyTxRequest {
            tx: withdrawtx,
            account: Some(account),
            info,
        }),
        tx_inputs: None,
    };
    let r = check_tx(enclave.geteid(), request0, &mut txdb);
    assert!(r.is_ok());
    let ta = txdb.get(&txid);
    let sealedtx = match ta {
        Ok(Some(tx)) => {
            debug!("new tx in DB!");
            tx.to_vec()
        }
        _ => {
            cleanup(&mut db);
            assert!(false, "new tx not in db");
            vec![]
        }
    };

    let end_b = end_block(enclave.geteid(), IntraEnclaveRequest::EndBlock);
    match end_b {
        Ok(b) => {
            debug!("request filter after one tx");
            assert!(b.iter().any(|x| *x != 0u8), "non-empty filter");
        }
        _ => {
            cleanup(&mut db);
            assert!(false, "filter not returned");
        }
    };

    let halfcoin = Coin::from(5000_0000u32);
    let utxo1 = TxoPointer::new(*txid, 0);
    let mut tx1 = Tx::new();
    tx1.attributes = TxAttributes::new(TEST_NETWORK_ID);
    tx1.add_input(utxo1.clone());
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
    let transfertx = TxAux::TransferTx {
        txid: tx1.id(),
        inputs: tx1.inputs.clone(),
        no_of_outputs: tx1.outputs.len() as TxoIndex,
        payload: TxObfuscated {
            key_from: 0,
            nonce: [0u8; 12],
            txpayload: plain_txaux.encode(),
        },
    };

    let tc = txdb.get(&txid1);
    match tc {
        Ok(None) => {
            debug!("new 2nd tx not in DB yet");
        }
        _ => {
            assert!(false, "new 2nd tx already in db");
        }
    };

    let mut request1 = IntraEnclaveRequest::ValidateTx {
        request: Box::new(VerifyTxRequest {
            tx: transfertx,
            account: None,
            info,
        }),
        tx_inputs: Some(vec![sealedtx.clone()]),
    };

    let r2 = check_tx(enclave.geteid(), request1, &mut txdb);
    assert!(r2.is_ok());
    let td = txdb.get(&txid1);
    match td {
        Ok(Some(tx)) => {
            debug!("new 2nd tx in DB!");
        }
        _ => {
            cleanup(&mut db);
            assert!(false, "new 2nd tx not in db");
        }
    };

    let mut tx2 = Tx::new();
    tx2.attributes = TxAttributes::new(TEST_NETWORK_ID);
    tx2.add_input(utxo1);
    tx2.add_output(TxOut::new(eaddr.clone(), Coin::zero()));
    let txid2 = tx2.id();
    let witness2 = vec![TxInWitness::TreeSig(
        schnorr_sign(&secp, &Message::from_slice(&txid2).unwrap(), &secret_key).0,
        merkle_tree
            .generate_proof(RawPubkey::from(public_key.serialize()))
            .unwrap(),
    )]
    .into();
    let plain_txaux2 = PlainTxAux::TransferTx(tx2.clone(), witness2);
    let transfertx2 = TxAux::TransferTx {
        txid: tx2.id(),
        inputs: tx2.inputs.clone(),
        no_of_outputs: tx2.outputs.len() as TxoIndex,
        payload: TxObfuscated {
            key_from: 0,
            nonce: [0u8; 12],
            txpayload: plain_txaux2.encode(),
        },
    };
    let mut request2 = IntraEnclaveRequest::ValidateTx {
        request: Box::new(VerifyTxRequest {
            tx: transfertx2,
            account: None,
            info,
        }),
        tx_inputs: Some(vec![sealedtx]),
    };

    let r3 = check_tx(enclave.geteid(), request2, &mut txdb);
    match r3 {
        Err(Error::ZeroCoin) => {
            debug!("invalid transaction rejected and error code returned");
        }
        x => {
            cleanup(&mut db);
            panic!(
                "something else happened (tx not correctly rejected): {:?}",
                x
            );
        }
    };

    cleanup(&mut db);
}
