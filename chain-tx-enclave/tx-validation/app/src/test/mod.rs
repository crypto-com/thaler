use crate::enclave_u::{check_initchain, check_tx, end_block};
use chain_core::common::MerkleTree;
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::state::account::{
    StakedState, StakedStateAddress, StakedStateOpWitness, WithdrawUnbondedTx,
};
use chain_core::tx::fee::Fee;
use chain_core::state::account::StakedStateDestination;
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
    TxEnclaveAux,
};
use chain_core::ChainInfo;
use chain_tx_validation::Error;
use enclave_protocol::{EncryptionRequest, IntraEnclaveRequest, VerifyTxRequest};
use enclave_u_common::enclave_u::init_enclave;
use env_logger::{Builder, WriteStyle};
use log::LevelFilter;
use log::{debug, error, info};
use parity_scale_codec::{Decode, Encode};
use secp256k1::{
    key::PublicKey, key::SecretKey, schnorrsig::schnorr_sign, Message, Secp256k1, Signing,
};
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use sled::Db;

extern "C" {
    fn ecall_test_encrypt(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        enc_request: *const u8,
        enc_request_len: usize,
        response_buf: *mut u8,
        response_len: u32,
    ) -> sgx_status_t;
}

pub fn encrypt(eid: sgx_enclave_id_t, request: EncryptionRequest) -> TxObfuscated {
    let request_buf: Vec<u8> = request.encode();
    let response_len = 2 * request_buf.len();
    let mut response_buf: Vec<u8> = vec![0u8; response_len];
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let response_slice = &mut response_buf[..];
    let result = unsafe {
        ecall_test_encrypt(
            eid,
            &mut retval,
            request_buf.as_ptr(),
            request_buf.len(),
            response_slice.as_mut_ptr(),
            response_buf.len() as u32,
        )
    };
    if retval == sgx_status_t::SGX_SUCCESS && result == retval {
        TxObfuscated::decode(&mut response_buf.as_slice()).expect("test response")
    } else {
        panic!("test enclave call failed: {} {}", retval, result);
    }
}

fn get_ecdsa_witness<C: Signing>(
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
        None,
        StakedStateAddress::from(*account_address),
        &StakedStateDestination::UnbondedFromCustomTime(0),
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

    let enclave = match init_enclave(true) {
        Ok(r) => {
            info!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
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
    let account = get_account(&addr);
    let withdrawtx = TxEnclaveAux::WithdrawUnbondedStakeTx {
        no_of_outputs: tx0.outputs.len() as TxoIndex,
        witness: witness0.clone(),
        payload: encrypt(
            enclave.geteid(),
            EncryptionRequest::WithdrawStake(tx0, account.clone(), witness0),
        ),
    };

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
    let request0 = IntraEnclaveRequest::ValidateTx {
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
    let transfertx = TxEnclaveAux::TransferTx {
        inputs: tx1.inputs.clone(),
        no_of_outputs: tx1.outputs.len() as TxoIndex,
        payload: encrypt(
            enclave.geteid(),
            EncryptionRequest::TransferTx(tx1, witness1),
        ),
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

    let request1 = IntraEnclaveRequest::ValidateTx {
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
        Ok(Some(_tx)) => {
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
    let transfertx2 = TxEnclaveAux::TransferTx {
        inputs: tx2.inputs.clone(),
        no_of_outputs: tx2.outputs.len() as TxoIndex,
        payload: encrypt(
            enclave.geteid(),
            EncryptionRequest::TransferTx(tx2, witness2),
        ),
    };
    let request2 = IntraEnclaveRequest::ValidateTx {
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
