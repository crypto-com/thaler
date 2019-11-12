use crate::enclave_u::init_connection;
use crate::enclave_u::run_server;
use crate::enclave_u::ZMQ_SOCKET;
use crate::start_enclave;
use crate::TIMEOUT_SEC;
use chain_core::common::MerkleTree;
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::state::account::{
    StakedState, StakedStateDestination, StakedStateAddress, StakedStateOpWitness, WithdrawUnbondedTx,
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
    TxEnclaveAux,
};
use chain_core::ChainInfo;
use client_common::PrivateKey;
use client_core::cipher::DefaultTransactionObfuscation;
use client_core::cipher::TransactionObfuscation;
use enclave_protocol::FLAGS;
use enclave_protocol::{EnclaveRequest, EnclaveResponse};
use enclave_u_common::enclave_u::init_enclave;
use env_logger::{Builder, WriteStyle};
use log::LevelFilter;
use log::{debug, error, info, warn};
use parity_scale_codec::{Decode, Encode};
use secp256k1::{
    key::PublicKey, key::SecretKey, schnorrsig::schnorr_sign, Message, Secp256k1, Signing,
};
use sgx_types::sgx_status_t;
use std::net::TcpListener;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time;

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
    StakedState::new_init_unbonded(
        Coin::one(),
        0,
        StakedStateAddress::from(*account_address),
    )
}

const TEST_NETWORK_ID: u8 = 0xab;

pub fn test_integration() {
    let mut builder = Builder::new();
    let validation_path =
        std::env::var("TX_VALIDATION_BIN_DIR").unwrap_or("/root/sgx/tx-validation/bin/".to_owned());
    let query_server_host = std::env::var("TX_QUERY_APP_HOST").unwrap_or("0.0.0.0".to_owned());
    let query_server_port = std::env::var("TX_QUERY_APP_PORT").unwrap_or("3443".to_owned());
    let query_server_addr = format!("{}:{}", query_server_host, query_server_port);
    let validation_dir = Path::new(&validation_path);
    let connection_socket = format! {"ipc://{}integration.enclave", validation_path};
    builder
        .filter(None, LevelFilter::Info)
        .write_style(WriteStyle::Always)
        .init();
    let mut validation = Command::new("./tx-validation-app")
        .current_dir(validation_dir)
        .env("TX_ENCLAVE_STORAGE", ".enclave-integration")
        .env("RUST_LOG", "debug")
        .args(&[&connection_socket])
        .spawn()
        .expect("failed to start tx validation");
    init_connection(&connection_socket);
    let t = thread::spawn(move || {
        let enclave = start_enclave();

        info!("Running TX Decryption Query server...");

        let listener = TcpListener::bind(query_server_addr)
            .expect("failed to bind the TCP socket");

        for _ in 0..2 {
            match listener.accept() {
                Ok((stream, addr)) => {
                    info!("new client: {:?}", addr);
                    let _ = stream.set_read_timeout(Some(time::Duration::new(TIMEOUT_SEC, 0)));
                    let _ = stream.set_write_timeout(Some(time::Duration::new(TIMEOUT_SEC, 0)));
                    let mut retval = sgx_status_t::SGX_SUCCESS;
                    let result =
                        unsafe { run_server(enclave.geteid(), &mut retval, stream.as_raw_fd()) };
                    match result {
                        sgx_status_t::SGX_SUCCESS => {
                            info!("client query finished");
                        }
                        e => {
                            error!("client query failed: {}", e);
                        }
                    }
                }
                Err(e) => info!("couldn't get client: {:?}", e),
            }
        }
    });

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
    let withdrawtx = TxEnclaveAux::WithdrawUnbondedStakeTx {
        no_of_outputs: tx0.outputs.len() as TxoIndex,
        witness: witness0,
        payload: TxObfuscated {
            txid: tx0.id(),
            key_from: 0,
            init_vector: [0u8; 12],
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

    ZMQ_SOCKET.with(|socket| {
        info!("sending a TX request");
        let request = EnclaveRequest::new_tx_request(withdrawtx, Some(account), info);
        let req = request.encode();
        socket.send(req, FLAGS).expect("request sending failed");
        let msg = socket
            .recv_bytes(FLAGS)
            .expect("failed to receive a response");
        let resp = EnclaveResponse::decode(&mut msg.as_slice()).expect("enclave tx response");
        info!("received a TX response");
        match resp {
            EnclaveResponse::VerifyTx(Ok(_)) => {
                info!("ok tx response");
            }
            _ => {
                panic!("failed tx response");
            }
        }
        let request2 = EnclaveRequest::CommitBlock {
            app_hash: [0u8; 32], info,
        };
        let req2 = request2.encode();
        socket.send(req2, FLAGS).expect("request sending failed");
        let msg2 = socket
            .recv_bytes(FLAGS)
            .expect("failed to receive a response");
        let resp2 = EnclaveResponse::decode(&mut msg2.as_slice()).expect("enclave commit response");
        info!("received a commit response");
        match resp2 {
            EnclaveResponse::CommitBlock(Ok(_)) => {
                info!("ok commit response");
            }
            _ => {
                panic!("failed commit response");
            }
        }

        thread::sleep(time::Duration::from_secs(10));
        let c = DefaultTransactionObfuscation::new(
            format!("localhost:{}", query_server_port),
            "localhost".to_owned(),
        );
        let txids = vec![*txid];
        let r1 = c.decrypt(
            txids.as_slice(),
            &PrivateKey::deserialize_from(&secret_key[..].to_vec()).expect("private key"),
        );
        match r1 {
            Ok(v) => {
                // TODO: check tx details
                assert_eq!(v.len(), 1, "expected one TX");
            }
            _ => {
                panic!("wrong decryption response");
            }
        }
        let r2 = c.decrypt(txids.as_slice(), &PrivateKey::new().expect("random key"));
        match r2 {
            Ok(v) => {
                assert_eq!(v.len(), 0, "expected no TX");
            }
            _ => {
                panic!("wrong decryption response");
            }
        }
        validation.kill();
    });
}
