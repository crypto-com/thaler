// TODO: remove, as it's not required on newer nightly
mod obfuscate;
mod validate;

#[allow(unused_imports)]
use rs_libc::alloc::*;

use chain_core::tx::TX_AUX_SIZE;
use chain_tx_filter::BlockFilter;
use chain_tx_validation::Error;
use enclave_macro::get_network_id;
use enclave_protocol::codec::{StreamRead, StreamWrite};
use enclave_protocol::{IntraEnclaveRequest, IntraEnclaveResponse, IntraEnclaveResponseOk};
use parity_scale_codec::{Decode, Encode};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
/// FIXME: genesis app hash etc.?
pub const NETWORK_HEX_ID: u8 = get_network_id!();

pub(crate) fn write_response<I: Write>(response: IntraEnclaveResponse, output: &mut I) {
    if let Err(e) = output.write_all(&response.encode()) {
        log::error!("writing response failed: {:?}", e);
    }
}

/// `process_signal` is used in unit tests
/// where the bool is used to stop the thread
/// and sender is used for signalling that response was written
fn handling_loop<I: Read + Write>(
    mut chain_abci: I,
    process_signal: Option<(Arc<AtomicBool>, Sender<()>)>,
) {
    let mut filter = BlockFilter::default();
    let mut request_buf = vec![0u8; 2 * TX_AUX_SIZE];
    log::debug!("waiting for chain-abci requests");
    loop {
        if let Some((ref b, _)) = process_signal {
            if b.load(Ordering::Relaxed) {
                break;
            }
        }
        log::trace!("waiting for chain-abci request");
        match chain_abci.read(&mut request_buf) {
            Ok(n) if n > 0 => match IntraEnclaveRequest::decode(&mut &request_buf.as_slice()[0..n])
            {
                Ok(IntraEnclaveRequest::InitChainCheck(network_id)) => {
                    let response: IntraEnclaveResponse = if network_id == NETWORK_HEX_ID {
                        Ok(IntraEnclaveResponseOk::InitChainCheck)
                    } else {
                        Err(Error::WrongChainHexId)
                    };
                    write_response(response, &mut chain_abci);
                    if let Some((_, ref s)) = process_signal {
                        let _ = s.send(());
                    }
                }
                Ok(IntraEnclaveRequest::ValidateTx { request, tx_inputs }) => {
                    log::debug!("validate tx request");
                    validate::handle_validate_tx(request, tx_inputs, &mut filter, &mut chain_abci);
                    if let Some((_, ref s)) = process_signal {
                        let _ = s.send(());
                    }
                }
                Ok(IntraEnclaveRequest::EndBlock) => {
                    log::debug!("end block request");

                    let maybe_filter = if filter.is_modified() {
                        Some(Box::new(filter.get_raw()))
                    } else {
                        None
                    };
                    filter.reset();
                    let response: IntraEnclaveResponse =
                        Ok(IntraEnclaveResponseOk::EndBlock(maybe_filter));
                    write_response(response, &mut chain_abci);
                    if let Some((_, ref s)) = process_signal {
                        let _ = s.send(());
                    }
                }
                Ok(IntraEnclaveRequest::Encrypt(request)) => {
                    obfuscate::handle_encrypt_request(request, &mut chain_abci);
                    if let Some((_, ref s)) = process_signal {
                        let _ = s.send(());
                    }
                }
                Err(e) => {
                    log::error!("check tx failed: {:?}", e);
                    write_response(Err(Error::EnclaveRejected), &mut chain_abci);
                }
            },
            Ok(_) => {
                // n == 0
                log::trace!("end of stream?");
            }
            Err(e) => {
                log::error!("error reading from chain-abci: {:?}", e);
            }
        }
    }
}

// stream_to_txquery: actually it's UnixStream
pub fn handling_txquery(stream_to_txquery: TcpStream) {
    std::thread::spawn(move || {
        let mut this_stream = stream_to_txquery;
        loop {
            let result = IntraEnclaveRequest::read_from(&this_stream);
            if result.is_err() {
                continue;
            }
            let request_form_txquery = result.expect("handling_txquery get unix-stream");
            match request_form_txquery {
                _ => {
                    log::debug!("handling_txquery unsupported protocol");
                    let reply = IntraEnclaveResponseOk::UnknownRequest;
                    reply.write_to(&this_stream);
                }
            }
        }
    });
}
pub fn entry() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();
    log::info!("Network ID: {:x}", NETWORK_HEX_ID);

    log::info!("Connecting to txquery enclave");
    let stream_to_txquery = TcpStream::connect("stream_to_txquery")?;
    handling_txquery(stream_to_txquery);

    // not really TCP -- stream provided by the runner
    log::info!("Connecting to chain-abci");
    let chain_abci = TcpStream::connect("chain-abci")?;
    handling_loop(chain_abci, None);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_core::common::MerkleTree;
    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::Coin;
    use chain_core::state::account::{
        StakedState, StakedStateAddress, StakedStateOpWitness, WithdrawUnbondedTx,
    };
    use chain_core::state::tendermint::BlockHeight;
    use chain_core::tx::fee::Fee;
    use chain_core::tx::witness::tree::RawXOnlyPubkey;
    use chain_core::tx::witness::EcdsaSignature;
    use chain_core::tx::witness::TxWitness;
    use chain_core::tx::TransactionId;
    use chain_core::tx::{
        data::{
            access::{TxAccess, TxAccessPolicy},
            address::ExtendedAddr,
            attribute::TxAttributes,
            input::{TxoPointer, TxoSize},
            output::TxOut,
            Tx, TxId,
        },
        witness::TxInWitness,
        TxEnclaveAux,
    };
    use chain_core::tx::{PlainTxAux, TxToObfuscate};
    use chain_core::ChainInfo;
    use chain_tx_validation::Error;
    use enclave_protocol::{IntraEnclaveRequest, IntraEnclaveResponseOk, VerifyTxRequest};
    use log::debug;
    use parity_scale_codec::{Decode, Encode};
    use secp256k1::{
        key::PublicKey, key::SecretKey, key::XOnlyPublicKey, schnorrsig::schnorr_sign, Message,
        Secp256k1, Signing,
    };
    use std::io::{Cursor, Read, Result, Write};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    pub struct FakeStream {
        reader: Cursor<Vec<u8>>,
        writer: Cursor<Vec<u8>>,
    }

    impl FakeStream {
        pub fn push_bytes(&mut self, bytes: &[u8]) {
            let avail = self.reader.get_ref().len();
            if self.reader.position() == avail as u64 {
                self.reader = Default::default();
            }
            self.reader.get_mut().extend(bytes.iter().map(|c| *c));
        }

        pub fn pop_written_bytes(&mut self) -> Vec<u8> {
            let mut result = Vec::new();
            std::mem::swap(&mut result, self.writer.get_mut());
            self.writer.set_position(0);
            result
        }
    }

    impl Read for FakeStream {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.reader.read(buf)
        }
    }

    impl Write for FakeStream {
        fn write<'a>(&mut self, buf: &'a [u8]) -> Result<usize> {
            self.writer.write(buf)
        }

        fn flush(&mut self) -> Result<()> {
            self.writer.flush()
        }
    }

    #[derive(Clone, Default)]
    pub struct SyncStream {
        pub stream: Arc<Mutex<FakeStream>>,
    }

    impl Read for SyncStream {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.stream.lock().unwrap().read(buf)
        }
    }

    impl Write for SyncStream {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.stream.lock().unwrap().write(buf)
        }

        fn flush(&mut self) -> Result<()> {
            self.stream.lock().unwrap().flush()
        }
    }

    pub fn push_bytes(stream: Arc<Mutex<FakeStream>>, bytes: &[u8]) {
        stream.lock().unwrap().push_bytes(bytes)
    }

    pub fn pop_written_bytes(stream: Arc<Mutex<FakeStream>>) -> Vec<u8> {
        stream.lock().unwrap().pop_written_bytes()
    }

    fn assert_stop_thread(stop: Arc<AtomicBool>, cond: bool, msg: &'static str) {
        if !cond {
            stop.store(true, Ordering::Relaxed);
            eprintln!("{}", msg);
            assert!(cond, msg);
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
        let mut state = StakedState::default(StakedStateAddress::from(*account_address));
        state.unbonded = Coin::one();
        state
    }
    const TEST_NETWORK_ID: u8 = 0xab;

    // can be run with cargo test --target x86_64-fortanix-unknown-sgx
    #[test]
    fn test_sealing() {
        let (sender, receiver) = std::sync::mpsc::channel();

        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let stream = SyncStream::default();
        let stream2 = stream.stream.clone();
        push_bytes(stream2.clone(), &IntraEnclaveRequest::EndBlock.encode());

        let _handler = std::thread::spawn(move || {
            handling_loop(stream, Some((stop2, sender)));
        });

        let _ = receiver.recv().unwrap();
        let end_b =
            IntraEnclaveResponse::decode(&mut pop_written_bytes(stream2.clone()).as_slice());

        match end_b {
            Ok(Ok(IntraEnclaveResponseOk::EndBlock(b))) => {
                debug!("request filter in the beginning");
                assert_stop_thread(stop.clone(), b.is_none(), "empty filter");
            }
            _ => {
                assert_stop_thread(stop.clone(), false, "filter not returned");
            }
        };

        let secp = secp256k1::SECP256K1;
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let x_public_key = XOnlyPublicKey::from_secret_key(&secp, &secret_key);

        let addr = RedeemAddress::from(&public_key);

        let merkle_tree = MerkleTree::new(vec![RawXOnlyPubkey::from(x_public_key.serialize())]);

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
            no_of_outputs: tx0.outputs.len() as TxoSize,
            witness: witness0.clone(),
            payload: crate::sgx_module::obfuscate::encrypt(
                TxToObfuscate::from(PlainTxAux::WithdrawUnbondedStakeTx(tx0.clone()), *txid)
                    .expect("tx"),
            ),
        };

        let info = ChainInfo {
            min_fee_computed: Fee::new(Coin::zero()),
            chain_hex_id: TEST_NETWORK_ID,
            block_time: 1,
            block_height: BlockHeight::genesis(),
            max_evidence_age: 0,
        };

        let request0 = IntraEnclaveRequest::ValidateTx {
            request: Box::new(VerifyTxRequest {
                tx: withdrawtx,
                account: Some(account),
                info,
            }),
            tx_inputs: None,
        };
        push_bytes(stream2.clone(), &request0.encode());
        let _ = receiver.recv().unwrap();
        let r = IntraEnclaveResponse::decode(&mut pop_written_bytes(stream2.clone()).as_slice());

        let sealedtx = match r {
            Ok(Ok(IntraEnclaveResponseOk::TxWithOutputs { sealed_tx, .. })) => sealed_tx,
            _ => vec![],
        };

        push_bytes(stream2.clone(), &IntraEnclaveRequest::EndBlock.encode());
        let _ = receiver.recv().unwrap();
        let end_b =
            IntraEnclaveResponse::decode(&mut pop_written_bytes(stream2.clone()).as_slice());

        match end_b {
            Ok(Ok(IntraEnclaveResponseOk::EndBlock(b))) => {
                debug!("request filter after one tx");
                assert_stop_thread(
                    stop.clone(),
                    b.unwrap().iter().any(|x| *x != 0u8),
                    "non-empty filter",
                );
            }
            _ => {
                assert_stop_thread(stop.clone(), false, "filter not returned");
            }
        };

        let utxo1 = TxoPointer::new(*txid, 0);
        let mut tx1 = Tx::new();
        tx1.attributes = TxAttributes::new(TEST_NETWORK_ID);
        tx1.add_input(utxo1.clone());
        tx1.add_output(TxOut::new(eaddr.clone(), Coin::one()));
        let txid1 = tx1.id();
        let witness1: TxWitness = vec![TxInWitness::TreeSig(
            schnorr_sign(
                &secp,
                &Message::from_slice(&txid1).unwrap(),
                &secret_key,
                &mut rand::thread_rng(),
            ),
            merkle_tree
                .generate_proof(RawXOnlyPubkey::from(x_public_key.serialize()))
                .unwrap(),
        )]
        .into();
        let transfertx = TxEnclaveAux::TransferTx {
            inputs: tx1.inputs.clone(),
            no_of_outputs: tx1.outputs.len() as TxoSize,
            payload: crate::sgx_module::obfuscate::encrypt(
                TxToObfuscate::from(PlainTxAux::TransferTx(tx1.clone(), witness1.clone()), txid1)
                    .expect("tx"),
            ),
        };

        let request1 = IntraEnclaveRequest::ValidateTx {
            request: Box::new(VerifyTxRequest {
                tx: transfertx,
                account: None,
                info,
            }),
            tx_inputs: Some(vec![sealedtx.clone()]),
        };
        push_bytes(stream2.clone(), &request1.encode());
        let _ = receiver.recv().unwrap();
        let r2 = IntraEnclaveResponse::decode(&mut pop_written_bytes(stream2.clone()).as_slice());

        match r2 {
            Ok(Ok(IntraEnclaveResponseOk::TxWithOutputs { .. })) => {}
            _ => {
                assert_stop_thread(stop.clone(), false, "valid tx not accepted");
            }
        };

        let mut tx2 = Tx::new();
        tx2.attributes = TxAttributes::new(TEST_NETWORK_ID);
        tx2.add_input(utxo1);
        tx2.add_output(TxOut::new(eaddr.clone(), Coin::zero()));
        let txid2 = tx2.id();
        let witness2: TxWitness = vec![TxInWitness::TreeSig(
            schnorr_sign(
                &secp,
                &Message::from_slice(&txid2).unwrap(),
                &secret_key,
                &mut rand::thread_rng(),
            ),
            merkle_tree
                .generate_proof(RawXOnlyPubkey::from(x_public_key.serialize()))
                .unwrap(),
        )]
        .into();
        let transfertx2 = TxEnclaveAux::TransferTx {
            inputs: tx2.inputs.clone(),
            no_of_outputs: tx2.outputs.len() as TxoSize,
            payload: crate::sgx_module::obfuscate::encrypt(
                TxToObfuscate::from(PlainTxAux::TransferTx(tx2.clone(), witness2.clone()), txid2)
                    .expect("tx"),
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
        push_bytes(stream2.clone(), &request2.encode());
        let _ = receiver.recv().unwrap();
        let r3 = IntraEnclaveResponse::decode(&mut pop_written_bytes(stream2.clone()).as_slice());

        match r3 {
            Ok(Err(Error::ZeroCoin)) => {
                debug!("invalid transaction rejected and error code returned");
            }
            Err(_) | Ok(Err(_)) => {
                assert_stop_thread(
                    stop.clone(),
                    false,
                    "something else happened (tx not correctly rejected)",
                );
            }
            Ok(Ok(_)) => {
                assert_stop_thread(
                    stop.clone(),
                    false,
                    "something else happened (invalid tx accepted)",
                );
            }
        };
        stop.store(true, Ordering::Relaxed);
    }
}
