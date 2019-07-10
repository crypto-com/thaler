//! This crate contains messages exchanged in REQ-REP socket between chain-abci app to enclave wrapper server

use chain_core::common::Timespec;
use chain_core::init::coin::Coin;
use chain_core::tx::data::Tx;
use chain_core::tx::data::TxId;
use chain_core::tx::{fee::Fee, PlainTxAux, TxAux};
use chain_tx_validation::TxWithOutputs;

use parity_codec::{Decode, Encode, Input, Output};

/// requests sent from chain-abci app to enclave wrapper server
pub enum EnclaveRequest {
    /// a sanity check (sends the chain network ID -- last byte / two hex digits convention)
    /// during InitChain or startup (to test one connected to the correct process)
    /// FIXME: test genesis hash etc.
    CheckChain { chain_hex_id: u8 },
    /// "stateless" transaction validation requests (sends transaction + all required information)
    /// double-spent / BitVec check done in chain-abci
    /// FIXME: when sealing is done, sealed TX would probably be stored by enclave server, hence this should send TxPointers instead
    /// FIXME: only certain Tx types should be sent -> create a datatype / enum for it (probably after encrypted Tx data types)
    VerifyTx {
        tx: TxAux,
        inputs: Vec<TxWithOutputs>,
        min_fee_computed: Fee,
        previous_block_time: Timespec,
        unbonding_period: u32,
    },
}

impl Encode for EnclaveRequest {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        match self {
            EnclaveRequest::CheckChain { chain_hex_id } => {
                dest.push_byte(0);
                dest.push_byte(*chain_hex_id);
            }
            EnclaveRequest::VerifyTx {
                tx,
                inputs,
                min_fee_computed,
                previous_block_time,
                unbonding_period,
            } => {
                dest.push_byte(1);
                tx.encode_to(dest);
                inputs.encode_to(dest);
                min_fee_computed.to_coin().encode_to(dest);
                previous_block_time.encode_to(dest);
                unbonding_period.encode_to(dest);
            }
        }
    }
}

impl Decode for EnclaveRequest {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        let tag = input.read_byte()?;
        match tag {
            0 => {
                let chain_hex_id: u8 = input.read_byte()?;
                Some(EnclaveRequest::CheckChain { chain_hex_id })
            }
            1 => {
                let tx = TxAux::decode(input)?;
                let inputs: Vec<TxWithOutputs> = Vec::decode(input)?;
                let fee = Coin::decode(input)?;
                let previous_block_time = Timespec::decode(input)?;
                let unbonding_period = u32::decode(input)?;
                Some(EnclaveRequest::VerifyTx {
                    tx,
                    inputs,
                    min_fee_computed: Fee::new(fee),
                    previous_block_time,
                    unbonding_period,
                })
            }
            _ => None,
        }
    }
}

/// reponses sent from enclave wrapper server to chain-abci app
/// TODO: better error responses?
pub enum EnclaveResponse {
    /// returns OK if chain_hex_id matches the one embedded in enclave
    CheckChain(Result<(), ()>),
    /// returns the paid fee if the TX is valid
    VerifyTx(Result<Fee, ()>),
    /// response if unsupported tx type is sent (e.g. unbondtx) -- TODO: probably unnecessary if there is a data type with a subset of TxAux
    UnsupportedTxType,
    /// response if the enclave failed to parse the request
    UnknownRequest,
}

impl Encode for EnclaveResponse {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        match self {
            EnclaveResponse::CheckChain(result) => {
                dest.push_byte(0);
                if result.is_ok() {
                    dest.push_byte(0);
                } else {
                    dest.push_byte(1);
                }
            }
            EnclaveResponse::VerifyTx(result) => {
                dest.push_byte(1);
                if result.is_ok() {
                    dest.push_byte(0);
                    result.unwrap().to_coin().encode_to(dest);
                } else {
                    dest.push_byte(1);
                }
            }
            EnclaveResponse::UnsupportedTxType => {
                dest.push_byte(2);
            }
            EnclaveResponse::UnknownRequest => {
                dest.push_byte(3);
            }
        }
    }
}

impl Decode for EnclaveResponse {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        let tag = input.read_byte()?;
        match tag {
            0 => {
                let result: u8 = input.read_byte()?;
                if result == 0 {
                    Some(EnclaveResponse::CheckChain(Ok(())))
                } else {
                    Some(EnclaveResponse::CheckChain(Err(())))
                }
            }
            1 => {
                let result: u8 = input.read_byte()?;
                if result == 0 {
                    let fee = Coin::decode(input)?;
                    Some(EnclaveResponse::VerifyTx(Ok(Fee::new(fee))))
                } else {
                    Some(EnclaveResponse::VerifyTx(Err(())))
                }
            }
            2 => Some(EnclaveResponse::UnsupportedTxType),
            3 => Some(EnclaveResponse::UnknownRequest),
            _ => None,
        }
    }
}

/// ZMQ flags to be used in the socket connection
pub const FLAGS: i32 = 0;

/// TODO: rethink / should be direct communication with the enclave (rather than via abci+zmq)
#[derive(Encode, Decode)]
pub struct EncryptionRequest {
    pub tx: PlainTxAux,
}

/// TODO: rethink / should be direct communication with the enclave (rather than via abci+zmq)
#[derive(Encode, Decode)]
pub struct EncryptionResponse {
    pub tx: TxAux,
}

/// TODO: rethink / should be direct communication with the enclave (rather than via abci+zmq)
/// TODO: limit txs size + no of view keys in each TX?
#[derive(Encode, Decode)]
pub struct DecryptionRequestBody {
    pub txs: Vec<TxId>,
}

/// TODO: rethink / should be direct communication with the enclave (rather than via abci+zmq)
#[derive(Encode, Decode)]
pub struct DecryptionRequest {
    pub body: DecryptionRequestBody,
    /// ecdsa on the body in compact form?
    pub view_key_sig: [u8; 64],
}

/// TODO: rethink / should be direct communication with the enclave (rather than via abci+zmq)
#[derive(Encode, Decode)]
pub struct DecryptionResponse {
    pub txs: Vec<Tx>,
}
