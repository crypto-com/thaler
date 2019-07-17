//! This crate contains messages exchanged in REQ-REP socket between chain-abci app to enclave wrapper server

use chain_core::init::coin::Coin;
use chain_core::state::account::DepositBondTx;
use chain_core::state::account::StakedState;
use chain_core::state::account::StakedStateOpWitness;
use chain_core::state::account::WithdrawUnbondedTx;
use chain_core::tx::data::Tx;
use chain_core::tx::data::TxId;
use chain_core::tx::witness::TxWitness;
use chain_core::tx::{fee::Fee, TxAux};
use chain_core::ChainInfo;
use chain_tx_validation::TxWithOutputs;

use parity_codec::{Decode, Encode, Input, Output};

/// requests sent from chain-abci app to enclave wrapper server
/// FIXME: the variant will be smaller once the TX storage is on the enclave side
#[allow(clippy::large_enum_variant)]
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
        account: Option<StakedState>,
        inputs: Vec<TxWithOutputs>,
        info: ChainInfo,
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
                account,
                inputs,
                info,
            } => {
                dest.push_byte(1);
                tx.encode_to(dest);
                account.encode_to(dest);
                inputs.encode_to(dest);
                info.encode_to(dest);
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
                let account: Option<StakedState> = Option::decode(input)?;
                let inputs: Vec<TxWithOutputs> = Vec::decode(input)?;
                let info = ChainInfo::decode(input)?;
                Some(EnclaveRequest::VerifyTx {
                    tx,
                    account,
                    inputs,
                    info,
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
    /// returns the affected (account) state (if any) and paid fee if the TX is valid
    VerifyTx(Result<(Fee, Option<StakedState>), ()>),
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
            EnclaveResponse::VerifyTx(Err(_)) => {
                dest.push_byte(1);
                dest.push_byte(1);
            }
            EnclaveResponse::VerifyTx(Ok((fee, acc))) => {
                dest.push_byte(1);
                dest.push_byte(0);
                fee.to_coin().encode_to(dest);
                acc.encode_to(dest);
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
                    let acc: Option<StakedState> = Option::decode(input)?;
                    Some(EnclaveResponse::VerifyTx(Ok((Fee::new(fee), acc))))
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
pub enum EncryptionRequest {
    TransferTx(Tx, TxWitness),
    DepositStake(DepositBondTx, TxWitness),
    WithdrawStake(WithdrawUnbondedTx, StakedState, StakedStateOpWitness),
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
