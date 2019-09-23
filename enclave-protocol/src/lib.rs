//! This crate contains messages exchanged in REQ-REP socket between chain-abci app to enclave wrapper server
//! as well as direct communication over TCP-TLS with optional querying enclaves

#![cfg_attr(all(feature = "mesalock_sgx", not(target_env = "sgx")), no_std)]
#![cfg_attr(
    all(target_env = "sgx", target_vendor = "mesalock"),
    feature(rustc_private)
)]

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use std::prelude::v1::{Box, Vec};

use chain_core::common::{H256, H264, H512};
use chain_core::init::coin::Coin;
use chain_core::state::account::DepositBondTx;
use chain_core::state::account::StakedState;
use chain_core::state::account::StakedStateOpWitness;
use chain_core::state::account::WithdrawUnbondedTx;
use chain_core::tx::data::{txid_hash, Tx, TxId};
use chain_core::tx::witness::TxWitness;
use chain_core::tx::{fee::Fee, TxAux};
use chain_core::ChainInfo;
use chain_tx_validation::TxWithOutputs;
use secp256k1::{
    key::{PublicKey, SecretKey},
    Message, Secp256k1, Signature, Signing, Verification,
};

const ENCRYPTION_REQUEST_SIZE: usize = 1024 * 60; // 60 KB
const TOKEN_LEN: usize = 1024;

/// raw sgx_sealed_data_t
type SealedLog = Vec<u8>;

/// tx filter
type TxFilter = [u8; 256];

/// variable length request passed to the tx-validation enclave
#[derive(Encode, Decode)]
pub enum IntraEnclaveRequest {
    ValidateTx {
        request: Box<VerifyTxRequest>,
        tx_inputs: Option<Vec<SealedLog>>,
    },
    EndBlock,
}

impl IntraEnclaveRequest {
    /// helper method to validate basic assumptions
    pub fn is_basic_valid(&self, chain_hex_id: u8) -> Result<(), ()> {
        match self {
            IntraEnclaveRequest::ValidateTx { request, tx_inputs } => {
                if request.info.chain_hex_id != chain_hex_id {
                    return Err(());
                }
                match request.tx {
                    TxAux::DepositStakeTx { .. } => match tx_inputs {
                        Some(ref i) if !i.is_empty() => Ok(()),
                        _ => Err(()),
                    },
                    TxAux::TransferTx { .. } => match tx_inputs {
                        Some(ref i) if !i.is_empty() => Ok(()),
                        _ => Err(()),
                    },
                    TxAux::WithdrawUnbondedStakeTx { .. } => {
                        if request.account.is_some() {
                            Ok(())
                        } else {
                            Err(())
                        }
                    }
                    _ => Err(()),
                }
            }
            _ => Err(()),
        }
    }
}

/// positive response from the enclave
#[derive(Encode, Decode)]
pub enum IntraEnclaveResponseOk {
    /// returns the actual paid fee + transaction data sealed for the local machine for later lookups
    TxWithOutputs { paid_fee: Fee, sealed_tx: SealedLog },
    /// deposit stake pays minimal fee, so this returns the sum of input amounts -- staked stake's bonded balance is added `input_coins-min_fee`
    DepositStakeTx { input_coins: Coin },
    /// transaction filter
    EndBlock(Box<TxFilter>),
}

/// variable length response returned from the tx-validation enclave
pub type IntraEnclaveResponse = Result<IntraEnclaveResponseOk, chain_tx_validation::Error>;

/// request passed from abci
/// TODO: only certain Tx types should be sent -> create a more restrictive datatype instead of checking in `is_basic_valid`
#[derive(Encode, Decode, Clone)]
pub struct VerifyTxRequest {
    pub tx: TxAux,
    pub account: Option<StakedState>,
    pub info: ChainInfo,
}

/// requests sent from chain-abci app to enclave wrapper server
#[derive(Encode, Decode)]
pub enum EnclaveRequest {
    /// a sanity check (sends the chain network ID -- last byte / two hex digits convention)
    /// during InitChain or startup (to test one connected to the correct process)
    /// and the last processed app hash
    /// FIXME: test genesis hash etc.
    CheckChain {
        chain_hex_id: u8,
        last_app_hash: Option<H256>,
    },
    /// "stateless" transaction validation requests (sends transaction + all required information)
    /// double-spent / BitVec check done in chain-abci
    VerifyTx(Box<VerifyTxRequest>),
    /// request to get the block's transaction filter and reset the existing one
    EndBlock,
    /// request to flush/persist storage + store the computed app hash
    /// FIXME: enclave should be able to compute a part of app hash, so send the other parts and check the same app hash was computed
    CommitBlock { app_hash: H256 },
    /// request to get a stored launch token (requested by TDQE -- they should be on the same machine)
    GetCachedLaunchToken { enclave_metaname: Vec<u8> },
    /// request to update the stored launch token (requested by TDQE -- they should be on the same machine)
    UpdateCachedLaunchToken {
        enclave_metaname: Vec<u8>,
        token: Box<[u8; TOKEN_LEN]>,
    },
    /// request to get tx data sealed to "mrsigner" (requested by TDQE -- they should be on the same machine)
    GetSealedTxData { txids: Vec<TxId> },
}

impl EnclaveRequest {
    pub fn new_tx_request(tx: TxAux, account: Option<StakedState>, info: ChainInfo) -> Self {
        EnclaveRequest::VerifyTx(Box::new(VerifyTxRequest { tx, account, info }))
    }
}

/// reponses sent from enclave wrapper server to chain-abci app
/// TODO: better error responses?
#[derive(Encode, Decode)]
pub enum EnclaveResponse {
    /// returns OK if chain_hex_id matches the one embedded in enclave and last_app_hash matches (returns the last app hash if any)
    CheckChain(Result<(), Option<H256>>),
    /// returns the affected (account) state (if any) and paid fee if the TX is valid
    VerifyTx(Result<(Fee, Option<StakedState>), chain_tx_validation::Error>),
    /// returns if the transaction filter for the current block
    EndBlock(Box<TxFilter>),
    /// returns if the data was sucessfully persisted in the enclave's local storage
    CommitBlock(Result<(), ()>),
    /// returns a stored launch token if any
    GetCachedLaunchToken(Result<Option<Box<[u8; TOKEN_LEN]>>, ()>),
    /// indicates whether the update was successful
    UpdateCachedLaunchToken(Result<(), ()>),
    /// returns Some(sealed data payloads) or None (if any TXID was not found / invalid)
    GetSealedTxData(Option<Vec<SealedLog>>),
    /// response if unsupported tx type is sent (e.g. unbondtx) -- TODO: probably unnecessary if there is a data type with a subset of TxAux
    UnsupportedTxType,
    /// response if the enclave failed to parse the request
    UnknownRequest,
}

/// ZMQ flags to be used in the socket connection
pub const FLAGS: i32 = 0;

/// TODO: rethink / should be direct communication with the enclave (rather than via abci+zmq)
#[derive(Encode)]
pub enum EncryptionRequest {
    TransferTx(Tx, TxWitness),
    DepositStake(DepositBondTx, TxWitness),
    WithdrawStake(WithdrawUnbondedTx, StakedState, StakedStateOpWitness),
}

impl Decode for EncryptionRequest {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let size = input
            .remaining_len()?
            .ok_or_else(|| "Unable to calculate size of input")?;

        if size > ENCRYPTION_REQUEST_SIZE {
            return Err("Request too large".into());
        }

        match input.read_byte()? {
            0 => Ok(EncryptionRequest::TransferTx(
                Tx::decode(input)?,
                TxWitness::decode(input)?,
            )),
            1 => Ok(EncryptionRequest::DepositStake(
                DepositBondTx::decode(input)?,
                TxWitness::decode(input)?,
            )),
            2 => Ok(EncryptionRequest::WithdrawStake(
                WithdrawUnbondedTx::decode(input)?,
                StakedState::decode(input)?,
                StakedStateOpWitness::decode(input)?,
            )),
            _ => Err("No such variant in enum EncryptionRequest".into()),
        }
    }
}

/// TODO: rethink / should be direct communication with the enclave (rather than via abci+zmq)
#[derive(Encode, Decode)]
pub struct EncryptionResponse {
    pub tx: TxAux,
}

/// Request in direct communication (over one-side attested TLS) to TDQE
pub struct DecryptionRequestBody {
    /// transactions to check
    pub txs: Vec<TxId>,
    /// requester's public view key
    pub view_key: PublicKey,
    /// 32-byte challenge obtained from TDQE after establishing TLS connection
    pub challenge: H256,
}

impl DecryptionRequestBody {
    pub fn new(txs: Vec<TxId>, view_key: PublicKey, challenge: H256) -> Self {
        DecryptionRequestBody {
            txs,
            view_key,
            challenge,
        }
    }
}

impl Encode for DecryptionRequestBody {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.txs.encode_to(dest);
        self.view_key.serialize().encode_to(dest);
        self.challenge.encode_to(dest);
    }
}

impl Decode for DecryptionRequestBody {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let txs: Vec<TxId> = Vec::decode(input)?;
        let view_key_bytes = H264::decode(input)?;
        let view_key = PublicKey::from_slice(&view_key_bytes)
            .map_err(|_| parity_scale_codec::Error::from("Unable to parse public key"))?;
        let challenge = H256::decode(input)?;
        Ok(DecryptionRequestBody::new(txs, view_key, challenge))
    }
}

/// Signed request in direct communication (over one-side attested TLS) to TDQE
pub struct DecryptionRequest {
    pub body: DecryptionRequestBody,
    pub view_key_sig: Signature,
}

impl DecryptionRequest {
    pub fn new(body: DecryptionRequestBody, view_key_sig: Signature) -> Self {
        DecryptionRequest { body, view_key_sig }
    }

    pub fn create<C: Signing>(
        secp: &Secp256k1<C>,
        txs: Vec<TxId>,
        challenge: H256,
        view_secret_key: &SecretKey,
    ) -> Self {
        let public_key = PublicKey::from_secret_key(&secp, &view_secret_key);
        let body = DecryptionRequestBody::new(txs, public_key, challenge);
        let body_hash = txid_hash(&body.encode());
        let message = Message::from_slice(&body_hash[..]).expect("32 bytes");
        let sig = secp.sign(&message, &view_secret_key);
        DecryptionRequest::new(body, sig)
    }

    pub fn verify<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        challenge: H256,
    ) -> Result<(), secp256k1::Error> {
        if self.body.challenge != challenge {
            return Err(secp256k1::Error::InvalidMessage);
        }
        let body_hash = txid_hash(&self.body.encode());
        let message = Message::from_slice(&body_hash[..]).expect("32 bytes");
        secp.verify(&message, &self.view_key_sig, &self.body.view_key)
    }
}

impl Encode for DecryptionRequest {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        self.body.encode_to(dest);
        self.view_key_sig.serialize_compact().encode_to(dest);
    }
}

impl Decode for DecryptionRequest {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let body: DecryptionRequestBody = DecryptionRequestBody::decode(input)?;
        let view_sig_bytes = H512::decode(input)?;
        let view_key_sig = Signature::from_compact(&view_sig_bytes)
            .map_err(|_| parity_scale_codec::Error::from("Unable to parse signature"))?;
        Ok(DecryptionRequest::new(body, view_key_sig))
    }
}

/// Response in direct communication (over one-side attested TLS) from TDQE
#[derive(Encode, Decode)]
pub struct DecryptionResponse {
    pub txs: Vec<TxWithOutputs>,
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn check_basic_dec_verify() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("Unable to create secret key");
        let req =
            DecryptionRequest::create(&secp, vec![[0u8; 32], [1u8; 32]], [2u8; 32], &secret_key);
        let encoded = req.encode();
        let decoded_req =
            DecryptionRequest::decode(&mut encoded.as_slice()).expect("encode-decode request");
        assert!(decoded_req.verify(&secp, [2u8; 32]).is_ok());
    }

    #[test]
    fn check_wrong_challenge_not_verify() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("Unable to create secret key");
        let req =
            DecryptionRequest::create(&secp, vec![[0u8; 32], [1u8; 32]], [2u8; 32], &secret_key);
        assert!(req.verify(&secp, [0u8; 32]).is_err());
    }
}
