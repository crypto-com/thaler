//! This crate contains messages exchanged in REQ-REP socket between chain-abci app to enclave wrapper server
//! as well as direct communication over TCP-TLS with optional querying enclaves

#![cfg_attr(all(feature = "mesalock_sgx", not(target_env = "sgx")), no_std)]
#![cfg_attr(
    all(target_env = "sgx", target_vendor = "mesalock"),
    feature(rustc_private)
)]

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
extern crate sgx_tstd as std;
pub mod error;

use error::Error as PError;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use std::prelude::v1::{Box, Vec};

use chain_core::common::{H256, H264, H512};
use chain_core::init::coin::Coin;
use chain_core::state::account::DepositBondTx;
use chain_core::state::account::StakedState;
use chain_core::state::account::StakedStateOpWitness;
use chain_core::state::account::WithdrawUnbondedTx;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::{txid_hash, Tx, TxId};
use chain_core::tx::witness::TxWitness;
use chain_core::tx::TxObfuscated;
use chain_core::tx::{fee::Fee, TxEnclaveAux};
use chain_core::ChainInfo;
use chain_tx_validation::TxWithOutputs;
use secp256k1::{
    key::{PublicKey, SecretKey},
    Message, Secp256k1, Signature, Signing, Verification,
};

pub const ENCRYPTION_REQUEST_SIZE: usize = 1024 * 60; // 60 KB

/// raw sgx_sealed_data_t
pub type SealedLog = Vec<u8>;

/// tx filter
type TxFilter = [u8; 256];

/// Internal encryption request
#[derive(Encode, Decode)]
pub struct IntraEncryptRequest {
    /// transaction ID
    pub txid: TxId,
    /// EncryptionRequest
    pub sealed_enc_request: SealedLog,
    /// transaction inputs (if any)
    pub tx_inputs: Option<Vec<SealedLog>>,
    /// last chain info
    pub info: ChainInfo,
}

/// variable length request passed to the tx-validation enclave
#[derive(Encode, Decode)]
pub enum IntraEnclaveRequest {
    ValidateTx {
        request: Box<VerifyTxRequest>,
        tx_inputs: Option<Vec<SealedLog>>,
    },
    EndBlock,
    Encrypt(Box<IntraEncryptRequest>),
}

impl IntraEnclaveRequest {
    pub fn new_validate_transfer(
        tx: TxEnclaveAux,
        info: ChainInfo,
        tx_inputs: Vec<SealedLog>,
    ) -> Self {
        Self::ValidateTx {
            tx_inputs: Some(tx_inputs),
            request: Box::new(VerifyTxRequest {
                tx,
                account: None,
                info,
            }),
        }
    }

    pub fn new_validate_deposit(
        tx: TxEnclaveAux,
        info: ChainInfo,
        account: Option<StakedState>,
        tx_inputs: Vec<SealedLog>,
    ) -> Self {
        Self::ValidateTx {
            tx_inputs: Some(tx_inputs),
            request: Box::new(VerifyTxRequest { tx, account, info }),
        }
    }

    pub fn new_validate_withdraw(tx: TxEnclaveAux, info: ChainInfo, account: StakedState) -> Self {
        Self::ValidateTx {
            tx_inputs: None,
            request: Box::new(VerifyTxRequest {
                tx,
                account: Some(account),
                info,
            }),
        }
    }
}

/// helper method to validate basic assumptions
pub fn is_basic_valid_tx_request(
    request: &VerifyTxRequest,
    tx_inputs: &Option<Vec<SealedLog>>,
    chain_hex_id: u8,
) -> Result<(), PError> {
    if request.info.chain_hex_id != chain_hex_id {
        return Err(PError::HexIdMisMatch);
    }
    match request.tx {
        TxEnclaveAux::DepositStakeTx { .. } => match tx_inputs {
            Some(ref i) if !i.is_empty() => Ok(()),
            _ => Err(PError::EmptySealedLog),
        },
        TxEnclaveAux::TransferTx { .. } => match tx_inputs {
            Some(ref i) if !i.is_empty() => Ok(()),
            _ => Err(PError::EmptySealedLog),
        },
        TxEnclaveAux::WithdrawUnbondedStakeTx { .. } => {
            if request.account.is_some() {
                Ok(())
            } else {
                Err(PError::EmptyRequestAccount)
            }
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
    EndBlock(Option<Box<TxFilter>>),
    /// encryption response
    Encrypt(TxObfuscated),
}

/// variable length response returned from the tx-validation enclave
pub type IntraEnclaveResponse = Result<IntraEnclaveResponseOk, chain_tx_validation::Error>;

/// request passed from abci
/// TODO: only certain Tx types should be sent -> create a more restrictive datatype instead of checking in `is_basic_valid`
#[derive(Encode, Decode, Clone)]
pub struct VerifyTxRequest {
    pub tx: TxEnclaveAux,
    pub account: Option<StakedState>,
    pub info: ChainInfo,
}

/// TQE's encryption request
#[derive(Encode, Decode)]
pub struct QueryEncryptRequest {
    /// transaction ID
    pub txid: TxId,
    /// EncryptionRequest sealed by TQE to "mrsigner"
    pub sealed_enc_request: SealedLog,
    /// transaction inputs (if any)
    pub tx_inputs: Option<Vec<TxoPointer>>,
}

/// requests sent from tx-query to chain-abci tx validation enclave app wrapper
#[derive(Encode, Decode)]
pub enum EnclaveRequest {
    /// request to get tx data sealed to "mrsigner" (requested by TQE -- they should be on the same machine)
    GetSealedTxData { txids: Vec<TxId> },
    /// request to encrypt tx by the current key (requested by TQE -- they should be on the same machine)
    EncryptTx(Box<QueryEncryptRequest>),
}

pub type VerifyOk = (Fee, Option<StakedState>, Option<Box<SealedLog>>);

/// responses sent from chain-abci tx validation enclave app wrapper to tx-query
/// TODO: better error responses?
#[derive(Encode, Decode)]
pub enum EnclaveResponse {
    /// returns Some(sealed data payloads) or None (if any TXID was not found / invalid)
    GetSealedTxData(Option<Vec<SealedLog>>),
    /// returns Ok(encrypted tx payload) if Tx was valid
    EncryptTx(Result<TxObfuscated, chain_tx_validation::Error>),
    /// response if the enclave failed to parse the request
    UnknownRequest,
}

/// ZMQ flags to be used in the socket connection
pub const FLAGS: i32 = 0;

/// initial request sent by client to TQE
#[derive(Encode, Decode)]
pub enum TxQueryInitRequest {
    Encrypt(Box<EncryptionRequest>),
    DecryptChallenge,
}

/// initial response by TQE
#[derive(Encode, Decode)]
pub enum TxQueryInitResponse {
    Encrypt(EncryptionResponse),
    DecryptChallenge(H256),
}

/// Sent initially in TxQueryInitRequest
/// TODO: remove/deprecate the abci mock
#[derive(Encode)]
pub enum EncryptionRequest {
    TransferTx(Tx, TxWitness),
    DepositStake(DepositBondTx, TxWitness),
    WithdrawStake(WithdrawUnbondedTx, Box<StakedState>, StakedStateOpWitness),
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
                Box::new(StakedState::decode(input)?),
                StakedStateOpWitness::decode(input)?,
            )),
            _ => Err("No such variant in enum EncryptionRequest".into()),
        }
    }
}

/// Response from TQE
#[derive(Encode, Decode)]
pub struct EncryptionResponse {
    pub resp: Result<TxEnclaveAux, chain_tx_validation::Error>,
}

/// Request in direct communication (over one-side attested TLS) to TQE
pub struct DecryptionRequestBody {
    /// transactions to check
    pub txs: Vec<TxId>,
    /// requester's public view key
    pub view_key: PublicKey,
    /// 32-byte challenge obtained from TQE after establishing TLS connection
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

/// Signed request in direct communication (over one-side attested TLS) to TQE
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

/// Response in direct communication (over one-side attested TLS) from TQE
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
