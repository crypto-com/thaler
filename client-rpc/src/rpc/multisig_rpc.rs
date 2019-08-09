use failure::ResultExt;
use hex::{decode, encode};
use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use secstr::SecUtf8;

use chain_core::common::{H256, HASH_SIZE_256};
use client_common::{Error, ErrorKind, PublicKey, Result as CommonResult};
use client_core::{MultiSigWalletClient, WalletClient};

use crate::server::{to_rpc_error, WalletRequest};

#[rpc]
pub trait MultiSigRpc: Send + Sync {
    #[rpc(name = "multiSig_newSession")]
    fn new_session(
        &self,
        request: WalletRequest,
        message: String,
        signer_public_keys: Vec<String>,
        self_public_key: String,
    ) -> Result<String>;

    #[rpc(name = "multiSig_nonceCommitment")]
    fn nonce_commitment(&self, session_id: String, passphrase: SecUtf8) -> Result<String>;

    #[rpc(name = "multiSig_addNonceCommitment")]
    fn add_nonce_commitment(
        &self,
        session_id: String,
        passphrase: SecUtf8,
        nonce_commitment: String,
        public_key: String,
    ) -> Result<()>;

    #[rpc(name = "multiSig_nonce")]
    fn nonce(&self, session_id: String, passphrase: SecUtf8) -> Result<String>;

    #[rpc(name = "multiSig_addNonce")]
    fn add_nonce(
        &self,
        session_id: String,
        passphrase: SecUtf8,
        nonce: String,
        public_key: String,
    ) -> Result<()>;

    #[rpc(name = "multiSig_partialSign")]
    fn partial_signature(&self, session_id: String, passphrase: SecUtf8) -> Result<String>;

    #[rpc(name = "multiSig_addPartialSignature")]
    fn add_partial_signature(
        &self,
        session_id: String,
        passphrase: SecUtf8,
        partial_signature: String,
        public_key: String,
    ) -> Result<()>;

    #[rpc(name = "multiSig_signature")]
    fn signature(&self, session_id: String, passphrase: SecUtf8) -> Result<String>;
}

pub struct MultiSigRpcImpl<T>
where
    T: WalletClient,
{
    client: T,
}

impl<T> MultiSigRpcImpl<T>
where
    T: WalletClient,
{
    pub fn new(client: T) -> Self {
        MultiSigRpcImpl { client }
    }
}

impl<T> MultiSigRpc for MultiSigRpcImpl<T>
where
    T: WalletClient + MultiSigWalletClient + 'static,
{
    fn new_session(
        &self,
        request: WalletRequest,
        message: String,
        signer_public_keys: Vec<String>,
        self_public_key: String,
    ) -> Result<String> {
        let message = parse_hash_256(message).map_err(to_rpc_error)?;
        let signer_public_keys = signer_public_keys
            .into_iter()
            .map(parse_public_key)
            .collect::<CommonResult<Vec<PublicKey>>>()
            .map_err(to_rpc_error)?;
        let self_public_key = parse_public_key(self_public_key).map_err(to_rpc_error)?;

        self.client
            .new_multi_sig_session(
                &request.name,
                &request.passphrase,
                message,
                signer_public_keys,
                self_public_key,
            )
            .map(serialize_hash_256)
            .map_err(to_rpc_error)
    }

    fn nonce_commitment(&self, session_id: String, passphrase: SecUtf8) -> Result<String> {
        let session_id = parse_hash_256(session_id).map_err(to_rpc_error)?;

        self.client
            .nonce_commitment(&session_id, &passphrase)
            .map(serialize_hash_256)
            .map_err(to_rpc_error)
    }

    fn add_nonce_commitment(
        &self,
        session_id: String,
        passphrase: SecUtf8,
        nonce_commitment: String,
        public_key: String,
    ) -> Result<()> {
        let session_id = parse_hash_256(session_id).map_err(to_rpc_error)?;
        let nonce_commitment = parse_hash_256(nonce_commitment).map_err(to_rpc_error)?;
        let public_key = parse_public_key(public_key).map_err(to_rpc_error)?;

        self.client
            .add_nonce_commitment(&session_id, &passphrase, nonce_commitment, &public_key)
            .map_err(to_rpc_error)
    }

    fn nonce(&self, session_id: String, passphrase: SecUtf8) -> Result<String> {
        let session_id = parse_hash_256(session_id).map_err(to_rpc_error)?;

        self.client
            .nonce(&session_id, &passphrase)
            .map(serialize_public_key)
            .map_err(to_rpc_error)
    }

    fn add_nonce(
        &self,
        session_id: String,
        passphrase: SecUtf8,
        nonce: String,
        public_key: String,
    ) -> Result<()> {
        let session_id = parse_hash_256(session_id).map_err(to_rpc_error)?;
        let nonce = parse_public_key(nonce).map_err(to_rpc_error)?;
        let public_key = parse_public_key(public_key).map_err(to_rpc_error)?;

        self.client
            .add_nonce(&session_id, &passphrase, &nonce, &public_key)
            .map_err(to_rpc_error)
    }

    fn partial_signature(&self, session_id: String, passphrase: SecUtf8) -> Result<String> {
        let session_id = parse_hash_256(session_id).map_err(to_rpc_error)?;

        self.client
            .partial_signature(&session_id, &passphrase)
            .map(serialize_hash_256)
            .map_err(to_rpc_error)
    }

    fn add_partial_signature(
        &self,
        session_id: String,
        passphrase: SecUtf8,
        partial_signature: String,
        public_key: String,
    ) -> Result<()> {
        let session_id = parse_hash_256(session_id).map_err(to_rpc_error)?;
        let partial_signature = parse_hash_256(partial_signature).map_err(to_rpc_error)?;
        let public_key = parse_public_key(public_key).map_err(to_rpc_error)?;

        self.client
            .add_partial_signature(&session_id, &passphrase, partial_signature, &public_key)
            .map_err(to_rpc_error)
    }

    fn signature(&self, session_id: String, passphrase: SecUtf8) -> Result<String> {
        let session_id = parse_hash_256(session_id).map_err(to_rpc_error)?;

        self.client
            .signature(&session_id, &passphrase)
            .map(|sig| sig.to_string())
            .map_err(to_rpc_error)
    }
}

fn serialize_hash_256(hash: H256) -> String {
    encode(&hash)
}

fn parse_hash_256(hash: String) -> CommonResult<H256> {
    let array = decode(hash).context(ErrorKind::DeserializationError)?;

    if array.len() != HASH_SIZE_256 {
        return Err(Error::from(ErrorKind::DeserializationError));
    }

    let mut new_hash: H256 = [0; HASH_SIZE_256];
    new_hash.copy_from_slice(&array);

    Ok(new_hash)
}

fn serialize_public_key(public_key: PublicKey) -> String {
    encode(&public_key.serialize())
}

fn parse_public_key(public_key: String) -> CommonResult<PublicKey> {
    let array = decode(public_key).context(ErrorKind::DeserializationError)?;
    PublicKey::deserialize_from(&array)
}
