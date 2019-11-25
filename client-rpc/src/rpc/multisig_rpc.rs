use hex::{decode, encode};
use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use secstr::SecUtf8;

use chain_core::common::{H256, HASH_SIZE_256};
use chain_core::tx::data::Tx;
use client_common::{Error, ErrorKind, PublicKey, Result as CommonResult, ResultExt};
use client_core::{MultiSigWalletClient, WalletClient};

use crate::server::{to_rpc_error, WalletRequest};

#[rpc]
pub trait MultiSigRpc: Send + Sync {
    #[rpc(name = "multiSig_createAddress")]
    fn create_address(
        &self,
        request: WalletRequest,
        public_keys: Vec<String>,
        self_public_key: String,
        required_signatures: usize,
    ) -> Result<String>;

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

    #[rpc(name = "multiSig_broadcastWithSignature")]
    fn broadcast_with_signature(
        &self,
        request: WalletRequest,
        session_id: String,
        unsigned_transaction: Tx,
    ) -> Result<String>;
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
    fn create_address(
        &self,
        request: WalletRequest,
        public_keys: Vec<String>,
        self_public_key: String,
        required_signatures: usize,
    ) -> Result<String> {
        let public_keys = parse_public_keys(public_keys).map_err(to_rpc_error)?;
        let self_public_key = parse_public_key(self_public_key).map_err(to_rpc_error)?;
        let extended_address = self
            .client
            .new_multisig_transfer_address(
                &request.name,
                &request.passphrase,
                public_keys,
                self_public_key,
                required_signatures,
            )
            .map_err(to_rpc_error)?;

        Ok(extended_address.to_string())
    }

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

    fn broadcast_with_signature(
        &self,
        request: WalletRequest,
        session_id: String,
        unsigned_transaction: Tx,
    ) -> Result<String> {
        let session_id = parse_hash_256(session_id).map_err(to_rpc_error)?;

        let tx_aux = self
            .client
            .transaction(
                &request.name,
                &session_id,
                &request.passphrase,
                unsigned_transaction,
            )
            .map_err(to_rpc_error)?;

        self.client
            .broadcast_transaction(&tx_aux)
            .map(|result| result.data.to_string())
            .map_err(to_rpc_error)
    }
}

fn serialize_hash_256(hash: H256) -> String {
    encode(&hash)
}

fn parse_hash_256(hash: String) -> CommonResult<H256> {
    let array = decode(&hash).chain(|| {
        (
            ErrorKind::DeserializationError,
            format!("({}) is not a valid hex string", hash),
        )
    })?;

    if array.len() != HASH_SIZE_256 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("({}) should be a hex string of 32 bytes", hash),
        ));
    }

    let mut new_hash: H256 = [0; HASH_SIZE_256];
    new_hash.copy_from_slice(&array);

    Ok(new_hash)
}

fn serialize_public_key(public_key: PublicKey) -> String {
    encode(&public_key.serialize())
}

fn parse_public_keys(public_keys: Vec<String>) -> CommonResult<Vec<PublicKey>> {
    public_keys
        .into_iter()
        .map(parse_public_key)
        .collect::<CommonResult<Vec<PublicKey>>>()
}

fn parse_public_key(public_key: String) -> CommonResult<PublicKey> {
    let array = decode(&public_key).chain(|| {
        (
            ErrorKind::DeserializationError,
            format!("Unable to deserialize public key ({})", public_key),
        )
    })?;
    PublicKey::deserialize_from(&array)
}

#[cfg(test)]
mod test {
    use super::*;
    use secstr::SecUtf8;

    use chain_core::init::coin::CoinError;
    use chain_core::tx::data::TxId;
    use chain_core::tx::fee::{Fee, FeeAlgorithm};
    use chain_core::tx::TxAux;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::lite;
    use client_common::tendermint::types::*;
    use client_common::tendermint::Client;
    use client_common::{PrivateKey, Result as CommonResult, SignedTransaction, Transaction};
    use client_core::signer::WalletSignerManager;
    use client_core::transaction_builder::DefaultWalletTransactionBuilder;
    use client_core::types::WalletKind;
    use client_core::wallet::DefaultWalletClient;
    use client_core::TransactionObfuscation;

    #[test]
    fn create_address_should_return_bech32_multisig_address() {
        let multisig_rpc = setup_multisig_rpc();

        let name = "Default";
        let passphrase = SecUtf8::from("123456");

        multisig_rpc
            .client
            .new_wallet(name, &passphrase, WalletKind::Basic)
            .unwrap();

        let wallet_public_key = multisig_rpc
            .client
            .new_public_key(name, &passphrase, None)
            .unwrap();
        let public_keys = vec![
            wallet_public_key.clone(),
            PublicKey::from(&PrivateKey::new().unwrap()),
            PublicKey::from(&PrivateKey::new().unwrap()),
        ];
        let public_keys = public_keys
            .into_iter()
            .map(|public_key| format!("{}", public_key))
            .collect::<Vec<String>>();

        let multisig_address = multisig_rpc
            .create_address(
                create_wallet_request("Default", "123456"),
                public_keys,
                format!("{}", wallet_public_key),
                2,
            )
            .unwrap();

        assert!(
            multisig_address.starts_with("dcro"),
            "Return address should be bech32"
        );
    }

    fn make_test_wallet_client(storage: MemoryStorage) -> TestWalletClient {
        let signer_manager = WalletSignerManager::new(storage.clone());
        let transaction_builder = DefaultWalletTransactionBuilder::new(
            signer_manager,
            ZeroFeeAlgorithm::default(),
            MockTransactionCipher,
        );
        DefaultWalletClient::new(storage, MockRpcClient, transaction_builder)
    }

    fn setup_multisig_rpc() -> MultiSigRpcImpl<TestWalletClient> {
        let storage = MemoryStorage::default();

        let wallet_client = make_test_wallet_client(storage.clone());

        MultiSigRpcImpl::new(wallet_client)
    }

    fn create_wallet_request(name: &str, passphrase: &str) -> WalletRequest {
        WalletRequest {
            name: name.to_owned(),
            passphrase: SecUtf8::from(passphrase),
        }
    }

    #[derive(Default, Clone)]
    pub struct ZeroFeeAlgorithm;

    impl FeeAlgorithm for ZeroFeeAlgorithm {
        fn calculate_fee(&self, _num_bytes: usize) -> std::result::Result<Fee, CoinError> {
            unreachable!("calculate_fee")
        }

        fn calculate_for_txaux(&self, _txaux: &TxAux) -> std::result::Result<Fee, CoinError> {
            unreachable!("calculate_for_txaux")
        }
    }

    #[derive(Debug, Clone)]
    struct MockTransactionCipher;

    impl TransactionObfuscation for MockTransactionCipher {
        fn decrypt(
            &self,
            _transaction_ids: &[TxId],
            _private_key: &PrivateKey,
        ) -> CommonResult<Vec<Transaction>> {
            unreachable!("decrypt")
        }

        fn encrypt(&self, _transaction: SignedTransaction) -> CommonResult<TxAux> {
            unreachable!("encrypt")
        }
    }

    type TestWalletTransactionBuilder =
        DefaultWalletTransactionBuilder<MemoryStorage, ZeroFeeAlgorithm, MockTransactionCipher>;
    type TestWalletClient =
        DefaultWalletClient<MemoryStorage, MockRpcClient, TestWalletTransactionBuilder>;

    #[derive(Default)]
    pub struct MockRpcClient;

    impl Client for MockRpcClient {
        fn genesis(&self) -> CommonResult<Genesis> {
            unreachable!("genesis")
        }

        fn status(&self) -> CommonResult<Status> {
            unreachable!("status")
        }

        fn block(&self, _height: u64) -> CommonResult<Block> {
            unreachable!("block")
        }

        fn block_batch<'a, T: Iterator<Item = &'a u64>>(
            &self,
            _heights: T,
        ) -> CommonResult<Vec<Block>> {
            unreachable!("block_batch")
        }

        fn block_results(&self, _height: u64) -> CommonResult<BlockResults> {
            unreachable!("block_results")
        }

        fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
            &self,
            _heights: T,
        ) -> CommonResult<Vec<BlockResults>> {
            unreachable!("block_results_batch")
        }

        fn block_batch_verified<'a, T: Clone + Iterator<Item = &'a u64>>(
            &self,
            _state: lite::TrustedState,
            _heights: T,
        ) -> CommonResult<(Vec<Block>, lite::TrustedState)> {
            unreachable!()
        }

        fn broadcast_transaction(&self, _transaction: &[u8]) -> CommonResult<BroadcastTxResponse> {
            unreachable!("broadcast_transaction")
        }

        fn query(&self, _path: &str, _data: &[u8]) -> CommonResult<AbciQuery> {
            unreachable!("query")
        }
    }
}
