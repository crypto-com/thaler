use failure::ResultExt;
use hex::{decode, encode};
use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};

use chain_core::common::{H256, HASH_SIZE_256};

use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use client_common::balance::BalanceChange;
use client_common::{Error, ErrorKind, PublicKey, Result as CommonResult};
use client_core::{MultiSigWalletClient, WalletClient};

use crate::server::{rpc_error_from_string, to_rpc_error};

#[derive(Serialize, Deserialize)]
pub struct RowTx {
    kind: String,
    transaction_id: String,
    address: String,
    height: String,
    time: String,
    amount: String,
}
use chain_core::state::account::{StakedStateAddress, StakedStateOpAttributes};

use chain_core::tx::data::input::TxoPointer;

use client_network::network_ops::NetworkOpsClient;

use std::str::FromStr;

#[rpc]
pub trait ClientRpc {
    #[rpc(name = "wallet_addresses")]
    fn addresses(&self, request: WalletRequest) -> Result<Vec<String>>;

    #[rpc(name = "wallet_balance")]
    fn balance(&self, request: WalletRequest) -> Result<Coin>;

    #[rpc(name = "wallet_create")]
    fn create(&self, request: WalletRequest) -> Result<String>;

    #[rpc(name = "wallet_list")]
    fn list(&self) -> Result<Vec<String>>;

    #[rpc(name = "wallet_sendtoaddress")]
    fn sendtoaddress(&self, request: WalletRequest, to_address: String, amount: u64) -> Result<()>;

    #[rpc(name = "sync")]
    fn sync(&self) -> Result<()>;

    #[rpc(name = "sync_all")]
    fn sync_all(&self) -> Result<()>;

    #[rpc(name = "wallet_transactions")]
    fn transactions(&self, request: WalletRequest) -> Result<Vec<RowTx>>;

    #[rpc(name = "multi_sig_new_session")]
    fn new_multi_sig_session(
        &self,
        request: WalletRequest,
        message: String,
        signer_public_keys: Vec<String>,
        self_public_key: String,
    ) -> Result<String>;

    #[rpc(name = "multi_sig_nonce_commitment")]
    fn nonce_commitment(&self, session_id: String, passphrase: SecUtf8) -> Result<String>;

    #[rpc(name = "multi_sig_add_nonce_commitment")]
    fn add_nonce_commitment(
        &self,
        session_id: String,
        passphrase: SecUtf8,
        nonce_commitment: String,
        public_key: String,
    ) -> Result<()>;

    #[rpc(name = "multi_sig_nonce")]
    fn nonce(&self, session_id: String, passphrase: SecUtf8) -> Result<String>;

    #[rpc(name = "multi_sig_add_nonce")]
    fn add_nonce(
        &self,
        session_id: String,
        passphrase: SecUtf8,
        nonce: String,
        public_key: String,
    ) -> Result<()>;

    #[rpc(name = "multi_sig_partial_signature")]
    fn partial_signature(&self, session_id: String, passphrase: SecUtf8) -> Result<String>;

    #[rpc(name = "multi_sig_add_partial_signature")]
    fn add_partial_signature(
        &self,
        session_id: String,
        passphrase: SecUtf8,
        partial_signature: String,
        public_key: String,
    ) -> Result<()>;

    #[rpc(name = "multi_sig_signature")]
    fn signature(&self, session_id: String, passphrase: SecUtf8) -> Result<String>;

    #[rpc(name = "create_deposit_bonded_stake_transaction")]
    fn create_deposit_bonded_stake_transaction(&self, request: ClientRequest) -> Result<String>;

    #[rpc(name = "create_unbond_stake_transaction")]
    fn create_unbond_stake_transaction(
        &self,
        request: CreateUnbondStakeTransactionRequest,
    ) -> Result<String>;

    #[rpc(name = "create_withdraw_all_unbonded_stake_transaction")]
    fn create_withdraw_all_unbonded_stake_transaction(
        &self,
        request: ClientRequest,
    ) -> Result<String>;
}

pub struct ClientRpcImpl<T: WalletClient + Send + Sync, S: NetworkOpsClient + Send + Sync> {
    client: T,
    ops_client: S,
    network_id: u8,
}

impl<T, S> ClientRpcImpl<T, S>
where
    T: WalletClient + Send + Sync,
    S: NetworkOpsClient + Send + Sync,
{
    pub fn new(client: T, ops_client: S, network_id: u8) -> Self {
        ClientRpcImpl {
            client,
            ops_client,
            network_id,
        }
    }
}

impl<T, S> ClientRpc for ClientRpcImpl<T, S>
where
    T: WalletClient + MultiSigWalletClient + Send + Sync + 'static,
    S: NetworkOpsClient + Send + Sync + 'static,
{
    fn addresses(&self, request: WalletRequest) -> Result<Vec<String>> {
        // TODO: Currently, it only returns staking addresses
        match self
            .client
            .staking_addresses(&request.name, &request.passphrase)
        {
            Ok(addresses) => addresses
                .iter()
                .map(|address| Ok(address.to_string()))
                .collect(),
            Err(e) => Err(to_rpc_error(e)),
        }
    }

    fn balance(&self, request: WalletRequest) -> Result<Coin> {
        self.sync()?;

        match self.client.balance(&request.name, &request.passphrase) {
            Ok(balance) => Ok(balance),
            Err(e) => Err(to_rpc_error(e)),
        }
    }

    fn create(&self, request: WalletRequest) -> Result<String> {
        if let Err(e) = self.client.new_wallet(&request.name, &request.passphrase) {
            return Err(to_rpc_error(e));
        }

        if let Err(e) = self
            .client
            .new_single_transfer_address(&request.name, &request.passphrase)
        {
            Err(to_rpc_error(e))
        } else {
            Ok(request.name)
        }
    }

    fn list(&self) -> Result<Vec<String>> {
        match self.client.wallets() {
            Ok(wallets) => Ok(wallets),
            Err(e) => Err(to_rpc_error(e)),
        }
    }

    fn sendtoaddress(&self, request: WalletRequest, to_address: String, amount: u64) -> Result<()> {
        self.sync()?;

        let address = to_address
            .parse::<ExtendedAddr>()
            .map_err(|err| rpc_error_from_string(format!("{}", err)))?;
        let coin = Coin::new(amount).map_err(|err| rpc_error_from_string(format!("{}", err)))?;
        let tx_out = TxOut::new(address, coin);
        let tx_attributes = TxAttributes::new(self.network_id);

        let return_address = self
            .client
            .new_single_transfer_address(&request.name, &request.passphrase)
            .map_err(to_rpc_error)?;

        let transaction = self
            .client
            .create_transaction(
                &request.name,
                &request.passphrase,
                vec![tx_out],
                tx_attributes,
                None,
                return_address,
            )
            .map_err(to_rpc_error)?;

        self.client
            .broadcast_transaction(&transaction)
            .map_err(to_rpc_error)
    }

    fn sync(&self) -> Result<()> {
        // TODO: Implement synchronization logic for current view key
        Ok(())
    }

    fn sync_all(&self) -> Result<()> {
        // TODO: Implement synchronization logic for current view key
        Ok(())
    }

    fn transactions(&self, request: WalletRequest) -> Result<Vec<RowTx>> {
        self.sync()?;

        self.client
            .history(&request.name, &request.passphrase)
            .map_err(to_rpc_error)
            .map(|transaction_changes| {
                let rowtxs: Vec<RowTx> = transaction_changes
                    .into_iter()
                    .map(|c| {
                        let bc = match c.balance_change {
                            BalanceChange::Incoming(change) => ("incoming", u64::from(change)),
                            BalanceChange::Outgoing(change) => ("outgoing", u64::from(change)),
                        };
                        RowTx {
                            kind: bc.0.to_string(),
                            transaction_id: hex::encode(c.transaction_id),
                            address: c.address.to_string(),
                            height: c.block_height.to_string(),
                            time: c.block_time.to_string(),
                            amount: bc.1.to_string(),
                        }
                    })
                    .collect();
                rowtxs
            })
    }

    fn new_multi_sig_session(
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

    fn create_deposit_bonded_stake_transaction(&self, request: ClientRequest) -> Result<String> {
        let utxo: Vec<TxoPointer> = vec![];
        let addr: StakedStateAddress =
            StakedStateAddress::from_str(request.address.as_str()).unwrap();

        let attr: StakedStateOpAttributes = StakedStateOpAttributes::new(self.network_id);
        let result = self.ops_client.create_deposit_bonded_stake_transaction(
            request.name.as_str(),
            &request.passphrase,
            utxo,
            addr,
            attr,
        );

        match result {
            Ok(_a) => Ok("success".to_string()),
            Err(_b) => Ok("fail".to_string()),
        }
    }

    fn create_unbond_stake_transaction(
        &self,
        request: CreateUnbondStakeTransactionRequest,
    ) -> Result<String> {
        let value = Coin::from_str(request.amount.as_str()).unwrap();
        let attr: StakedStateOpAttributes = StakedStateOpAttributes::new(self.network_id);
        let addr: StakedStateAddress =
            StakedStateAddress::from_str(request.address.as_str()).unwrap();

        let result = self.ops_client.create_unbond_stake_transaction(
            request.name.as_str(),
            &request.passphrase,
            &addr,
            value,
            attr,
        );
        match result {
            Ok(_a) => Ok("success".to_string()),
            Err(_b) => Ok("fail".to_string()),
        }
    }

    fn create_withdraw_all_unbonded_stake_transaction(
        &self,
        request: ClientRequest,
    ) -> Result<String> {
        let addr: StakedStateAddress =
            StakedStateAddress::from_str(request.address.as_str()).unwrap();
        let utxo: Vec<TxOut> = vec![];
        let attr = TxAttributes::new(self.network_id);

        let result = self.ops_client.create_withdraw_unbonded_stake_transaction(
            request.name.as_str(),
            &request.passphrase,
            &addr,
            utxo,
            attr,
        );

        match result {
            Ok(_a) => Ok("success".to_string()),
            Err(_b) => Ok("fail".to_string()),
        }
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

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletRequest {
    name: String,
    passphrase: SecUtf8,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientRequest {
    name: String,
    passphrase: SecUtf8,
    address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUnbondStakeTransactionRequest {
    name: String,
    passphrase: SecUtf8,
    address: String,
    amount: String, // u64 as String
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use std::time::SystemTime;

    use chrono::DateTime;
    use parity_codec::Encode;

    use chain_core::init::coin::CoinError;
    use chain_core::tx::data::input::{TxoIndex, TxoPointer};
    use chain_core::tx::data::{Tx, TxId};
    use chain_core::tx::fee::{Fee, FeeAlgorithm};
    use chain_core::tx::{PlainTxAux, TransactionId, TxAux, TxObfuscated};
    use client_common::balance::BalanceChange;
    use client_common::balance::TransactionChange;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::types::*;
    use client_common::tendermint::Client;
    use client_common::{PrivateKey, Result as CommonResult, SignedTransaction, Transaction};
    use client_core::signer::DefaultSigner;
    use client_core::transaction_builder::DefaultTransactionBuilder;
    use client_core::wallet::DefaultWalletClient;
    use client_index::{AddressDetails, Index, TransactionCipher};
    use client_network::network_ops::DefaultNetworkOpsClient;

    #[derive(Default)]
    pub struct MockIndex;

    impl Index for MockIndex {
        fn address_details(&self, address: &ExtendedAddr) -> CommonResult<AddressDetails> {
            let mut address_details = AddressDetails::default();

            address_details.transaction_history = vec![TransactionChange {
                transaction_id: [0u8; 32],
                address: address.clone(),
                balance_change: BalanceChange::Incoming(Coin::new(30).unwrap()),
                block_height: 1,
                block_time: DateTime::from(SystemTime::now()),
            }];
            address_details.balance = Coin::new(30).unwrap();

            Ok(address_details)
        }

        fn transaction(&self, _: &TxId) -> CommonResult<Option<Transaction>> {
            Ok(Some(Transaction::TransferTransaction(Tx {
                inputs: vec![TxoPointer {
                    id: [0u8; 32],
                    index: 1,
                }],
                outputs: Default::default(),
                attributes: TxAttributes::new(171),
            })))
        }

        fn output(&self, _input: &TxoPointer) -> CommonResult<TxOut> {
            Ok(TxOut {
                address: ExtendedAddr::OrTree([0; 32]),
                value: Coin::new(10000000000000000000).unwrap(),
                valid_from: None,
            })
        }

        fn broadcast_transaction(&self, _transaction: &[u8]) -> CommonResult<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    pub struct ZeroFeeAlgorithm;

    impl FeeAlgorithm for ZeroFeeAlgorithm {
        fn calculate_fee(&self, _num_bytes: usize) -> std::result::Result<Fee, CoinError> {
            Ok(Fee::new(Coin::zero()))
        }

        fn calculate_for_txaux(&self, _txaux: &TxAux) -> std::result::Result<Fee, CoinError> {
            Ok(Fee::new(Coin::zero()))
        }
    }

    #[derive(Debug)]
    struct MockTransactionCipher;

    impl TransactionCipher for MockTransactionCipher {
        fn decrypt(
            &self,
            _transaction_ids: &[TxId],
            _private_key: &PrivateKey,
        ) -> CommonResult<Vec<Transaction>> {
            unreachable!()
        }

        fn encrypt(&self, transaction: SignedTransaction) -> CommonResult<TxAux> {
            let txpayload = transaction.encode();

            match transaction {
                SignedTransaction::TransferTransaction(tx, _) => Ok(TxAux::TransferTx {
                    txid: tx.id(),
                    inputs: tx.inputs.clone(),
                    no_of_outputs: tx.outputs.len() as TxoIndex,
                    payload: TxObfuscated {
                        key_from: 0,
                        nonce: [0u8; 12],
                        txpayload,
                    },
                }),
                SignedTransaction::DepositStakeTransaction(tx, witness) => {
                    let plain = PlainTxAux::DepositStakeTx(witness);
                    Ok(TxAux::DepositStakeTx {
                        tx,
                        payload: TxObfuscated {
                            key_from: 0,
                            nonce: [0u8; 12],
                            txpayload: plain.encode(),
                        },
                    })
                }
                SignedTransaction::WithdrawUnbondedStakeTransaction(tx, _, witness) => {
                    let plain = PlainTxAux::WithdrawUnbondedStakeTx(tx.clone());
                    Ok(TxAux::WithdrawUnbondedStakeTx {
                        txid: tx.id(),
                        no_of_outputs: tx.outputs.len() as TxoIndex,
                        witness,
                        payload: TxObfuscated {
                            key_from: 0,
                            nonce: [0u8; 12],
                            txpayload: plain.encode(),
                        },
                    })
                }
                SignedTransaction::UnbondStakeTransaction(_, _) => unreachable!(),
            }
        }
    }

    type TestTxBuilder =
        DefaultTransactionBuilder<TestSigner, ZeroFeeAlgorithm, MockTransactionCipher>;
    type TestSigner = DefaultSigner<MemoryStorage>;
    type TestWalletClient = DefaultWalletClient<MemoryStorage, MockIndex, TestTxBuilder>;
    type TestOpsClient = DefaultNetworkOpsClient<
        TestWalletClient,
        TestSigner,
        MockRpcClient,
        ZeroFeeAlgorithm,
        MockTransactionCipher,
    >;

    #[derive(Default)]
    pub struct MockRpcClient;
    impl Client for MockRpcClient {
        fn genesis(&self) -> CommonResult<Genesis> {
            unreachable!()
        }

        fn status(&self) -> CommonResult<Status> {
            unreachable!()
        }

        fn block(&self, _height: u64) -> CommonResult<Block> {
            unreachable!()
        }

        fn block_results(&self, _height: u64) -> CommonResult<BlockResults> {
            unreachable!()
        }

        fn broadcast_transaction(&self, _transaction: &[u8]) -> CommonResult<()> {
            unreachable!()
        }

        fn query(&self, _path: &str, _data: &[u8]) -> CommonResult<QueryResult> {
            unreachable!()
        }
    }

    #[test]
    fn test_create_duplicated_wallet() {
        let wallet_rpc = setup_wallet_rpc();

        assert_eq!(
            "Default".to_owned(),
            wallet_rpc
                .create(create_wallet_request("Default", "123456"))
                .unwrap()
        );

        assert_eq!(
            to_rpc_error(Error::from(ErrorKind::AlreadyExists)),
            wallet_rpc
                .create(create_wallet_request("Default", "123456"))
                .unwrap_err()
        );
    }

    #[test]
    fn test_create_and_list_wallet_flow() {
        let wallet_rpc = setup_wallet_rpc();

        assert_eq!(0, wallet_rpc.list().unwrap().len());

        assert_eq!(
            "Default".to_owned(),
            wallet_rpc
                .create(create_wallet_request("Default", "123456"))
                .unwrap()
        );

        assert_eq!(vec!["Default"], wallet_rpc.list().unwrap());

        assert_eq!(
            "Personal".to_owned(),
            wallet_rpc
                .create(create_wallet_request("Personal", "123456"))
                .unwrap()
        );

        let wallet_list = wallet_rpc.list().unwrap();
        assert_eq!(2, wallet_list.len());
        assert!(wallet_list.contains(&"Default".to_owned()));
        assert!(wallet_list.contains(&"Personal".to_owned()));
    }

    #[test]
    fn test_create_and_list_wallet_addresses_flow() {
        let wallet_rpc = setup_wallet_rpc();

        assert_eq!(
            to_rpc_error(Error::from(ErrorKind::WalletNotFound)),
            wallet_rpc
                .addresses(create_wallet_request("Default", "123456"))
                .unwrap_err()
        );

        assert_eq!(
            "Default".to_owned(),
            wallet_rpc
                .create(create_wallet_request("Default", "123456"))
                .unwrap()
        );

        assert_eq!(
            1,
            wallet_rpc
                .addresses(create_wallet_request("Default", "123456"))
                .unwrap()
                .len()
        );
    }

    #[test]
    fn test_wallet_balance() {
        let wallet_rpc = setup_wallet_rpc();

        wallet_rpc
            .create(create_wallet_request("Default", "123456"))
            .unwrap();
        assert_eq!(
            Coin::new(30).unwrap(),
            wallet_rpc
                .balance(create_wallet_request("Default", "123456"))
                .unwrap()
        )
    }

    #[test]
    fn test_wallet_transactions() {
        let wallet_rpc = setup_wallet_rpc();

        wallet_rpc
            .create(create_wallet_request("Default", "123456"))
            .unwrap();
        assert_eq!(
            1,
            wallet_rpc
                .transactions(create_wallet_request("Default", "123456"))
                .unwrap()
                .len()
        )
    }

    #[test]
    fn test_create_deposit_bonded_stake_transaction() {
        let client_rpc = setup_wallet_rpc();
        assert!(client_rpc
            .create_deposit_bonded_stake_transaction(create_client_request(
                "Default",
                "123456",
                "0x0e7c045110b8dbf29765047380898919c5cb56f4",
            ))
            .is_ok());
    }

    #[test]
    fn test_create_unbond_stake_transaction() {
        let client_rpc = setup_wallet_rpc();
        assert!(client_rpc
            .create_unbond_stake_transaction(create_unbonded_stake_client_request(
                "Default",
                "123456",
                "0x0e7c045110b8dbf29765047380898919c5cb56f4",
                "1",
            ))
            .is_ok());
    }

    #[test]
    fn test_create_withdraw_all_unbonded_stake_transaction() {
        let client_rpc = setup_wallet_rpc();
        assert!(client_rpc
            .create_withdraw_all_unbonded_stake_transaction(create_client_request(
                "Default",
                "123456",
                "0x0e7c045110b8dbf29765047380898919c5cb56f4",
            ))
            .is_ok());
    }

    fn make_test_wallet_client() -> TestWalletClient {
        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());
        DefaultWalletClient::builder()
            .with_wallet(storage)
            .with_transaction_read(MockIndex::default())
            .with_transaction_write(DefaultTransactionBuilder::new(
                signer,
                ZeroFeeAlgorithm::default(),
                MockTransactionCipher,
            ))
            .build()
            .unwrap()
    }
    fn make_test_ops_client() -> TestOpsClient {
        let storage = MemoryStorage::default();
        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage.clone())
            .with_transaction_read(MockIndex::default())
            .with_transaction_write(DefaultTransactionBuilder::new(
                DefaultSigner::new(storage.clone()),
                ZeroFeeAlgorithm::default(),
                MockTransactionCipher,
            ))
            .build()
            .unwrap();
        DefaultNetworkOpsClient::new(
            wallet_client,
            DefaultSigner::new(storage.clone()),
            MockRpcClient {},
            ZeroFeeAlgorithm::default(),
            MockTransactionCipher,
        )
    }

    fn setup_wallet_rpc() -> ClientRpcImpl<TestWalletClient, TestOpsClient> {
        let wallet_client = make_test_wallet_client();
        let ops_client = make_test_ops_client();
        let chain_id = 171u8;

        ClientRpcImpl::new(wallet_client, ops_client, chain_id)
    }

    fn create_wallet_request(name: &str, passphrase: &str) -> WalletRequest {
        WalletRequest {
            name: name.to_owned(),
            passphrase: SecUtf8::from(passphrase),
        }
    }

    fn create_client_request(name: &str, passphrase: &str, address: &str) -> ClientRequest {
        ClientRequest {
            name: name.to_owned(),
            passphrase: SecUtf8::from(passphrase),
            address: address.to_owned(),
        }
    }

    fn create_unbonded_stake_client_request(
        name: &str,
        passphrase: &str,
        address: &str,
        amount: &str,
    ) -> CreateUnbondStakeTransactionRequest {
        CreateUnbondStakeTransactionRequest {
            name: name.to_owned(),
            passphrase: SecUtf8::from(passphrase),
            address: address.to_owned(),
            amount: amount.to_owned(),
        }
    }
}
