use chain_core::init::coin::Coin;
use chain_core::state::account::{StakedStateAddress, StakedStateOpAttributes};

use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;

use client_network::network_ops::NetworkOpsClient;
use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[rpc]
pub trait ClientRpc {
    #[rpc(name = "query_client")]
    fn query_client(&self, request: ClientRequest) -> Result<String>;

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

pub struct ClientRpcImpl<T: NetworkOpsClient + Send + Sync> {
    client: T,
    chain_id: u8,
}

impl<T> ClientRpcImpl<T>
where
    T: NetworkOpsClient + Send + Sync,
{
    pub fn new(client: T, chain_id: u8) -> Self {
        ClientRpcImpl { client, chain_id }
    }
}

impl<T> ClientRpc for ClientRpcImpl<T>
where
    T: NetworkOpsClient + Send + Sync + 'static,
{
    fn query_client(&self, request: ClientRequest) -> Result<String> {
        let m = serde_json::to_string(&request).unwrap();
        Ok(m.to_string())
    }

    fn create_deposit_bonded_stake_transaction(&self, request: ClientRequest) -> Result<String> {
        let utxo: Vec<TxoPointer> = vec![];
        let addr: StakedStateAddress =
            StakedStateAddress::from_str(request.address.as_str()).unwrap();

        let attr: StakedStateOpAttributes = StakedStateOpAttributes::new(self.chain_id);
        let result = self.client.create_deposit_bonded_stake_transaction(
            request.name.as_str(),
            &SecUtf8::from(request.passphrase),
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
        let attr: StakedStateOpAttributes = StakedStateOpAttributes::new(self.chain_id);
        let addr: StakedStateAddress =
            StakedStateAddress::from_str(request.address.as_str()).unwrap();

        let result = self.client.create_unbond_stake_transaction(
            request.name.as_str(),
            &SecUtf8::from(request.passphrase),
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
        let attr = TxAttributes::new(self.chain_id);

        let result = self.client.create_withdraw_unbonded_stake_transaction(
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
mod tests {
    use super::*;

    use chrono::DateTime;
    use std::time::SystemTime;

    use chain_core::init::coin::CoinError;
    use chain_core::tx::data::input::TxoPointer;
    use chain_core::tx::data::{Tx, TxId};
    use chain_core::tx::fee::{Fee, FeeAlgorithm};
    use chain_core::tx::TxAux;
    use client_common::balance::BalanceChange;
    use client_common::storage::MemoryStorage;
    use client_common::Transaction;
    use client_core::signer::DefaultSigner;
    use client_core::transaction_builder::DefaultTransactionBuilder;
    use client_core::wallet::DefaultWalletClient;
    use client_index::Index;

    use crate::wallet_rpc::{WalletRequest, WalletRpcImpl};
    use chain_core::tx::data::address::ExtendedAddr;
    use client_common::balance::TransactionChange;
    use client_common::tendermint::types::*;
    use client_common::tendermint::{Client, RpcClient};
    use client_common::{Error, ErrorKind, PublicKey};
    use client_common::{Error, ErrorKind, PublicKey, Result as CommonResult};
    use client_index::index::DefaultIndex;
    use client_network::network_ops::DefaultNetworkOpsClient;
    use serde_json::Value;

    type TestRpcClient =
        DefaultNetworkOpsClient<TestWalletClient, TestSigner, MockRpcClient, ZeroFeeAlgorithm>;
    type TestClient = ClientRpcImpl<TestRpcClient>;

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

        fn query(&self, _path: &str, _data: &str) -> CommonResult<QueryResult> {
            unreachable!()
        }
    }
    #[derive(Default)]
    pub struct MockIndex;

    impl Index for MockIndex {
        fn sync(&self) -> CommonResult<()> {
            Ok(())
        }

        fn sync_all(&self) -> CommonResult<()> {
            Ok(())
        }

        fn transaction_changes(
            &self,
            address: &ExtendedAddr,
        ) -> CommonResult<Vec<TransactionChange>> {
            Ok(vec![TransactionChange {
                transaction_id: [0u8; 32],
                address: address.clone(),
                balance_change: BalanceChange::Incoming(Coin::new(30).unwrap()),
                height: 1,
                time: DateTime::from(SystemTime::now()),
            }])
        }

        fn balance(&self, _: &ExtendedAddr) -> CommonResult<Coin> {
            Ok(Coin::new(30).unwrap())
        }

        fn unspent_transactions(
            &self,
            _address: &ExtendedAddr,
        ) -> CommonResult<Vec<(TxoPointer, TxOut)>> {
            Ok(Vec::new())
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

        fn output(&self, _id: &TxId, _index: usize) -> CommonResult<TxOut> {
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
    struct ZeroFeeAlgorithm;

    impl FeeAlgorithm for ZeroFeeAlgorithm {
        fn calculate_fee(&self, _num_bytes: usize) -> std::result::Result<Fee, CoinError> {
            Ok(Fee::new(Coin::zero()))
        }

        fn calculate_for_txaux(&self, _txaux: &TxAux) -> std::result::Result<Fee, CoinError> {
            Ok(Fee::new(Coin::zero()))
        }
    }

    type TestTxBuilder = DefaultTransactionBuilder<TestSigner, ZeroFeeAlgorithm>;
    type TestSigner = DefaultSigner<MemoryStorage>;
    type TestWalletClient = DefaultWalletClient<MemoryStorage, MockIndex, TestTxBuilder>;
    type TestWallet = WalletRpcImpl<TestWalletClient>;
    fn setup_wallet_rpc() -> TestWallet {
        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());
        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .with_transaction_read(MockIndex::default())
            .with_transaction_write(DefaultTransactionBuilder::new(
                signer,
                ZeroFeeAlgorithm::default(),
            ))
            .build()
            .unwrap();
        let chain_id = 171u8;
        WalletRpcImpl::new(wallet_client, chain_id)
    }

    fn create_client_rpc() -> TestClient {
        let storage = MemoryStorage::default();
        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage.clone())
            .with_transaction_read(MockIndex::default())
            .with_transaction_write(DefaultTransactionBuilder::new(
                DefaultSigner::new(storage.clone()),
                ZeroFeeAlgorithm::default(),
            ))
            .build()
            .unwrap();
        let network_ops_client = DefaultNetworkOpsClient::new(
            wallet_client,
            DefaultSigner::new(storage.clone()),
            MockRpcClient {},
            ZeroFeeAlgorithm::default(),
        );

        ClientRpcImpl::new(network_ops_client, 171u8)
    }

    #[test]
    fn test_create_deposit_bonded_stake_transaction() {
        let client_rpc = create_client_rpc();
        let data = client_rpc
            .create_deposit_bonded_stake_transaction(create_client_request(
                "Default",
                "123456",
                "0x0e7c045110b8dbf29765047380898919c5cb56f4",
            ))
            .unwrap();
        let v: Value = serde_json::from_str(data.as_str()).unwrap();
        let tx = v.get("DepositStakeTx").unwrap();
        let attr = tx[0].get("attributes").unwrap();
        let hexid = attr.get("chain_hex_id").unwrap();
        assert!(171 as u64 == hexid.as_u64().unwrap());
    }

    #[test]
    fn test_create_unbond_stake_transaction() {
        let client_rpc = create_client_rpc();
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
        let client_rpc = create_client_rpc();
        assert!(client_rpc
            .create_withdraw_all_unbonded_stake_transaction(create_client_request(
                "Default",
                "123456",
                "0x0e7c045110b8dbf29765047380898919c5cb56f4",
            ))
            .is_ok());
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
