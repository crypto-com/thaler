use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use chain_core::init::coin::Coin;
use chain_core::tx::data::access::{TxAccess, TxAccessPolicy};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::TxAux;
use client_common::balance::BalanceChange;
use client_common::{PublicKey, Result as CommonResult};
use client_core::{MultiSigWalletClient, WalletClient};

use crate::server::{rpc_error_from_string, to_rpc_error, WalletRequest};

#[derive(Serialize, Deserialize)]
pub struct RowTx {
    kind: String,
    transaction_id: String,
    address: String,
    height: String,
    time: String,
    amount: Coin,
}

#[rpc]
pub trait WalletRpc: Send + Sync {
    #[rpc(name = "wallet_balance")]
    fn balance(&self, request: WalletRequest) -> Result<Coin>;

    #[rpc(name = "wallet_create")]
    fn create(&self, request: WalletRequest) -> Result<String>;

    #[rpc(name = "wallet_createStakingAddress")]
    fn create_staking_address(&self, request: WalletRequest) -> Result<String>;

    #[rpc(name = "wallet_createTransferAddress")]
    fn create_transfer_address(&self, request: WalletRequest) -> Result<String>;

    #[rpc(name = "wallet_getViewKey")]
    fn get_view_key(&self, request: WalletRequest) -> Result<String>;

    #[rpc(name = "wallet_list")]
    fn list(&self) -> Result<Vec<String>>;

    #[rpc(name = "wallet_sendToAddress")]
    fn send_to_address(
        &self,
        request: WalletRequest,
        to_address: String,
        amount: Coin,
        view_keys: Vec<String>,
    ) -> Result<String>;

    #[rpc(name = "wallet_listStakingAddresses")]
    fn list_staking_addresses(&self, request: WalletRequest) -> Result<Vec<String>>;

    #[rpc(name = "wallet_listTransferAddresses")]
    fn list_transfer_addresses(&self, request: WalletRequest) -> Result<Vec<String>>;

    #[rpc(name = "wallet_transactions")]
    fn transactions(&self, request: WalletRequest) -> Result<Vec<RowTx>>;
}

pub struct WalletRpcImpl<T>
where
    T: WalletClient,
{
    client: T,
    network_id: u8,
}

impl<T> WalletRpcImpl<T>
where
    T: WalletClient,
{
    pub fn new(client: T, network_id: u8) -> Self {
        WalletRpcImpl { client, network_id }
    }
}

impl<T> WalletRpc for WalletRpcImpl<T>
where
    T: WalletClient + MultiSigWalletClient + 'static,
{
    fn balance(&self, request: WalletRequest) -> Result<Coin> {
        match self.client.balance(&request.name, &request.passphrase) {
            Ok(balance) => Ok(balance),
            Err(e) => Err(to_rpc_error(e)),
        }
    }

    fn create(&self, request: WalletRequest) -> Result<String> {
        if let Err(err) = self.client.new_wallet(&request.name, &request.passphrase) {
            return Err(to_rpc_error(err));
        }

        self.client
            .new_staking_address(&request.name, &request.passphrase)
            .map_err(to_rpc_error)?;
        self.client
            .new_transfer_address(&request.name, &request.passphrase)
            .map_err(to_rpc_error)?;
        Ok(request.name)
    }

    fn create_staking_address(&self, request: WalletRequest) -> Result<String> {
        self.client
            .new_staking_address(&request.name, &request.passphrase)
            .map(|extended_addr| extended_addr.to_string())
            .map_err(to_rpc_error)
    }

    fn create_transfer_address(&self, request: WalletRequest) -> Result<String> {
        let extended_address = self
            .client
            .new_transfer_address(&request.name, &request.passphrase)
            .map_err(to_rpc_error)?;

        Ok(extended_address.to_string())
    }

    fn get_view_key(&self, request: WalletRequest) -> Result<String> {
        let public_key = self
            .client
            .view_key(&request.name, &request.passphrase)
            .map_err(to_rpc_error)?;
        Ok(public_key.to_string())
    }

    fn list(&self) -> Result<Vec<String>> {
        self.client.wallets().map_err(to_rpc_error)
    }

    fn send_to_address(
        &self,
        request: WalletRequest,
        to_address: String,
        amount: Coin,
        view_keys: Vec<String>,
    ) -> Result<String> {
        let address = to_address
            .parse::<ExtendedAddr>()
            .map_err(|err| rpc_error_from_string(format!("{}", err)))?;
        let tx_out = TxOut::new(address, amount);

        let view_keys = view_keys
            .iter()
            .map(|view_key| PublicKey::from_str(view_key))
            .collect::<CommonResult<Vec<PublicKey>>>()
            .map_err(to_rpc_error)?;

        let view_key = self
            .client
            .view_key(&request.name, &request.passphrase)
            .map_err(to_rpc_error)?;

        let mut access_policies = vec![TxAccessPolicy {
            view_key: view_key.into(),
            access: TxAccess::AllData,
        }];

        for key in view_keys.iter() {
            access_policies.push(TxAccessPolicy {
                view_key: key.into(),
                access: TxAccess::AllData,
            });
        }

        let attributes = TxAttributes::new_with_access(self.network_id, access_policies);

        let return_address = self
            .client
            .new_transfer_address(&request.name, &request.passphrase)
            .map_err(to_rpc_error)?;

        let transaction = self
            .client
            .create_transaction(
                &request.name,
                &request.passphrase,
                vec![tx_out],
                attributes,
                None,
                return_address,
            )
            .map_err(to_rpc_error)?;

        self.client
            .broadcast_transaction(&transaction)
            .map_err(to_rpc_error)?;

        if let TxAux::TransferTx { txid, .. } = transaction {
            Ok(hex::encode(txid))
        } else {
            Err(rpc_error_from_string(String::from(
                "Transaction is not transfer transaction",
            )))
        }
    }

    fn list_staking_addresses(&self, request: WalletRequest) -> Result<Vec<String>> {
        self.client
            .staking_addresses(&request.name, &request.passphrase)
            .map(|addresses| addresses.iter().map(ToString::to_string).collect())
            .map_err(to_rpc_error)
    }

    fn list_transfer_addresses(&self, request: WalletRequest) -> Result<Vec<String>> {
        self.client
            .transfer_addresses(&request.name, &request.passphrase)
            .map(|addresses| addresses.iter().map(ToString::to_string).collect())
            .map_err(to_rpc_error)
    }

    fn transactions(&self, request: WalletRequest) -> Result<Vec<RowTx>> {
        self.client
            .history(&request.name, &request.passphrase)
            .map_err(to_rpc_error)
            .map(|transaction_changes| {
                transaction_changes
                    .into_iter()
                    .map(|c| {
                        let bc = match c.balance_change {
                            BalanceChange::Incoming(change) => ("incoming", change),
                            BalanceChange::Outgoing(change) => ("outgoing", change),
                        };
                        RowTx {
                            kind: bc.0.to_string(),
                            transaction_id: hex::encode(c.transaction_id),
                            address: c.address.to_string(),
                            height: c.block_height.to_string(),
                            time: c.block_time.to_string(),
                            amount: bc.1,
                        }
                    })
                    .collect()
            })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use secstr::SecUtf8;
    use std::time::SystemTime;

    use chrono::DateTime;
    use parity_scale_codec::Encode;

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
    use client_common::{
        Error, ErrorKind, PrivateKey, Result as CommonResult, SignedTransaction, Transaction,
    };
    use client_core::signer::DefaultSigner;
    use client_core::transaction_builder::DefaultTransactionBuilder;
    use client_core::wallet::DefaultWalletClient;
    use client_index::{AddressDetails, Index, TransactionObfuscation};

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

    impl TransactionObfuscation for MockTransactionCipher {
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

    #[derive(Default)]
    pub struct MockRpcClient;

    impl Client for MockRpcClient {
        fn genesis(&self) -> CommonResult<Genesis> {
            unreachable!("genesis")
        }

        fn status(&self) -> CommonResult<Status> {
            Ok(Status {
                sync_info: SyncInfo {
                    latest_block_height: "1".to_string(),
                },
            })
        }

        fn block(&self, _height: u64) -> CommonResult<Block> {
            Ok(Block {
                block: BlockInner {
                    header: Header {
                        height: "1".to_string(),
                        time: DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                    },
                    data: Data { txs: None },
                },
            })
        }

        fn block_results(&self, _height: u64) -> CommonResult<BlockResults> {
            Ok(BlockResults {
                height: "1".to_string(),
                results: Results {
                    deliver_tx: None,
                    end_block: None,
                },
            })
        }

        fn broadcast_transaction(&self, _transaction: &[u8]) -> CommonResult<()> {
            unreachable!("broadcast_transaction")
        }

        fn query(&self, _path: &str, _data: &[u8]) -> CommonResult<QueryResult> {
            unreachable!("query")
        }
    }

    #[test]
    fn balance_should_return_wallet_balance() {
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

    mod create {
        use super::*;

        #[test]
        fn create_duplicated_wallet_should_throw_error() {
            let wallet_rpc = setup_wallet_rpc();

            wallet_rpc
                .create(create_wallet_request("Default", "123456"))
                .unwrap();

            assert_eq!(
                to_rpc_error(Error::from(ErrorKind::AlreadyExists)),
                wallet_rpc
                    .create(create_wallet_request("Default", "123456"))
                    .unwrap_err()
            );
        }

        #[test]
        fn create_should_create_named_wallet() {
            let wallet_rpc = setup_wallet_rpc();

            assert_eq!(
                "Default".to_owned(),
                wallet_rpc
                    .create(create_wallet_request("Default", "123456"))
                    .unwrap()
            );

            assert_eq!(vec!["Default"], wallet_rpc.list().unwrap());
        }

        #[test]
        fn create_should_create_staking_and_transfer_address_for_the_wallet() {
            let wallet_rpc = setup_wallet_rpc();
            let wallet_request = create_wallet_request("Default", "123456");

            wallet_rpc.create(wallet_request.clone()).unwrap();

            assert_eq!(
                1,
                wallet_rpc
                    .list_transfer_addresses(wallet_request.clone())
                    .unwrap()
                    .len()
            );
            // FIXME: Create a transfer address also creates a staking address
            // which is a known problem
            assert_eq!(
                2,
                wallet_rpc
                    .list_staking_addresses(wallet_request.clone())
                    .unwrap()
                    .len()
            );
        }
    }

    #[test]
    fn create_staking_address_should_work() {
        let wallet_rpc = setup_wallet_rpc();
        let wallet_request = create_wallet_request("Default", "123456");

        wallet_rpc.create(wallet_request.clone()).unwrap();
        // FIXME: Create a transfer address also creates a staking address
        // which is a known problem
        assert_eq!(
            2,
            wallet_rpc
                .list_staking_addresses(wallet_request.clone())
                .unwrap()
                .len()
        );

        wallet_rpc
            .create_staking_address(wallet_request.clone())
            .unwrap();

        assert_eq!(
            3,
            wallet_rpc
                .list_staking_addresses(wallet_request.clone())
                .unwrap()
                .len()
        );
    }

    #[test]
    fn create_transfer_address_should_work() {
        let wallet_rpc = setup_wallet_rpc();
        let wallet_request = create_wallet_request("Default", "123456");

        wallet_rpc.create(wallet_request.clone()).unwrap();

        assert_eq!(
            1,
            wallet_rpc
                .list_transfer_addresses(wallet_request.clone())
                .unwrap()
                .len()
        );

        wallet_rpc
            .create_transfer_address(wallet_request.clone())
            .unwrap();

        assert_eq!(
            2,
            wallet_rpc
                .list_transfer_addresses(wallet_request.clone())
                .unwrap()
                .len()
        );
    }

    #[test]
    fn get_view_key_should_return_public_key() {
        let wallet_rpc = setup_wallet_rpc();
        let wallet_request = create_wallet_request("Default", "123456");

        wallet_rpc.create(wallet_request.clone()).unwrap();

        assert_eq!(
            wallet_rpc
                .get_view_key(wallet_request.clone())
                .unwrap()
                .len(),
            66
        );
    }

    #[test]
    fn list_should_list_all_wallets() {
        let wallet_rpc = setup_wallet_rpc();

        assert_eq!(0, wallet_rpc.list().unwrap().len());

        wallet_rpc
            .create(create_wallet_request("Default", "123456"))
            .unwrap();

        assert_eq!(vec!["Default"], wallet_rpc.list().unwrap());

        wallet_rpc
            .create(create_wallet_request("Personal", "123456"))
            .unwrap();

        let wallet_list = wallet_rpc.list().unwrap();
        assert_eq!(2, wallet_list.len());
        assert!(wallet_list.contains(&"Default".to_owned()));
        assert!(wallet_list.contains(&"Personal".to_owned()));
    }

    #[test]
    fn transactions_should_return_list_of_wallet_transactions() {
        let wallet_rpc = setup_wallet_rpc();
        let wallet_request = create_wallet_request("Default", "123456");

        wallet_rpc.create(wallet_request.clone()).unwrap();
        assert_eq!(
            1,
            wallet_rpc
                .transactions(wallet_request.clone())
                .unwrap()
                .len()
        )
    }

    fn make_test_wallet_client(storage: MemoryStorage) -> TestWalletClient {
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

    fn setup_wallet_rpc() -> WalletRpcImpl<TestWalletClient> {
        let storage = MemoryStorage::default();

        let wallet_client = make_test_wallet_client(storage.clone());
        let chain_id = 171u8;

        WalletRpcImpl::new(wallet_client, chain_id)
    }

    fn create_wallet_request(name: &str, passphrase: &str) -> WalletRequest {
        WalletRequest {
            name: name.to_owned(),
            passphrase: SecUtf8::from(passphrase),
        }
    }
}
