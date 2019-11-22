use std::collections::BTreeSet;
use std::str::FromStr;

use jsonrpc_core::Result;
use jsonrpc_derive::rpc;

use chain_core::init::coin::Coin;
use chain_core::tx::data::access::{TxAccess, TxAccessPolicy};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::TxObfuscated;
use chain_core::tx::{TxAux, TxEnclaveAux};
use client_common::{PublicKey, Result as CommonResult};
use client_core::types::TransactionChange;
use client_core::types::WalletKind;
use client_core::{Mnemonic, MultiSigWalletClient, WalletClient};

use crate::server::{rpc_error_from_string, to_rpc_error, WalletRequest};

#[rpc]
pub trait WalletRpc: Send + Sync {
    #[rpc(name = "wallet_balance")]
    fn balance(&self, request: WalletRequest) -> Result<Coin>;

    #[rpc(name = "wallet_create")]
    fn create(&self, request: WalletRequest, walletkind: WalletKind) -> Result<String>;

    #[rpc(name = "wallet_restore")]
    fn restore(&self, request: WalletRequest, mnemonics: Mnemonic) -> Result<String>;

    #[rpc(name = "wallet_createStakingAddress")]
    fn create_staking_address(&self, request: WalletRequest) -> Result<String>;

    #[rpc(name = "wallet_createTransferAddress")]
    fn create_transfer_address(&self, request: WalletRequest) -> Result<String>;

    #[rpc(name = "wallet_getViewKey")]
    fn get_view_key(&self, request: WalletRequest) -> Result<String>;

    #[rpc(name = "wallet_list")]
    fn list(&self) -> Result<Vec<String>>;

    #[rpc(name = "wallet_listPublicKeys")]
    fn list_public_keys(&self, request: WalletRequest) -> Result<BTreeSet<PublicKey>>;

    #[rpc(name = "wallet_listStakingAddresses")]
    fn list_staking_addresses(&self, request: WalletRequest) -> Result<BTreeSet<String>>;

    #[rpc(name = "wallet_listTransferAddresses")]
    fn list_transfer_addresses(&self, request: WalletRequest) -> Result<BTreeSet<String>>;

    #[rpc(name = "wallet_sendToAddress")]
    fn send_to_address(
        &self,
        request: WalletRequest,
        to_address: String,
        amount: Coin,
        view_keys: Vec<String>,
    ) -> Result<String>;

    #[rpc(name = "wallet_transactions")]
    fn transactions(&self, request: WalletRequest) -> Result<Vec<TransactionChange>>;
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

    fn create(&self, request: WalletRequest, kind: WalletKind) -> Result<String> {
        let mnemonic = self
            .client
            .new_wallet(&request.name, &request.passphrase, kind)
            .map_err(to_rpc_error)?;

        self.client
            .new_staking_address(&request.name, &request.passphrase)
            .map_err(to_rpc_error)?;
        self.client
            .new_transfer_address(&request.name, &request.passphrase)
            .map_err(to_rpc_error)?;

        match (kind, mnemonic) {
            (WalletKind::Basic, None) => Ok(request.name),
            (WalletKind::HD, Some(mnemonic)) => Ok(mnemonic.unsecure_phrase().to_string()),
            _ => Err(rpc_error_from_string(
                "Internal Error: Invalid mnemonic for given wallet kind".to_owned(),
            )),
        }
    }

    fn restore(&self, request: WalletRequest, mnemonic: Mnemonic) -> Result<String> {
        self.client
            .restore_wallet(&request.name, &request.passphrase, &mnemonic)
            .map_err(to_rpc_error)?;

        mnemonic.zeroize();

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

    fn list_public_keys(&self, request: WalletRequest) -> Result<BTreeSet<PublicKey>> {
        self.client
            .public_keys(&request.name, &request.passphrase)
            .map_err(to_rpc_error)
    }

    fn list_staking_addresses(&self, request: WalletRequest) -> Result<BTreeSet<String>> {
        self.client
            .staking_addresses(&request.name, &request.passphrase)
            .map(|addresses| addresses.iter().map(ToString::to_string).collect())
            .map_err(to_rpc_error)
    }

    fn list_transfer_addresses(&self, request: WalletRequest) -> Result<BTreeSet<String>> {
        self.client
            .transfer_addresses(&request.name, &request.passphrase)
            .map(|addresses| addresses.iter().map(ToString::to_string).collect())
            .map_err(to_rpc_error)
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

        if let TxAux::EnclaveTx(TxEnclaveAux::TransferTx {
            payload: TxObfuscated { txid, .. },
            ..
        }) = transaction
        {
            Ok(hex::encode(txid))
        } else {
            Err(rpc_error_from_string(String::from(
                "Transaction is not transfer transaction",
            )))
        }
    }

    fn transactions(&self, request: WalletRequest) -> Result<Vec<TransactionChange>> {
        self.client
            .history(&request.name, &request.passphrase)
            .map_err(to_rpc_error)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use secstr::SecUtf8;

    use parity_scale_codec::Encode;

    use chain_core::init::coin::CoinError;
    use chain_core::tx::data::input::TxoIndex;
    use chain_core::tx::data::TxId;
    use chain_core::tx::fee::{Fee, FeeAlgorithm};
    use chain_core::tx::{PlainTxAux, TransactionId, TxAux, TxObfuscated};
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::lite;
    use client_common::tendermint::mock;
    use client_common::tendermint::types::*;
    use client_common::tendermint::Client;
    use client_common::{
        Error, ErrorKind, PrivateKey, Result as CommonResult, SignedTransaction, Transaction,
    };
    use client_core::signer::DefaultSigner;
    use client_core::transaction_builder::DefaultTransactionBuilder;
    use client_core::wallet::DefaultWalletClient;
    use client_core::TransactionObfuscation;

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
                SignedTransaction::TransferTransaction(tx, _) => {
                    Ok(TxAux::EnclaveTx(TxEnclaveAux::TransferTx {
                        inputs: tx.inputs.clone(),
                        no_of_outputs: tx.outputs.len() as TxoIndex,
                        payload: TxObfuscated {
                            txid: tx.id(),
                            key_from: 0,
                            init_vector: [0u8; 12],
                            txpayload,
                        },
                    }))
                }
                SignedTransaction::DepositStakeTransaction(tx, witness) => {
                    let plain = PlainTxAux::DepositStakeTx(witness);
                    Ok(TxAux::EnclaveTx(TxEnclaveAux::DepositStakeTx {
                        tx: tx.clone(),
                        payload: TxObfuscated {
                            txid: tx.id(),
                            key_from: 0,
                            init_vector: [0u8; 12],
                            txpayload: plain.encode(),
                        },
                    }))
                }
                SignedTransaction::WithdrawUnbondedStakeTransaction(tx, _, witness) => {
                    let plain = PlainTxAux::WithdrawUnbondedStakeTx(tx.clone());
                    Ok(TxAux::EnclaveTx(TxEnclaveAux::WithdrawUnbondedStakeTx {
                        no_of_outputs: tx.outputs.len() as TxoIndex,
                        witness,
                        payload: TxObfuscated {
                            txid: tx.id(),
                            key_from: 0,
                            init_vector: [0u8; 12],
                            txpayload: plain.encode(),
                        },
                    }))
                }
            }
        }
    }

    type TestTxBuilder =
        DefaultTransactionBuilder<TestSigner, ZeroFeeAlgorithm, MockTransactionCipher>;
    type TestSigner = DefaultSigner<MemoryStorage>;
    type TestWalletClient = DefaultWalletClient<MemoryStorage, MockRpcClient, TestTxBuilder>;

    #[derive(Default)]
    pub struct MockRpcClient;

    impl Client for MockRpcClient {
        fn genesis(&self) -> CommonResult<Genesis> {
            unreachable!("genesis")
        }

        fn status(&self) -> CommonResult<Status> {
            Ok(Status {
                sync_info: status::SyncInfo {
                    latest_block_height: Height::default(),
                    latest_app_hash: Hash::from_str(
                        "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C",
                    )
                    .unwrap(),
                    ..mock::sync_info()
                },
                ..mock::status_response()
            })
        }

        fn block(&self, _height: u64) -> CommonResult<Block> {
            Ok(Block {
                header: Header {
                    app_hash: Hash::from_str(
                        "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C",
                    )
                    .unwrap(),
                    time: Time::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                    ..mock::header()
                },
                ..mock::block()
            })
        }

        fn block_batch<'a, T: Iterator<Item = &'a u64>>(
            &self,
            _heights: T,
        ) -> CommonResult<Vec<Block>> {
            Ok(vec![Block {
                header: Header {
                    app_hash: Hash::from_str(
                        "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C",
                    )
                    .unwrap(),
                    time: Time::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                    ..mock::header()
                },
                ..mock::block()
            }])
        }

        fn block_results(&self, _height: u64) -> CommonResult<BlockResults> {
            Ok(BlockResults {
                height: Height::default(),
                results: Results {
                    deliver_tx: None,
                    end_block: None,
                },
            })
        }

        fn block_results_batch<'a, T: Iterator<Item = &'a u64>>(
            &self,
            _heights: T,
        ) -> CommonResult<Vec<BlockResults>> {
            Ok(vec![BlockResults {
                height: Height::default(),
                results: Results {
                    deliver_tx: None,
                    end_block: None,
                },
            }])
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

    #[test]
    fn balance_should_return_wallet_balance() {
        let wallet_rpc = setup_wallet_rpc();

        wallet_rpc
            .create(
                create_wallet_request("Default", "123456"),
                WalletKind::Basic,
            )
            .unwrap();
        assert_eq!(
            Coin::zero(),
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
                .create(
                    create_wallet_request("Default", "123456"),
                    WalletKind::Basic,
                )
                .unwrap();

            assert_eq!(
                to_rpc_error(Error::new(
                    ErrorKind::InvalidInput,
                    "Wallet with name (Default) already exists"
                )),
                wallet_rpc
                    .create(
                        create_wallet_request("Default", "123456"),
                        WalletKind::Basic
                    )
                    .unwrap_err()
            );
        }

        #[test]
        fn create_should_create_named_wallet() {
            let wallet_rpc = setup_wallet_rpc();

            assert_eq!(
                "Default".to_owned(),
                wallet_rpc
                    .create(
                        create_wallet_request("Default", "123456"),
                        WalletKind::Basic
                    )
                    .unwrap()
            );

            assert_eq!(vec!["Default"], wallet_rpc.list().unwrap());
        }

        #[test]
        fn create_should_create_staking_and_transfer_address_for_the_wallet() {
            let wallet_rpc = setup_wallet_rpc();
            let wallet_request = create_wallet_request("Default", "123456");

            wallet_rpc
                .create(wallet_request.clone(), WalletKind::Basic)
                .unwrap();

            assert_eq!(
                1,
                wallet_rpc
                    .list_transfer_addresses(wallet_request.clone())
                    .unwrap()
                    .len()
            );
            assert_eq!(
                1,
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

        wallet_rpc
            .create(wallet_request.clone(), WalletKind::Basic)
            .unwrap();
        assert_eq!(
            1,
            wallet_rpc
                .list_staking_addresses(wallet_request.clone())
                .unwrap()
                .len()
        );

        wallet_rpc
            .create_staking_address(wallet_request.clone())
            .unwrap();

        assert_eq!(
            2,
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

        wallet_rpc
            .create(wallet_request.clone(), WalletKind::Basic)
            .unwrap();

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

        wallet_rpc
            .create(wallet_request.clone(), WalletKind::Basic)
            .unwrap();

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
            .create(
                create_wallet_request("Default", "123456"),
                WalletKind::Basic,
            )
            .unwrap();

        assert_eq!(vec!["Default"], wallet_rpc.list().unwrap());

        wallet_rpc
            .create(
                create_wallet_request("Personal", "123456"),
                WalletKind::Basic,
            )
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

        wallet_rpc
            .create(wallet_request.clone(), WalletKind::Basic)
            .unwrap();
        assert_eq!(
            0,
            wallet_rpc
                .transactions(wallet_request.clone())
                .unwrap()
                .len()
        )
    }

    fn make_test_wallet_client(storage: MemoryStorage) -> TestWalletClient {
        let signer = DefaultSigner::new(storage.clone());
        let transaction_builder = DefaultTransactionBuilder::new(
            signer,
            ZeroFeeAlgorithm::default(),
            MockTransactionCipher,
        );
        DefaultWalletClient::new(storage, MockRpcClient, transaction_builder)
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

    #[test]
    fn hdwallet_should_create_hd_wallet() {
        let wallet_rpc = setup_wallet_rpc();

        wallet_rpc
            .create(create_wallet_request("Default", "123456"), WalletKind::HD)
            .unwrap();
    }

    #[test]
    fn hdwallet_should_recover_hd_wallet() {
        let wallet_rpc = setup_wallet_rpc();

        let result=wallet_rpc
            .restore(
                create_wallet_request("Default", "123456"),
                Mnemonic::from_secstr(&SecUtf8::from("online hire print other clock like betray vote hollow bus insect meadow replace two tape worry quality disease cabin girl tree pudding issue radar")).unwrap()
            )
            .unwrap();
        assert!("Default" == result);
    }

    #[test]
    fn wallet_can_send_amount_should_fail_with_insufficient_amount() {
        let wallet_rpc = setup_wallet_rpc();

        let result = wallet_rpc
            .restore(
                create_wallet_request("Default", "123456"),
                Mnemonic::from_secstr(&SecUtf8::from("speed tortoise kiwi forward extend baby acoustic foil coach castle ship purchase unlock base hip erode tag keen present vibrant oyster cotton write fetch")).unwrap()
            )
            .unwrap();
        assert_eq!("Default", result);

        let wallet_request = create_wallet_request("Default", "123456");

        let result = wallet_rpc
            .create_transfer_address(wallet_request.clone())
            .unwrap();
        assert_eq!(
            "dcro1fnjq70pf9hvd2tkd3rj7pash6ph7p42qakqt2k39sjqp4m4p25kqclslnt",
            result.to_string()
        );

        let to_result = wallet_rpc
            .create_transfer_address(wallet_request.clone())
            .unwrap();
        assert_eq!(
            "dcro1ee3exuxyv5pauameswxureamlvmptjm8tsg4lcwqpx2nclshc6eqt8fanm",
            to_result.to_string()
        );

        let viewkey = wallet_rpc.get_view_key(wallet_request.clone()).unwrap();

        let send_result = wallet_rpc.send_to_address(
            wallet_request.clone(),
            to_result,
            Coin::from(1_0000u32),
            vec![viewkey],
        );
        assert!(send_result.is_err());
    }
}
