use std::collections::BTreeSet;
use std::str::FromStr;

use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use secstr::SecUtf8;

use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use client_common::{PrivateKey, PublicKey, Result as CommonResult, SecKey};
use client_core::service::WalletInfo;
use client_core::transaction_builder::SignedTransferTransaction;
use client_core::types::{TransactionChange, WalletBalance, WalletKind};
use client_core::wallet::{CreateWalletRequest, WalletRequest};
use client_core::{Mnemonic, MultiSigWalletClient, UnspentTransactions, WalletClient};
use parity_scale_codec::{Decode, Encode};

use crate::server::{rpc_error_from_string, to_rpc_error};

#[rpc]
pub trait WalletRpc: Send + Sync {
    #[rpc(name = "wallet_balance")]
    fn balance(&self, request: WalletRequest) -> Result<WalletBalance>;

    #[rpc(name = "wallet_create")]
    fn create(
        &self,
        request: CreateWalletRequest,
        walletkind: WalletKind,
    ) -> Result<(SecKey, Option<String>)>;

    #[rpc(name = "wallet_restore")]
    fn restore(&self, request: CreateWalletRequest, mnemonics: Mnemonic) -> Result<SecKey>;

    #[rpc(name = "wallet_restoreBasic")]
    fn restore_basic(&self, request: CreateWalletRequest, view_key: SecUtf8) -> Result<SecKey>;

    #[rpc(name = "wallet_delete")]
    fn delete(&self, request: CreateWalletRequest) -> Result<()>;

    #[rpc(name = "wallet_createStakingAddress")]
    fn create_staking_address(&self, request: WalletRequest) -> Result<String>;

    #[rpc(name = "wallet_createStakingAddressBatch")]
    fn create_staking_address_batch(&self, request: WalletRequest, count: u32) -> Result<u32>;

    #[rpc(name = "wallet_createWatchStakingAddress")]
    fn create_watch_staking_address(
        &self,
        request: WalletRequest,
        public_key: PublicKey,
    ) -> Result<String>;

    #[rpc(name = "wallet_createTransferAddress")]
    fn create_transfer_address(&self, request: WalletRequest) -> Result<String>;

    #[rpc(name = "wallet_createTransferAddressBatch")]
    fn create_transfer_address_batch(&self, request: WalletRequest, count: u32) -> Result<u32>;

    #[rpc(name = "wallet_createWatchTransferAddress")]
    fn create_watch_transfer_address(
        &self,
        request: WalletRequest,
        public_key: PublicKey,
    ) -> Result<String>;

    #[rpc(name = "wallet_getViewKey")]
    fn get_view_key(&self, request: WalletRequest, private: bool) -> Result<String>;

    #[rpc(name = "wallet_list")]
    fn list(&self) -> Result<Vec<String>>;

    #[rpc(name = "wallet_listPublicKeys")]
    fn list_public_keys(&self, request: WalletRequest) -> Result<Vec<PublicKey>>;

    #[rpc(name = "wallet_listStakingAddresses")]
    fn list_staking_addresses(&self, request: WalletRequest) -> Result<Vec<String>>;

    #[rpc(name = "wallet_listTransferAddresses")]
    fn list_transfer_addresses(&self, request: WalletRequest) -> Result<Vec<String>>;

    #[rpc(name = "wallet_listUTxO")]
    fn list_utxo(&self, request: WalletRequest) -> Result<UnspentTransactions>;

    #[rpc(name = "wallet_sendToAddress")]
    fn send_to_address(
        &self,
        request: WalletRequest,
        to_address: String,
        amount: Coin,
        view_keys: Vec<String>,
    ) -> Result<String>;

    #[rpc(name = "wallet_buildRawTransferTx")]
    fn build_raw_transfer_tx(
        &self,
        request: WalletRequest,
        to_address: String,
        amount: Coin,
        view_keys: Vec<String>,
    ) -> Result<String>;

    #[rpc(name = "wallet_broadcastSignedTransferTx")]
    fn broadcast_signed_transfer_tx(
        &self,
        request: WalletRequest,
        signed_tx: String,
    ) -> Result<String>;

    #[rpc(name = "wallet_transactions")]
    fn transactions(
        &self,
        request: WalletRequest,
        offset: usize,
        limit: usize,
        reversed: bool,
    ) -> Result<Vec<TransactionChange>>;

    #[rpc(name = "wallet_exportTransaction")]
    fn export_plain_tx(&self, request: WalletRequest, txid: String) -> Result<String>;

    #[rpc(name = "wallet_importTransaction")]
    fn import_plain_tx(&self, request: WalletRequest, tx: String) -> Result<Coin>;

    #[rpc(name = "wallet_getEncKey")]
    fn get_enc_key(&self, request: CreateWalletRequest) -> Result<SecKey>;

    #[rpc(name = "wallet_export")]
    fn export(&self, request: WalletRequest) -> Result<WalletInfo>;

    #[rpc(name = "wallet_import")]
    fn import(&self, request: CreateWalletRequest, wallet_info: WalletInfo) -> Result<SecKey>;
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
    fn balance(&self, request: WalletRequest) -> Result<WalletBalance> {
        self.client
            .balance(&request.name, &request.enckey)
            .map_err(to_rpc_error)
    }

    fn create(
        &self,
        request: CreateWalletRequest,
        kind: WalletKind,
    ) -> Result<(SecKey, Option<String>)> {
        // TODO: add hardware wallet
        let (enckey, mnemonic) = self
            .client
            .new_wallet(&request.name, &request.passphrase, kind)
            .map_err(to_rpc_error)?;

        self.client
            .new_staking_address(&request.name, &enckey)
            .map_err(to_rpc_error)?;
        self.client
            .new_transfer_address(&request.name, &enckey)
            .map_err(to_rpc_error)?;

        match (kind, mnemonic) {
            (WalletKind::Basic, None) => Ok((enckey, None)),
            (WalletKind::HD, Some(mnemonic)) => {
                Ok((enckey, Some(mnemonic.unsecure_phrase().to_string())))
            }
            _ => Err(rpc_error_from_string(
                "Internal Error: Invalid mnemonic for given wallet kind".to_owned(),
            )),
        }
    }

    fn restore(&self, request: CreateWalletRequest, mnemonic: Mnemonic) -> Result<SecKey> {
        let enckey = self
            .client
            .restore_wallet(&request.name, &request.passphrase, &mnemonic)
            .map_err(to_rpc_error)?;

        mnemonic.zeroize();

        self.client
            .new_staking_address(&request.name, &enckey)
            .map_err(to_rpc_error)?;
        self.client
            .new_transfer_address(&request.name, &enckey)
            .map_err(to_rpc_error)?;
        Ok(enckey)
    }

    fn restore_basic(&self, request: CreateWalletRequest, view_key: SecUtf8) -> Result<SecKey> {
        let view_key =
            PrivateKey::deserialize_from(&hex::decode(view_key.unsecure()).map_err(to_rpc_error)?)
                .map_err(to_rpc_error)?;
        let enckey = self
            .client
            .restore_basic_wallet(&request.name, &request.passphrase, &view_key)
            .map_err(to_rpc_error)?;

        Ok(enckey)
    }

    fn delete(&self, request: CreateWalletRequest) -> Result<()> {
        self.client
            .delete_wallet(&request.name, &request.passphrase)
            .map_err(to_rpc_error)
    }

    fn create_staking_address(&self, request: WalletRequest) -> Result<String> {
        self.client
            .new_staking_address(&request.name, &request.enckey)
            .map(|staked_state_addr| staked_state_addr.to_string())
            .map_err(to_rpc_error)
    }
    fn create_staking_address_batch(&self, request: WalletRequest, count: u32) -> Result<u32> {
        for _i in 0..count {
            self.client
                .new_staking_address(&request.name, &request.enckey)
                .map(|staked_state_addr| staked_state_addr.to_string())
                .map_err(to_rpc_error)?;
        }
        Ok(count)
    }

    fn create_watch_staking_address(
        &self,
        request: WalletRequest,
        public_key: PublicKey,
    ) -> Result<String> {
        self.client
            .new_watch_staking_address(&request.name, &request.enckey, &public_key)
            .map(|staked_state_addr| staked_state_addr.to_string())
            .map_err(to_rpc_error)
    }

    fn create_transfer_address(&self, request: WalletRequest) -> Result<String> {
        let extended_address = self
            .client
            .new_transfer_address(&request.name, &request.enckey)
            .map_err(to_rpc_error)?;

        Ok(extended_address.to_string())
    }

    fn create_transfer_address_batch(&self, request: WalletRequest, count: u32) -> Result<u32> {
        for _i in 0..count {
            self.client
                .new_transfer_address(&request.name, &request.enckey)
                .map_err(to_rpc_error)?;
        }
        Ok(count)
    }

    fn create_watch_transfer_address(
        &self,
        request: WalletRequest,
        public_key: PublicKey,
    ) -> Result<String> {
        let extended_address = self
            .client
            .new_watch_transfer_address(&request.name, &request.enckey, &public_key)
            .map_err(to_rpc_error)?;

        Ok(extended_address.to_string())
    }

    fn get_view_key(&self, request: WalletRequest, private: bool) -> Result<String> {
        let s = if private {
            hex::encode(
                &self
                    .client
                    .view_key_private(&request.name, &request.enckey)
                    .map_err(to_rpc_error)?
                    .serialize(),
            )
        } else {
            self.client
                .view_key(&request.name, &request.enckey)
                .map_err(to_rpc_error)?
                .to_string()
        };
        Ok(s)
    }

    fn list(&self) -> Result<Vec<String>> {
        self.client.wallets().map_err(to_rpc_error)
    }

    fn list_public_keys(&self, request: WalletRequest) -> Result<Vec<PublicKey>> {
        self.client
            .public_keys(&request.name, &request.enckey)
            .map(|keys| keys.into_iter().collect())
            .map_err(to_rpc_error)
    }

    fn list_staking_addresses(&self, request: WalletRequest) -> Result<Vec<String>> {
        self.client
            .staking_addresses(&request.name, &request.enckey)
            .map(|addresses| addresses.iter().map(ToString::to_string).collect())
            .map_err(to_rpc_error)
    }

    fn list_transfer_addresses(&self, request: WalletRequest) -> Result<Vec<String>> {
        self.client
            .transfer_addresses(&request.name, &request.enckey)
            .map(|addresses| addresses.iter().map(ToString::to_string).collect())
            .map_err(to_rpc_error)
    }

    fn list_utxo(&self, request: WalletRequest) -> Result<UnspentTransactions> {
        self.client
            .unspent_transactions(&request.name, &request.enckey)
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
        let mut view_keys = view_keys
            .iter()
            .map(|view_key| PublicKey::from_str(view_key))
            .collect::<CommonResult<BTreeSet<PublicKey>>>()
            .map_err(to_rpc_error)?;
        let tx_id = self
            .client
            .send_to_address(
                &request.name,
                &request.enckey,
                amount,
                address,
                &mut view_keys,
                self.network_id,
            )
            .map_err(to_rpc_error)?;
        Ok(hex::encode(tx_id))
    }

    fn build_raw_transfer_tx(
        &self,
        request: WalletRequest,
        to_address: String,
        amount: Coin,
        view_keys: Vec<String>,
    ) -> Result<String> {
        let to_address = to_address
            .parse::<ExtendedAddr>()
            .map_err(|err| rpc_error_from_string(format!("{}", err)))?;
        let view_keys = view_keys
            .iter()
            .map(|view_key| PublicKey::from_str(view_key))
            .collect::<CommonResult<Vec<PublicKey>>>()
            .map_err(to_rpc_error)?;
        let unsigned_transfer_tx = self
            .client
            .build_raw_transfer_tx(
                &request.name,
                &request.enckey,
                to_address,
                amount,
                view_keys,
                self.network_id,
            )
            .map_err(to_rpc_error)?;
        let raw_data = unsigned_transfer_tx.encode();
        let b64 = base64::encode(&raw_data);
        Ok(b64)
    }

    fn broadcast_signed_transfer_tx(
        &self,
        request: WalletRequest,
        signed_tx: String,
    ) -> Result<String> {
        let raw_data = base64::decode(&signed_tx).map_err(to_rpc_error)?;
        let signed_tx =
            SignedTransferTransaction::decode(&mut raw_data.as_slice()).map_err(to_rpc_error)?;
        let tx_id = self
            .client
            .broadcast_signed_transfer_tx(&request.name, &request.enckey, signed_tx)
            .map_err(to_rpc_error)?;
        Ok(hex::encode(tx_id))
    }

    fn export_plain_tx(&self, request: WalletRequest, txid: String) -> Result<String> {
        let tx_info = self
            .client
            .export_plain_tx(&request.name, &request.enckey, &txid)
            .map_err(to_rpc_error)?;
        tx_info.encode().map_err(to_rpc_error)
    }

    fn import_plain_tx(&self, request: WalletRequest, tx: String) -> Result<Coin> {
        self.client
            .import_plain_tx(&request.name, &request.enckey, &tx)
            .map_err(to_rpc_error)
    }

    fn transactions(
        &self,
        request: WalletRequest,
        offset: usize,
        limit: usize,
        reversed: bool,
    ) -> Result<Vec<TransactionChange>> {
        self.client
            .history(&request.name, &request.enckey, offset, limit, reversed)
            .map_err(to_rpc_error)
    }

    fn get_enc_key(&self, request: CreateWalletRequest) -> Result<SecKey> {
        self.client
            .auth_token(&request.name, &request.passphrase)
            .map_err(to_rpc_error)
    }

    fn export(&self, request: WalletRequest) -> Result<WalletInfo> {
        let wallet_info = self
            .client
            .export_wallet(&request.name, &request.enckey)
            .map_err(to_rpc_error)?;
        Ok(wallet_info)
    }

    fn import(&self, request: CreateWalletRequest, wallet_info: WalletInfo) -> Result<SecKey> {
        self.client
            .import_wallet(&request.name, &request.passphrase, wallet_info)
            .map_err(to_rpc_error)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use secstr::SecUtf8;

    use parity_scale_codec::Encode;

    use chain_core::init::coin::CoinError;
    use chain_core::state::tendermint::BlockHeight;
    use chain_core::state::ChainState;
    use chain_core::tx::data::input::TxoSize;
    use chain_core::tx::data::TxId;
    use chain_core::tx::fee::{Fee, FeeAlgorithm};
    use chain_core::tx::{PlainTxAux, TransactionId, TxAux, TxEnclaveAux, TxObfuscated};
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::lite;
    use client_common::tendermint::mock;
    use client_common::tendermint::types::*;
    use client_common::tendermint::Client;
    use client_common::{
        seckey::derive_enckey, Error, ErrorKind, Result as CommonResult, SignedTransaction,
        Transaction,
    };
    use client_core::service::HwKeyService;
    use client_core::signer::WalletSignerManager;
    use client_core::transaction_builder::DefaultWalletTransactionBuilder;
    use client_core::wallet::DefaultWalletClient;
    use client_core::TransactionObfuscation;

    #[derive(Default, Clone)]
    pub struct ZeroFeeAlgorithm;

    impl FeeAlgorithm for ZeroFeeAlgorithm {
        fn calculate_fee(&self, _num_bytes: usize) -> std::result::Result<Fee, CoinError> {
            Ok(Fee::new(Coin::zero()))
        }

        fn calculate_for_txaux(&self, _txaux: &TxAux) -> std::result::Result<Fee, CoinError> {
            Ok(Fee::new(Coin::zero()))
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
            unreachable!()
        }

        fn encrypt(&self, transaction: SignedTransaction) -> CommonResult<TxAux> {
            let txpayload = transaction.encode();

            match transaction {
                SignedTransaction::TransferTransaction(tx, _) => {
                    Ok(TxAux::EnclaveTx(TxEnclaveAux::TransferTx {
                        inputs: tx.inputs.clone(),
                        no_of_outputs: tx.outputs.len() as TxoSize,
                        payload: TxObfuscated {
                            txid: tx.id(),
                            key_from: BlockHeight::genesis(),
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
                            key_from: BlockHeight::genesis(),
                            init_vector: [0u8; 12],
                            txpayload: plain.encode(),
                        },
                    }))
                }
                SignedTransaction::WithdrawUnbondedStakeTransaction(tx, witness) => {
                    let plain = PlainTxAux::WithdrawUnbondedStakeTx(tx.clone());
                    Ok(TxAux::EnclaveTx(TxEnclaveAux::WithdrawUnbondedStakeTx {
                        no_of_outputs: tx.outputs.len() as TxoSize,
                        witness,
                        payload: TxObfuscated {
                            txid: tx.id(),
                            key_from: BlockHeight::genesis(),
                            init_vector: [0u8; 12],
                            txpayload: plain.encode(),
                        },
                    }))
                }
            }
        }
    }

    type TestWalletTransactionBuilder =
        DefaultWalletTransactionBuilder<MemoryStorage, ZeroFeeAlgorithm, MockTransactionCipher>;
    type TestWalletClient =
        DefaultWalletClient<MemoryStorage, MockRpcClient, TestWalletTransactionBuilder>;

    #[derive(Default, Clone)]
    pub struct MockRpcClient;

    impl Client for MockRpcClient {
        fn genesis(&self) -> CommonResult<Genesis> {
            unreachable!("genesis")
        }

        fn status(&self) -> CommonResult<Status> {
            Ok(Status {
                sync_info: status::SyncInfo {
                    latest_block_height: Height::default(),
                    latest_app_hash: Some(
                        Hash::from_str(
                            "3891040F29C6A56A5E36B17DCA6992D8F91D1EAAB4439D008D19A9D703271D3C",
                        )
                        .unwrap(),
                    ),
                    ..mock::sync_info()
                },
                ..mock::status_response()
            })
        }

        fn block(&self, _height: u64) -> CommonResult<Block> {
            Ok(Block {
                header: Header {
                    app_hash: hex::decode(
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
                    app_hash: hex::decode(
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

        fn query_state_batch<T: Iterator<Item = u64>>(
            &self,
            _heights: T,
        ) -> CommonResult<Vec<ChainState>> {
            unreachable!()
        }
    }

    #[test]
    fn balance_should_return_wallet_balance() {
        let wallet_rpc = setup_wallet_rpc();
        let (create_request, wallet_request) = create_wallet_request("Default", "123456");

        wallet_rpc
            .create(create_request, WalletKind::Basic)
            .unwrap();
        assert_eq!(
            WalletBalance::default(),
            wallet_rpc.balance(wallet_request).unwrap()
        )
    }

    mod create {
        use super::*;

        #[test]
        fn create_duplicated_wallet_should_throw_error() {
            let wallet_rpc = setup_wallet_rpc();
            let (create_request, _) = create_wallet_request("Default", "123456");

            wallet_rpc
                .create(create_request.clone(), WalletKind::Basic)
                .unwrap();

            assert_eq!(
                to_rpc_error(Error::new(
                    ErrorKind::InvalidInput,
                    "Wallet with name (Default) already exists"
                )),
                wallet_rpc
                    .create(create_request, WalletKind::Basic)
                    .unwrap_err()
            );
        }

        #[test]
        fn create_should_create_named_wallet() {
            let wallet_rpc = setup_wallet_rpc();

            wallet_rpc
                .create(
                    create_wallet_request("Default", "123456").0,
                    WalletKind::Basic,
                )
                .unwrap();

            assert_eq!(vec!["Default"], wallet_rpc.list().unwrap());
        }

        #[test]
        fn create_should_create_staking_and_transfer_address_for_the_wallet() {
            let wallet_rpc = setup_wallet_rpc();
            let (create_request, wallet_request) = create_wallet_request("Default", "123456");

            wallet_rpc
                .create(create_request, WalletKind::Basic)
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
        let (create_request, wallet_request) = create_wallet_request("Default", "123456");

        wallet_rpc
            .create(create_request, WalletKind::Basic)
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
        let (create_request, wallet_request) = create_wallet_request("Default", "123456");

        wallet_rpc
            .create(create_request, WalletKind::Basic)
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
        let (create_request, wallet_request) = create_wallet_request("Default", "123456");

        wallet_rpc
            .create(create_request, WalletKind::Basic)
            .unwrap();

        assert_eq!(
            wallet_rpc
                .get_view_key(wallet_request.clone(), false)
                .unwrap()
                .len(),
            66
        );
    }

    #[test]
    fn test_export_import_wallet() {
        let wallet_rpc = setup_wallet_rpc();
        let (create_request, wallet_request) = create_wallet_request("Default", "123456");
        wallet_rpc
            .create(create_request.clone(), WalletKind::Basic)
            .unwrap();
        let old_staking_address = wallet_rpc
            .list_staking_addresses(wallet_request.clone())
            .unwrap()[0]
            .clone();
        let old_transfer_address = wallet_rpc
            .list_transfer_addresses(wallet_request.clone())
            .unwrap()[0]
            .clone();
        let old_enckey = wallet_rpc.get_enc_key(create_request.clone()).unwrap();
        let wallet_info = wallet_rpc.export(wallet_request.clone()).unwrap();
        // delete the old wallet
        wallet_rpc.delete(create_request.clone()).unwrap();
        let new_enckey = wallet_rpc
            .import(create_request.clone(), wallet_info)
            .unwrap();
        let new_staking_address = wallet_rpc
            .list_staking_addresses(wallet_request.clone())
            .unwrap()[0]
            .clone();
        let new_transfer_address = wallet_rpc
            .list_transfer_addresses(wallet_request.clone())
            .unwrap()[0]
            .clone();
        assert_eq!(old_transfer_address, new_transfer_address);
        assert_eq!(old_staking_address, new_staking_address);
        assert_eq!(old_enckey, new_enckey);
    }

    #[test]
    fn list_should_list_all_wallets() {
        let wallet_rpc = setup_wallet_rpc();

        assert_eq!(0, wallet_rpc.list().unwrap().len());

        wallet_rpc
            .create(
                create_wallet_request("Default", "123456").0,
                WalletKind::Basic,
            )
            .unwrap();

        assert_eq!(vec!["Default"], wallet_rpc.list().unwrap());

        wallet_rpc
            .create(
                create_wallet_request("Personal", "123456").0,
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
        let (create_request, wallet_request) = create_wallet_request("Default", "123456");

        wallet_rpc
            .create(create_request, WalletKind::Basic)
            .unwrap();
        assert_eq!(
            0,
            wallet_rpc
                .transactions(wallet_request.clone(), 0, 100, false)
                .unwrap()
                .len()
        )
    }

    fn make_test_wallet_client(storage: MemoryStorage) -> TestWalletClient {
        let signer_manager = WalletSignerManager::new(storage.clone(), HwKeyService::default());
        let transaction_builder = DefaultWalletTransactionBuilder::new(
            signer_manager,
            ZeroFeeAlgorithm::default(),
            MockTransactionCipher,
        );
        DefaultWalletClient::new(
            storage,
            MockRpcClient,
            transaction_builder,
            None,
            HwKeyService::default(),
        )
    }

    fn setup_wallet_rpc() -> WalletRpcImpl<TestWalletClient> {
        let storage = MemoryStorage::default();

        let wallet_client = make_test_wallet_client(storage.clone());
        let chain_id = 171u8;

        WalletRpcImpl::new(wallet_client, chain_id)
    }

    fn create_wallet_request(name: &str, passphrase: &str) -> (CreateWalletRequest, WalletRequest) {
        let passphrase = SecUtf8::from(passphrase);
        (
            CreateWalletRequest {
                name: name.to_owned(),
                passphrase: passphrase.clone(),
            },
            WalletRequest {
                name: name.to_owned(),
                enckey: derive_enckey(&passphrase, name).unwrap(),
            },
        )
    }

    #[test]
    fn hdwallet_should_create_hd_wallet() {
        let wallet_rpc = setup_wallet_rpc();

        wallet_rpc
            .create(create_wallet_request("Default", "123456").0, WalletKind::HD)
            .unwrap();
    }

    #[test]
    fn hdwallet_should_recover_hd_wallet() {
        let wallet_rpc = setup_wallet_rpc();

        wallet_rpc
            .restore(
                create_wallet_request("Default", "123456").0,
                Mnemonic::from_secstr(&SecUtf8::from("online hire print other clock like betray vote hollow bus insect meadow replace two tape worry quality disease cabin girl tree pudding issue radar")).unwrap()
            )
            .unwrap();
    }

    #[test]
    fn wallet_can_send_amount_should_fail_with_insufficient_amount() {
        let wallet_rpc = setup_wallet_rpc();
        let (create_request, wallet_request) = create_wallet_request("Default", "123456");

        wallet_rpc
            .restore(
                create_request,
                Mnemonic::from_secstr(&SecUtf8::from("speed tortoise kiwi forward extend baby acoustic foil coach castle ship purchase unlock base hip erode tag keen present vibrant oyster cotton write fetch")).unwrap()
            )
            .unwrap();

        // NOTE: this changed in 0.4 due to a migration to x-only pubkeys, as specified by BIP-340
        // + switch to blake3

        let expect_addrs = [
            "dcro166l9msr047ek4g5e00x6fsycwpkpkcm40y28cd6l7x2t93tyy25sg43uex",
            "dcro1plg2e79emeypwaq2w2aryvteq9qefxhujc9xplslawz70dk6s8hstaw9kp",
            "dcro1jy5a4p5ucrn3kmkz03ju8fla7uql36m5fn0c62t5v2hm322f0xhqxdef5w",
        ];
        let addrs = expect_addrs
            .iter()
            .map(|s| {
                let addr = wallet_rpc
                    .create_transfer_address(wallet_request.clone())
                    .unwrap();
                assert_eq!(addr, *s);
                addr
            })
            .collect::<Vec<_>>();

        let viewkey = wallet_rpc
            .get_view_key(wallet_request.clone(), false)
            .unwrap();

        let send_result = wallet_rpc.send_to_address(
            wallet_request.clone(),
            addrs[0].clone(),
            Coin::from(1_0000u32),
            vec![viewkey],
        );
        assert!(send_result.is_err());
    }
}
