use std::str::FromStr;

use failure::ResultExt;
use hex::{decode, encode};
use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};

use chain_core::common::{H256, HASH_SIZE_256};
use chain_core::init::coin::Coin;
use chain_core::state::account::{StakedStateAddress, StakedStateOpAttributes};
use chain_core::tx::data::access::{TxAccess, TxAccessPolicy};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use client_common::balance::BalanceChange;
use client_common::{Error, ErrorKind, PublicKey, Result as CommonResult};
use client_core::{MultiSigWalletClient, WalletClient};
use client_network::NetworkOpsClient;

use crate::server::{rpc_error_from_string, to_rpc_error, WalletRequest};

#[derive(Serialize, Deserialize)]
pub struct RowTx {
    kind: String,
    transaction_id: String,
    address: String,
    height: String,
    time: String,
    amount: String,
}

#[rpc]
pub trait ClientRpc: Send + Sync {
    #[rpc(name = "wallet_newMultiSigSession")]
    fn wallet_new_multi_sig_session(
        &self,
        request: WalletRequest,
        message: String,
        signer_public_keys: Vec<String>,
        self_public_key: String,
    ) -> Result<String>;

    #[rpc(name = "multiSig_nonceCommitment")]
    fn multi_sig_nonce_commitment(&self, session_id: String, passphrase: SecUtf8) -> Result<String>;

    #[rpc(name = "multi_sig_add_nonce_commitment")]
    fn multi_sig_add_nonce_commitment(
        &self,
        session_id: String,
        passphrase: SecUtf8,
        nonce_commitment: String,
        public_key: String,
    ) -> Result<()>;

    #[rpc(name = "multiSig_nonce")]
    fn multi_sig_nonce(&self, session_id: String, passphrase: SecUtf8) -> Result<String>;

    #[rpc(name = "multiSig_addNonce")]
    fn multi_sig_add_nonce(
        &self,
        session_id: String,
        passphrase: SecUtf8,
        nonce: String,
        public_key: String,
    ) -> Result<()>;

    #[rpc(name = "multiSig_partialSign")]
    fn multi_sig_partial_signature(&self, session_id: String, passphrase: SecUtf8) -> Result<String>;

    #[rpc(name = "multiSig_addPartialSignature")]
    fn multi_sig_add_partial_signature(
        &self,
        session_id: String,
        passphrase: SecUtf8,
        partial_signature: String,
        public_key: String,
    ) -> Result<()>;

    #[rpc(name = "multiSig_signature")]
    fn multi_sig_signature(&self, session_id: String, passphrase: SecUtf8) -> Result<String>;

    #[rpc(name = "staking_depositStake")]
    fn staking_deposit_stake(
        &self,
        request: WalletRequest,
        to_address: String,
        inputs: Vec<TxoPointer>,
    ) -> Result<()>;

    #[rpc(name = "staking_unbondStake")]
    fn staking_unbond_stake(
        &self,
        request: WalletRequest,
        staking_address: String,
        amount: Coin,
    ) -> Result<()>;

    #[rpc(name = "staking_withdrawAllUnbondedStake")]
    fn staking_withdraw_all_unbonded_stake(
        &self,
        request: WalletRequest,
        from_address: String,
        to_address: String,
        view_keys: Vec<String>,
    ) -> Result<()>;

    #[rpc(name = "wallet_addresses")]
    fn wallet_addresses(&self, request: WalletRequest) -> Result<Vec<String>>;

    #[rpc(name = "wallet_balance")]
    fn wallet_balance(&self, request: WalletRequest) -> Result<Coin>;

    #[rpc(name = "wallet_create")]
    fn wallet_create(&self, request: WalletRequest) -> Result<String>;

    #[rpc(name = "wallet_list")]
    fn wallet_list(&self) -> Result<Vec<String>>;

    #[rpc(name = "wallet_sendToAddress")]
    fn wallet_send_to_address(
        &self,
        request: WalletRequest,
        to_address: String,
        amount: Coin,
        view_keys: Vec<String>,
    ) -> Result<()>;

    #[rpc(name = "wallet_transactions")]
    fn wallet_transactions(&self, request: WalletRequest) -> Result<Vec<RowTx>>;
}

pub struct ClientRpcImpl<T, N>
where
    T: WalletClient,
    N: NetworkOpsClient,
{
    client: T,
    ops_client: N,
    network_id: u8,
}

impl<T, N> ClientRpcImpl<T, N>
where
    T: WalletClient,
    N: NetworkOpsClient,
{
    pub fn new(
        client: T,
        ops_client: N,
        network_id: u8,
    ) -> Self {
        ClientRpcImpl {
            client,
            ops_client,
            network_id,
        }
    }
}

impl<T, N> ClientRpc for ClientRpcImpl<T, N>
where
    T: WalletClient + MultiSigWalletClient + 'static,
    N: NetworkOpsClient + 'static,
{
    fn wallet_addresses(&self, request: WalletRequest) -> Result<Vec<String>> {
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

    fn wallet_balance(&self, request: WalletRequest) -> Result<Coin> {
        match self.client.balance(&request.name, &request.passphrase) {
            Ok(balance) => Ok(balance),
            Err(e) => Err(to_rpc_error(e)),
        }
    }

    fn wallet_create(&self, request: WalletRequest) -> Result<String> {
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

    fn wallet_list(&self) -> Result<Vec<String>> {
        self.client.wallets().map_err(to_rpc_error)
    }

    fn wallet_send_to_address(
        &self,
        request: WalletRequest,
        to_address: String,
        amount: Coin,
        view_keys: Vec<String>,
    ) -> Result<()> {
        let address = to_address
            .parse::<ExtendedAddr>()
            .map_err(|err| rpc_error_from_string(format!("{}", err)))?;
        let tx_out = TxOut::new(address, amount);

        let view_keys = view_keys
            .into_iter()
            .map(|key| PublicKey::from_str(&key))
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
            .new_single_transfer_address(&request.name, &request.passphrase)
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
            .map_err(to_rpc_error)
    }

    fn wallet_transactions(&self, request: WalletRequest) -> Result<Vec<RowTx>> {
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

    fn wallet_new_multi_sig_session(
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

    fn multi_sig_nonce_commitment(&self, session_id: String, passphrase: SecUtf8) -> Result<String> {
        let session_id = parse_hash_256(session_id).map_err(to_rpc_error)?;

        self.client
            .nonce_commitment(&session_id, &passphrase)
            .map(serialize_hash_256)
            .map_err(to_rpc_error)
    }

    fn multi_sig_add_nonce_commitment(
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

    fn multi_sig_nonce(&self, session_id: String, passphrase: SecUtf8) -> Result<String> {
        let session_id = parse_hash_256(session_id).map_err(to_rpc_error)?;

        self.client
            .nonce(&session_id, &passphrase)
            .map(serialize_public_key)
            .map_err(to_rpc_error)
    }

    fn multi_sig_add_nonce(
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

    fn multi_sig_partial_signature(&self, session_id: String, passphrase: SecUtf8) -> Result<String> {
        let session_id = parse_hash_256(session_id).map_err(to_rpc_error)?;

        self.client
            .partial_signature(&session_id, &passphrase)
            .map(serialize_hash_256)
            .map_err(to_rpc_error)
    }

    fn multi_sig_add_partial_signature(
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

    fn multi_sig_signature(&self, session_id: String, passphrase: SecUtf8) -> Result<String> {
        let session_id = parse_hash_256(session_id).map_err(to_rpc_error)?;

        self.client
            .signature(&session_id, &passphrase)
            .map(|sig| sig.to_string())
            .map_err(to_rpc_error)
    }

    fn staking_deposit_stake(
        &self,
        request: WalletRequest,
        to_address: String,
        inputs: Vec<TxoPointer>,
    ) -> Result<()> {
        let addr = StakedStateAddress::from_str(&to_address)
            .context(ErrorKind::DeserializationError)
            .map_err(Into::<Error>::into)
            .map_err(to_rpc_error)?;
        let attr = StakedStateOpAttributes::new(self.network_id);
        let transaction = self
            .ops_client
            .create_deposit_bonded_stake_transaction(
                &request.name,
                &request.passphrase,
                inputs,
                addr,
                attr,
            )
            .map_err(to_rpc_error)?;

        self.client
            .broadcast_transaction(&transaction)
            .map_err(to_rpc_error)
    }

    fn staking_unbond_stake(
        &self,
        request: WalletRequest,
        staking_address: String,
        amount: Coin,
    ) -> Result<()> {
        let attr = StakedStateOpAttributes::new(self.network_id);
        let addr = StakedStateAddress::from_str(&staking_address)
            .context(ErrorKind::DeserializationError)
            .map_err(Into::<Error>::into)
            .map_err(to_rpc_error)?;

        let transaction = self
            .ops_client
            .create_unbond_stake_transaction(
                &request.name,
                &request.passphrase,
                &addr,
                amount,
                attr,
            )
            .map_err(to_rpc_error)?;

        self.client
            .broadcast_transaction(&transaction)
            .map_err(to_rpc_error)
    }

    fn staking_withdraw_all_unbonded_stake(
        &self,
        request: WalletRequest,
        from_address: String,
        to_address: String,
        view_keys: Vec<String>,
    ) -> Result<()> {
        let from_address = StakedStateAddress::from_str(&from_address)
            .context(ErrorKind::DeserializationError)
            .map_err(Into::<Error>::into)
            .map_err(to_rpc_error)?;
        let to_address = ExtendedAddr::from_str(&to_address)
            .context(ErrorKind::DeserializationError)
            .map_err(Into::<Error>::into)
            .map_err(to_rpc_error)?;
        let view_keys = view_keys
            .into_iter()
            .map(|key| PublicKey::from_str(&key))
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

        let transaction = self
            .ops_client
            .create_withdraw_all_unbonded_stake_transaction(
                &request.name,
                &request.passphrase,
                &from_address,
                to_address,
                attributes,
            )
            .map_err(to_rpc_error)?;

        self.client
            .broadcast_transaction(&transaction)
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

#[cfg(test)]
pub mod tests {
    use super::*;

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
    fn test_create_duplicated_wallet() {
        let client_rpc = setup_client_rpc();

        assert_eq!(
            "Default".to_owned(),
            client_rpc
                .wallet_create(create_wallet_request("Default", "123456"))
                .unwrap()
        );

        assert_eq!(
            to_rpc_error(Error::from(ErrorKind::AlreadyExists)),
            client_rpc
                .wallet_create(create_wallet_request("Default", "123456"))
                .unwrap_err()
        );
    }

    #[test]
    fn test_create_and_list_wallet_flow() {
        let client_rpc = setup_client_rpc();

        assert_eq!(0, client_rpc.wallet_list().unwrap().len());

        assert_eq!(
            "Default".to_owned(),
            client_rpc
                .wallet_create(create_wallet_request("Default", "123456"))
                .unwrap()
        );

        assert_eq!(vec!["Default"], client_rpc.wallet_list().unwrap());

        assert_eq!(
            "Personal".to_owned(),
            client_rpc
                .wallet_create(create_wallet_request("Personal", "123456"))
                .unwrap()
        );

        let wallet_list = client_rpc.wallet_list().unwrap();
        assert_eq!(2, wallet_list.len());
        assert!(wallet_list.contains(&"Default".to_owned()));
        assert!(wallet_list.contains(&"Personal".to_owned()));
    }

    #[test]
    fn test_create_and_list_wallet_addresses_flow() {
        let client_rpc = setup_client_rpc();

        assert_eq!(
            to_rpc_error(Error::from(ErrorKind::WalletNotFound)),
            client_rpc
                .wallet_addresses(create_wallet_request("Default", "123456"))
                .unwrap_err()
        );

        assert_eq!(
            "Default".to_owned(),
            client_rpc
                .wallet_create(create_wallet_request("Default", "123456"))
                .unwrap()
        );

        assert_eq!(
            1,
            client_rpc
                .wallet_addresses(create_wallet_request("Default", "123456"))
                .unwrap()
                .len()
        );
    }

    #[test]
    fn test_wallet_balance() {
        let client_rpc = setup_client_rpc();

        client_rpc
            .wallet_create(create_wallet_request("Default", "123456"))
            .unwrap();
        assert_eq!(
            Coin::new(30).unwrap(),
            client_rpc
                .wallet_balance(create_wallet_request("Default", "123456"))
                .unwrap()
        )
    }

    #[test]
    fn test_wallet_transactions() {
        let client_rpc = setup_client_rpc();

        client_rpc
            .wallet_create(create_wallet_request("Default", "123456"))
            .unwrap();
        assert_eq!(
            1,
            client_rpc
                .wallet_transactions(create_wallet_request("Default", "123456"))
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
    fn make_test_ops_client(storage: MemoryStorage) -> TestOpsClient {
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
            MockRpcClient,
            ZeroFeeAlgorithm::default(),
            MockTransactionCipher,
        )
    }

    fn setup_client_rpc() -> ClientRpcImpl<
        TestWalletClient,
        TestOpsClient,
    > {
        let storage = MemoryStorage::default();

        let wallet_client = make_test_wallet_client(storage.clone());
        let ops_client = make_test_ops_client(storage.clone());
        let chain_id = 171u8;

        ClientRpcImpl::new(wallet_client, ops_client, chain_id)
    }

    fn create_wallet_request(name: &str, passphrase: &str) -> WalletRequest {
        WalletRequest {
            name: name.to_owned(),
            passphrase: SecUtf8::from(passphrase),
        }
    }
}
