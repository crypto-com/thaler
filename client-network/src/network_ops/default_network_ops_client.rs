use crate::NetworkOpsClient;
use chain_core::init::coin::Coin;
use chain_core::state::account::Nonce;
use chain_core::state::account::StakedState;
use chain_core::state::account::{DepositBondTx, UnbondTx};
use chain_core::state::account::{StakedStateAddress, StakedStateOpAttributes};
use chain_core::state::account::{StakedStateOpWitness, WithdrawUnbondedTx};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::{TransactionId, TxAux};
use client_common::tendermint::Client;
use client_common::{Error, ErrorKind, Result};
use client_core::signer::Signer;
use client_core::UnspentTransactions;
use client_core::WalletClient;
use parity_codec::Decode;
use secstr::SecUtf8;
/// Default implementation of `NetworkOpsClient`
pub struct DefaultNetworkOpsClient<'a, W, S, C>
where
    W: WalletClient,
    S: Signer,
    C: Client,
{
    wallet_client: &'a W,
    signer: &'a S,
    client: &'a C,
}

impl<'a, W, S, C> DefaultNetworkOpsClient<'a, W, S, C>
where
    W: WalletClient,
    S: Signer,
    C: Client,
{
    /// Creates a new instance of `DefaultNetworkOpsClient`
    pub fn new(wallet_client: &'a W, signer: &'a S, client: &'a C) -> Self {
        Self {
            wallet_client,
            signer,
            client,
        }
    }

    /// Get account info
    pub fn get_account(&self, staked_state_address: &[u8]) -> Result<StakedState> {
        self.client
            .query("account", hex::encode(staked_state_address).as_str())
            .map(|x| x.response.value)
            .and_then(|value| match base64::decode(value.as_bytes()) {
                Ok(a) => Ok(a),
                Err(_b) => Err(Error::from(ErrorKind::RpcError)),
            })
            .and_then(|data| match StakedState::decode(&mut data.as_slice()) {
                Some(a) => Ok(a),
                None => Err(Error::from(ErrorKind::RpcError)),
            })
    }

    /// Get staked state info
    pub fn get_staked_state_account(
        &self,
        to_staked_account: StakedStateAddress,
    ) -> Result<StakedState> {
        match to_staked_account {
            StakedStateAddress::BasicRedeem(a) => self.get_account(&a.0),
        }
    }

    /// Get nonce
    pub fn get_staked_state_nonce(&self, to_staked_account: StakedStateAddress) -> Result<Nonce> {
        let state = self.get_staked_state_account(to_staked_account);
        state.map(|x| x.nonce)
    }
}

impl<'a, W, S, C> NetworkOpsClient for DefaultNetworkOpsClient<'a, W, S, C>
where
    W: WalletClient,
    S: Signer,
    C: Client,
{
    fn create_deposit_bonded_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        inputs: Vec<TxoPointer>,
        to_staked_account: StakedStateAddress,
        attributes: StakedStateOpAttributes,
    ) -> Result<TxAux> {
        let transaction: DepositBondTx =
            DepositBondTx::new(inputs.clone(), to_staked_account, attributes);

        let transactions = inputs
            .into_iter()
            .map(|txo_pointer: TxoPointer| {
                let id = txo_pointer.id;
                let index = txo_pointer.index;
                Ok((txo_pointer, self.wallet_client.output(&id, index as usize)?))
            })
            .collect::<Result<Vec<(TxoPointer, TxOut)>>>()?;
        let unspent_transactions = UnspentTransactions::new(transactions);
        let witness = self.signer.sign(
            name,
            passphrase,
            transaction.id(),
            unspent_transactions.select_all(),
        )?;
        Ok(TxAux::DepositStakeTx(transaction, witness))
    }
    fn create_unbond_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        from_address: &ExtendedAddr,
        value: Coin,
        attributes: StakedStateOpAttributes,
    ) -> Result<TxAux> {
        match from_address {
            ExtendedAddr::BasicRedeem(ref redeem_address) => self
                .get_staked_state_nonce(StakedStateAddress::BasicRedeem(*redeem_address))
                .and_then(|nonce| {
                    let transaction = UnbondTx::new(value, nonce, attributes);
                    let public_key = self
                        .wallet_client
                        .find_public_key(name, passphrase, redeem_address)?
                        .ok_or_else(|| Error::from(ErrorKind::AddressNotFound))?;

                    let private_key = self
                        .wallet_client
                        .private_key(passphrase, &public_key)?
                        .ok_or_else(|| Error::from(ErrorKind::PrivateKeyNotFound))?;
                    let signature = private_key
                        .sign(transaction.id())
                        .map(StakedStateOpWitness::new)?;
                    Ok(TxAux::UnbondStakeTx(transaction, signature))
                }),
            ExtendedAddr::OrTree(_) => Err(ErrorKind::InvalidInput.into()),
        }
    }

    fn create_withdraw_unbonded_stake_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        from_address: &ExtendedAddr,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
    ) -> Result<TxAux> {
        match from_address {
            ExtendedAddr::BasicRedeem(ref redeem_address) => self
                .get_staked_state_nonce(StakedStateAddress::BasicRedeem(*redeem_address))
                .and_then(|nonce| {
                    let transaction = WithdrawUnbondedTx::new(nonce, outputs, attributes);
                    let public_key = self
                        .wallet_client
                        .find_public_key(name, passphrase, redeem_address)?
                        .ok_or_else(|| Error::from(ErrorKind::AddressNotFound))?;
                    let private_key = self
                        .wallet_client
                        .private_key(passphrase, &public_key)?
                        .ok_or_else(|| Error::from(ErrorKind::PrivateKeyNotFound))?;
                    let signature = private_key
                        .sign(transaction.id())
                        .map(StakedStateOpWitness::new)?;
                    Ok(TxAux::WithdrawUnbondedStakeTx(transaction, signature))
                }),
            ExtendedAddr::OrTree(_) => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::DateTime;

    use chain_core::init::coin::Coin;
    use chain_core::state::account::WithdrawUnbondedTx;
    use chain_core::tx::data::address::ExtendedAddr;
    use chain_core::tx::data::input::TxoPointer;
    use chain_core::tx::data::output::TxOut;
    use chain_core::tx::data::Tx;
    use chain_core::tx::TransactionId;
    use chain_core::tx::TxAux;
    use client_common::tendermint::Client;
    use client_common::{ErrorKind, Result};

    use std::str::FromStr;

    use secp256k1::recovery::{RecoverableSignature, RecoveryId};

    use chain_core::init::address::RedeemAddress;

    use chain_core::state::account::StakedStateOpWitness;

    use chain_core::tx::data::attribute::TxAttributes;
    use client_common::storage::MemoryStorage;
    use client_common::tendermint::types::*;

    use chain_tx_validation::witness::verify_tx_recover_address;

    //use client_common::tendermint::RpcClient;
    use client_core::signer::DefaultSigner;
    use client_core::wallet::DefaultWalletClient;
    use client_core::{PrivateKey, PublicKey};
    use parity_codec::Encode;

    #[derive(Clone)]
    pub struct MockClient {
        pub addresses: [ExtendedAddr; 2],
    }

    impl MockClient {
        fn transaction(&self, height: u64) -> Option<TxAux> {
            if height == 1 {
                Some(TxAux::WithdrawUnbondedStakeTx(
                    WithdrawUnbondedTx {
                        nonce: 0,
                        outputs: vec![TxOut {
                            address: self.addresses[0].clone(),
                            value: Coin::new(100).unwrap(),
                            valid_from: None,
                        }],
                        attributes: TxAttributes::new(171),
                    },
                    StakedStateOpWitness::new(
                        RecoverableSignature::from_compact(
                            &[
                                0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f, 0x04, 0x77, 0x2b,
                                0x6f, 0x92, 0x1f, 0x0b, 0xa6, 0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43,
                                0x9e, 0x65, 0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98, 0x4c,
                                0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8, 0x80, 0x12, 0x0e, 0xf8,
                                0x02, 0x5e, 0x70, 0x9f, 0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae,
                                0x06, 0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89,
                            ],
                            RecoveryId::from_i32(1).unwrap(),
                        )
                        .unwrap(),
                    ),
                ))
            } else if height == 2 {
                Some(TxAux::TransferTx(
                    Tx {
                        inputs: vec![TxoPointer {
                            id: self.transaction(1).unwrap().tx_id(),
                            index: 0,
                        }],
                        outputs: vec![TxOut {
                            address: self.addresses[1].clone(),
                            value: Coin::new(100).unwrap(),
                            valid_from: None,
                        }],
                        attributes: TxAttributes::new(171),
                    },
                    vec![].into(),
                ))
            } else {
                None
            }
        }
    }

    impl Default for MockClient {
        fn default() -> Self {
            Self {
                addresses: [
                    ExtendedAddr::BasicRedeem(
                        RedeemAddress::from_str("1fdf22497167a793ca794963ad6c95e6ffa0b971")
                            .unwrap(),
                    ),
                    ExtendedAddr::BasicRedeem(
                        RedeemAddress::from_str("790661a2fd9da3fee53caab80859ecae125a20a5")
                            .unwrap(),
                    ),
                ],
            }
        }
    }

    impl Client for MockClient {
        fn genesis(&self) -> Result<Genesis> {
            unreachable!()
        }

        fn status(&self) -> Result<Status> {
            Ok(Status {
                sync_info: SyncInfo {
                    latest_block_height: "2".to_owned(),
                },
            })
        }

        fn block(&self, height: u64) -> Result<Block> {
            if height == 1 {
                Ok(Block {
                    block: BlockInner {
                        header: Header {
                            height: "1".to_owned(),
                            time: DateTime::from_str("2019-04-09T09:38:41.735577Z").unwrap(),
                        },
                        data: Data {
                            txs: Some(vec![base64::encode(&self.transaction(1).unwrap().encode())]),
                        },
                    },
                })
            } else if height == 2 {
                Ok(Block {
                    block: BlockInner {
                        header: Header {
                            height: "2".to_owned(),
                            time: DateTime::from_str("2019-04-10T09:38:41.735577Z").unwrap(),
                        },
                        data: Data {
                            txs: Some(vec![base64::encode(&self.transaction(2).unwrap().encode())]),
                        },
                    },
                })
            } else {
                Err(ErrorKind::InvalidInput.into())
            }
        }

        fn block_results(&self, height: u64) -> Result<BlockResults> {
            if height == 1 {
                Ok(BlockResults {
                    height: "1".to_owned(),
                    results: Results {
                        deliver_tx: Some(vec![DeliverTx {
                            tags: vec![Tag {
                                key: "dHhpZA==".to_owned(),
                                value: base64::encode(&self.transaction(1).unwrap().tx_id()[..]),
                            }],
                        }]),
                    },
                })
            } else if height == 2 {
                Ok(BlockResults {
                    height: "2".to_owned(),
                    results: Results {
                        deliver_tx: Some(vec![DeliverTx {
                            tags: vec![Tag {
                                key: "dHhpZA==".to_owned(),
                                value: base64::encode(&self.transaction(2).unwrap().tx_id()[..]),
                            }],
                        }]),
                    },
                })
            } else {
                Err(ErrorKind::InvalidInput.into())
            }
        }

        fn broadcast_transaction(&self, _: &[u8]) -> Result<()> {
            Ok(())
        }

        /// Get abci query
        fn query(&self, _path: &str, _data: &str) -> Result<QueryResult> {
            Ok(QueryResult {
                response: Response {
                    value: "AAAAAAAAAAAAAAAAAAAAAAAAeiLByLEia/aSXAAAAAAADbIhxPV9XTi5aBOcBukTKq+E6N8=".to_string(),
                },
            })
        }
    }

    #[test]
    fn check_create_deposit_bonded_stake_transaction() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();

        let tendermint_client = MockClient::default();
        let network_ops_client =
            DefaultNetworkOpsClient::new(&wallet_client, &signer, &tendermint_client);

        let inputs: Vec<TxoPointer> = vec![];
        let to_staked_account =
            RedeemAddress::from_str("1fdf22497167a793ca794963ad6c95e6ffa0b971").unwrap();

        let attributes = StakedStateOpAttributes::new(0);
        assert!(network_ops_client
            .create_deposit_bonded_stake_transaction(
                name,
                passphrase,
                inputs,
                to_staked_account.into(),
                attributes,
            )
            .is_ok());
    }

    #[test]
    fn check_create_unbond_stake_transaction() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();

        let tendermint_client = MockClient::default();
        let network_ops_client =
            DefaultNetworkOpsClient::new(&wallet_client, &signer, &tendermint_client);

        let value = Coin::new(0).unwrap();
        let attributes = StakedStateOpAttributes::new(0);

        assert_eq!(
            ErrorKind::InvalidInput,
            network_ops_client
                .create_unbond_stake_transaction(
                    name,
                    passphrase,
                    &ExtendedAddr::OrTree([0; 32]),
                    value,
                    attributes,
                )
                .unwrap_err()
                .kind()
        );
    }

    #[test]
    fn check_withdraw_unbonded_stake_transaction() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();

        let tendermint_client = MockClient::default();
        let network_ops_client =
            DefaultNetworkOpsClient::new(&wallet_client, &signer, &tendermint_client);

        wallet_client.new_wallet(name, passphrase).unwrap();

        let from_address = wallet_client.new_redeem_address(name, passphrase).unwrap();

        let transaction = network_ops_client
            .create_withdraw_unbonded_stake_transaction(
                name,
                passphrase,
                &from_address,
                Vec::new(),
                TxAttributes::new(171),
            )
            .unwrap();

        match transaction {
            TxAux::WithdrawUnbondedStakeTx(transaction, witness) => {
                let id = transaction.id();
                let account_address =
                    verify_tx_recover_address(&witness, &id).expect("Unable to verify transaction");

                assert_eq!(ExtendedAddr::from(account_address), from_address)
            }
            _ => unreachable!(
                "`create_withdraw_unbonded_stake_transaction()` created invalid transaction type"
            ),
        }
    }

    #[test]
    fn check_withdraw_unbonded_stake_transaction_address_not_found() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();

        let tendermint_client = MockClient::default();
        let network_ops_client =
            DefaultNetworkOpsClient::new(&wallet_client, &signer, &tendermint_client);

        wallet_client.new_wallet(name, passphrase).unwrap();

        assert_eq!(
            ErrorKind::AddressNotFound,
            network_ops_client
                .create_withdraw_unbonded_stake_transaction(
                    name,
                    passphrase,
                    &ExtendedAddr::BasicRedeem(RedeemAddress::from(&PublicKey::from(
                        &PrivateKey::new().unwrap(),
                    ))),
                    Vec::new(),
                    TxAttributes::new(171),
                )
                .unwrap_err()
                .kind()
        );
    }

    #[test]
    fn check_withdraw_unbonded_stake_transaction_wallet_not_found() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();
        let tendermint_client = MockClient::default();

        let network_ops_client =
            DefaultNetworkOpsClient::new(&wallet_client, &signer, &tendermint_client);

        assert_eq!(
            ErrorKind::WalletNotFound,
            network_ops_client
                .create_withdraw_unbonded_stake_transaction(
                    name,
                    passphrase,
                    &ExtendedAddr::BasicRedeem(RedeemAddress::from(&PublicKey::from(
                        &PrivateKey::new().unwrap(),
                    ))),
                    Vec::new(),
                    TxAttributes::new(171),
                )
                .unwrap_err()
                .kind()
        );
    }

    #[test]
    fn check_withdraw_unbonded_stake_transaction_invalid_address_type() {
        let name = "name";
        let passphrase = &SecUtf8::from("passphrase");

        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage.clone());

        let wallet_client = DefaultWalletClient::builder()
            .with_wallet(storage)
            .build()
            .unwrap();
        let tendermint_client = MockClient::default();

        let network_ops_client =
            DefaultNetworkOpsClient::new(&wallet_client, &signer, &tendermint_client);

        assert_eq!(
            ErrorKind::InvalidInput,
            network_ops_client
                .create_withdraw_unbonded_stake_transaction(
                    name,
                    passphrase,
                    &ExtendedAddr::OrTree([0; 32]),
                    Vec::new(),
                    TxAttributes::new(171),
                )
                .unwrap_err()
                .kind()
        );
    }
}
