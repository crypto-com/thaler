use failure::ResultExt;
use rlp::encode;
use secstr::SecStr;
use zeroize::Zeroize;

use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::{sum_coins, Coin};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::TxId;
use client_common::balance::TransactionChange;
use client_common::storage::UnauthorizedStorage;
use client_common::{ErrorKind, Result, Storage};
use client_index::index::{Index, UnauthorizedIndex};

use crate::service::*;
use crate::transaction_builder::UnauthorizedTransactionBuilder;
use crate::{PrivateKey, PublicKey, TransactionBuilder, WalletClient};

/// Default implementation of `WalletClient` based on `Storage` and `Index`
#[derive(Debug, Default, Clone)]
pub struct DefaultWalletClient<S, I, T>
where
    S: Storage,
    I: Index,
    T: TransactionBuilder,
{
    key_service: KeyService<S>,
    wallet_service: WalletService<S>,
    index: I,
    transaction_builder: T,
}

impl<S, I, T> DefaultWalletClient<S, I, T>
where
    S: Storage + Clone,
    I: Index,
    T: TransactionBuilder,
{
    /// Creates a new instance of `DefaultWalletClient`
    fn new(storage: S, index: I, transaction_builder: T) -> Self {
        Self {
            key_service: KeyService::new(storage.clone()),
            wallet_service: WalletService::new(storage),
            index,
            transaction_builder,
        }
    }
}

impl DefaultWalletClient<UnauthorizedStorage, UnauthorizedIndex, UnauthorizedTransactionBuilder> {
    /// Returns builder for `DefaultWalletClient`
    pub fn builder() -> DefaultWalletClientBuilder<
        UnauthorizedStorage,
        UnauthorizedIndex,
        UnauthorizedTransactionBuilder,
    > {
        DefaultWalletClientBuilder::default()
    }
}

impl<S, I, T> WalletClient for DefaultWalletClient<S, I, T>
where
    S: Storage,
    I: Index,
    T: TransactionBuilder,
{
    fn wallets(&self) -> Result<Vec<String>> {
        self.wallet_service.names()
    }

    fn new_wallet(&self, name: &str, passphrase: &SecStr) -> Result<String> {
        self.wallet_service.create(name, passphrase)
    }

    fn private_keys(&self, name: &str, passphrase: &SecStr) -> Result<Vec<PrivateKey>> {
        let wallet_id = self.wallet_service.get(name, passphrase)?;

        match wallet_id {
            None => Err(ErrorKind::WalletNotFound.into()),
            Some(wallet_id) => Ok(self
                .key_service
                .get_keys(&wallet_id, passphrase)?
                .unwrap_or_default()),
        }
    }

    fn public_keys(&self, name: &str, passphrase: &SecStr) -> Result<Vec<PublicKey>> {
        let keys = self.private_keys(name, passphrase)?;
        let public_keys = keys.iter().map(PublicKey::from).collect::<Vec<PublicKey>>();
        Ok(public_keys)
    }

    fn addresses(&self, name: &str, passphrase: &SecStr) -> Result<Vec<ExtendedAddr>> {
        let public_keys = self.public_keys(name, passphrase)?;

        let addresses = public_keys
            .iter()
            .map(|public_key| ExtendedAddr::BasicRedeem(RedeemAddress::from(public_key)))
            .collect::<Vec<ExtendedAddr>>();

        Ok(addresses)
    }

    fn private_key(
        &self,
        name: &str,
        passphrase: &SecStr,
        address: &ExtendedAddr,
    ) -> Result<Option<PrivateKey>> {
        let private_keys = self.private_keys(name, passphrase)?;
        let addresses = self.addresses(name, passphrase)?;

        for (i, known_address) in addresses.iter().enumerate() {
            if known_address == address {
                return Ok(Some(private_keys[i].clone()));
            }
        }

        Ok(None)
    }

    fn new_public_key(&self, name: &str, passphrase: &SecStr) -> Result<PublicKey> {
        let wallet_id = self.wallet_service.get(name, passphrase)?;

        match wallet_id {
            None => Err(ErrorKind::WalletNotFound.into()),
            Some(wallet_id) => {
                let mut private_key = self.key_service.generate(&wallet_id, passphrase)?;
                let public_key = PublicKey::from(&private_key);

                private_key.zeroize();

                Ok(public_key)
            }
        }
    }

    fn new_address(&self, name: &str, passphrase: &SecStr) -> Result<ExtendedAddr> {
        let public_key = self.new_public_key(name, passphrase)?;

        Ok(ExtendedAddr::BasicRedeem(RedeemAddress::from(&public_key)))
    }

    fn balance(&self, name: &str, passphrase: &SecStr) -> Result<Coin> {
        let addresses = self.addresses(name, passphrase)?;

        let balances = addresses
            .iter()
            .map(|address| self.index.balance(address))
            .collect::<Result<Vec<Coin>>>()?;

        Ok(sum_coins(balances.into_iter()).context(ErrorKind::BalanceAdditionError)?)
    }

    fn history(&self, name: &str, passphrase: &SecStr) -> Result<Vec<TransactionChange>> {
        let addresses = self.addresses(name, passphrase)?;

        let history = addresses
            .iter()
            .map(|address| self.index.transaction_changes(address))
            .collect::<Result<Vec<Vec<TransactionChange>>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<TransactionChange>>();

        Ok(history)
    }

    fn unspent_transactions(
        &self,
        name: &str,
        passphrase: &SecStr,
    ) -> Result<Vec<(TxoPointer, Coin)>> {
        let addresses = self.addresses(name, passphrase)?;

        let mut unspent_transactions = Vec::new();
        for address in addresses {
            unspent_transactions.extend(self.index.unspent_transactions(&address)?);
        }

        Ok(unspent_transactions)
    }

    fn output(&self, id: &TxId, index: usize) -> Result<TxOut> {
        self.index.output(id, index)
    }

    fn create_and_broadcast_transaction(
        &self,
        name: &str,
        passphrase: &SecStr,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
    ) -> Result<()> {
        let tx_aux = self
            .transaction_builder
            .build(name, passphrase, outputs, attributes, self)?;

        self.index.broadcast_transaction(&encode(&tx_aux))
    }

    fn sync(&self) -> Result<()> {
        self.index.sync()
    }

    fn sync_all(&self) -> Result<()> {
        self.index.sync_all()
    }
}

#[derive(Debug)]
pub struct DefaultWalletClientBuilder<S, I, T>
where
    S: Storage + Clone,
    I: Index,
    T: TransactionBuilder,
{
    storage: S,
    index: I,
    transaction_builder: T,
    storage_set: bool,
    index_set: bool,
    transaction_builder_set: bool,
}

impl Default
    for DefaultWalletClientBuilder<
        UnauthorizedStorage,
        UnauthorizedIndex,
        UnauthorizedTransactionBuilder,
    >
{
    fn default() -> Self {
        DefaultWalletClientBuilder {
            storage: UnauthorizedStorage,
            index: UnauthorizedIndex,
            transaction_builder: UnauthorizedTransactionBuilder,
            storage_set: false,
            index_set: false,
            transaction_builder_set: false,
        }
    }
}

impl<S, I, T> DefaultWalletClientBuilder<S, I, T>
where
    S: Storage + Clone,
    I: Index,
    T: TransactionBuilder,
{
    /// Adds functionality for address generation and storage
    pub fn with_wallet<NS: Storage + Clone>(
        self,
        storage: NS,
    ) -> DefaultWalletClientBuilder<NS, I, T> {
        DefaultWalletClientBuilder {
            storage,
            index: self.index,
            transaction_builder: self.transaction_builder,
            storage_set: true,
            index_set: self.index_set,
            transaction_builder_set: self.transaction_builder_set,
        }
    }

    /// Adds functionality for balance tracking and transaction history
    pub fn with_transaction_read<NI: Index>(
        self,
        index: NI,
    ) -> DefaultWalletClientBuilder<S, NI, T> {
        DefaultWalletClientBuilder {
            storage: self.storage,
            index,
            transaction_builder: self.transaction_builder,
            storage_set: self.storage_set,
            index_set: true,
            transaction_builder_set: self.transaction_builder_set,
        }
    }

    /// Adds functionality for transaction creation and broadcasting
    pub fn with_transaction_write<NT: TransactionBuilder>(
        self,
        transaction_builder: NT,
    ) -> DefaultWalletClientBuilder<S, I, NT> {
        DefaultWalletClientBuilder {
            storage: self.storage,
            index: self.index,
            transaction_builder,
            storage_set: self.storage_set,
            index_set: self.index_set,
            transaction_builder_set: true,
        }
    }

    /// Builds `DefaultWalletClient`
    pub fn build(self) -> Result<DefaultWalletClient<S, I, T>> {
        if !self.index_set && !self.transaction_builder_set || self.storage_set && self.index_set {
            Ok(DefaultWalletClient::new(
                self.storage,
                self.index,
                self.transaction_builder,
            ))
        } else {
            Err(ErrorKind::InvalidInput.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;
    use std::sync::RwLock;
    use std::time::SystemTime;

    use chrono::DateTime;

    use chain_core::init::coin::{Coin, CoinError};
    use chain_core::tx::data::address::ExtendedAddr;
    use chain_core::tx::data::attribute::TxAttributes;
    use chain_core::tx::data::input::TxoPointer;
    use chain_core::tx::data::output::TxOut;
    use chain_core::tx::data::{Tx, TxId};
    use chain_core::tx::fee::{Fee, FeeAlgorithm};
    use chain_core::tx::TxAux;
    use client_common::balance::{BalanceChange, TransactionChange};
    use client_common::storage::MemoryStorage;
    use client_common::Result;
    use client_index::Index;

    use crate::transaction_builder::DefaultTransactionBuilder;

    #[derive(Debug)]
    pub struct MockIndex {
        addr_1: ExtendedAddr,
        addr_2: ExtendedAddr,
        addr_3: ExtendedAddr,
        changed: RwLock<bool>,
    }

    impl MockIndex {
        fn new(addr_1: ExtendedAddr, addr_2: ExtendedAddr, addr_3: ExtendedAddr) -> Self {
            Self {
                addr_1,
                addr_2,
                addr_3,
                changed: RwLock::new(false),
            }
        }
    }

    impl Default for MockIndex {
        fn default() -> Self {
            Self {
                addr_1: ExtendedAddr::BasicRedeem(
                    RedeemAddress::from_str("1fdf22497167a793ca794963ad6c95e6ffa0b971").unwrap(),
                ),
                addr_2: ExtendedAddr::BasicRedeem(
                    RedeemAddress::from_str("790661a2fd9da3fee53caab80859ecae125a20a5").unwrap(),
                ),
                addr_3: ExtendedAddr::BasicRedeem(
                    RedeemAddress::from_str("780661a2fd9da3fee53caab80859ecae105a20b6").unwrap(),
                ),
                changed: RwLock::new(false),
            }
        }
    }

    impl Index for MockIndex {
        fn sync(&self) -> Result<()> {
            Ok(())
        }

        fn sync_all(&self) -> Result<()> {
            Ok(())
        }

        fn transaction_changes(&self, address: &ExtendedAddr) -> Result<Vec<TransactionChange>> {
            if address == &self.addr_1 {
                Ok(vec![
                    TransactionChange {
                        transaction_id: TxId::repeat_byte(0),
                        address: address.clone(),
                        balance_change: BalanceChange::Incoming(Coin::new(30).unwrap()),
                        height: 1,
                        time: DateTime::from(SystemTime::now()),
                    },
                    TransactionChange {
                        transaction_id: TxId::repeat_byte(1),
                        address: address.clone(),
                        balance_change: BalanceChange::Outgoing(Coin::new(30).unwrap()),
                        height: 2,
                        time: DateTime::from(SystemTime::now()),
                    },
                ])
            } else if address == &self.addr_2 {
                if *self.changed.read().unwrap() {
                    Ok(vec![
                        TransactionChange {
                            transaction_id: TxId::repeat_byte(1),
                            address: address.clone(),
                            balance_change: BalanceChange::Incoming(Coin::new(30).unwrap()),
                            height: 1,
                            time: DateTime::from(SystemTime::now()),
                        },
                        TransactionChange {
                            transaction_id: TxId::repeat_byte(2),
                            address: address.clone(),
                            balance_change: BalanceChange::Outgoing(Coin::new(30).unwrap()),
                            height: 2,
                            time: DateTime::from(SystemTime::now()),
                        },
                    ])
                } else {
                    Ok(vec![TransactionChange {
                        transaction_id: TxId::repeat_byte(1),
                        address: address.clone(),
                        balance_change: BalanceChange::Incoming(Coin::new(30).unwrap()),
                        height: 2,
                        time: DateTime::from(SystemTime::now()),
                    }])
                }
            } else if *self.changed.read().unwrap() && address == &self.addr_3 {
                Ok(vec![TransactionChange {
                    transaction_id: TxId::repeat_byte(1),
                    address: address.clone(),
                    balance_change: BalanceChange::Incoming(Coin::new(30).unwrap()),
                    height: 2,
                    time: DateTime::from(SystemTime::now()),
                }])
            } else {
                Ok(Default::default())
            }
        }

        fn balance(&self, address: &ExtendedAddr) -> Result<Coin> {
            if address == &self.addr_1 {
                Ok(Coin::zero())
            } else if address == &self.addr_2 {
                if *self.changed.read().unwrap() {
                    Ok(Coin::zero())
                } else {
                    Ok(Coin::new(30).unwrap())
                }
            } else if *self.changed.read().unwrap() && address == &self.addr_3 {
                Ok(Coin::new(30).unwrap())
            } else {
                Ok(Coin::zero())
            }
        }

        fn unspent_transactions(&self, address: &ExtendedAddr) -> Result<Vec<(TxoPointer, Coin)>> {
            if address == &self.addr_1 {
                Ok(Default::default())
            } else if address == &self.addr_2 {
                if *self.changed.read().unwrap() {
                    Ok(Default::default())
                } else {
                    Ok(vec![(
                        TxoPointer::new(TxId::repeat_byte(1), 0),
                        Coin::new(30).unwrap(),
                    )])
                }
            } else if *self.changed.read().unwrap() && address == &self.addr_3 {
                Ok(vec![(
                    TxoPointer::new(TxId::repeat_byte(2), 0),
                    Coin::new(30).unwrap(),
                )])
            } else {
                Ok(Default::default())
            }
        }

        fn transaction(&self, _: &TxId) -> Result<Option<Tx>> {
            unreachable!();
        }

        fn output(&self, id: &TxId, index: usize) -> Result<TxOut> {
            if id == &TxId::repeat_byte(0) && index == 0 {
                Ok(TxOut {
                    address: self.addr_1.clone(),
                    value: Coin::new(30).unwrap(),
                    valid_from: None,
                })
            } else if id == &TxId::repeat_byte(1) && index == 0 {
                Ok(TxOut {
                    address: self.addr_2.clone(),
                    value: Coin::new(30).unwrap(),
                    valid_from: None,
                })
            } else if *self.changed.read().unwrap() && id == &TxId::repeat_byte(2) && index == 0 {
                Ok(TxOut {
                    address: self.addr_3.clone(),
                    value: Coin::new(30).unwrap(),
                    valid_from: None,
                })
            } else {
                Err(ErrorKind::TransactionNotFound.into())
            }
        }

        fn broadcast_transaction(&self, _transaction: &[u8]) -> Result<()> {
            let mut changed = self.changed.write().unwrap();
            *changed = true;
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct ZeroFeeAlgorithm;

    impl FeeAlgorithm for ZeroFeeAlgorithm {
        fn calculate_fee(&self, _num_bytes: usize) -> std::result::Result<Fee, CoinError> {
            Ok(Fee::new(Coin::zero()))
        }

        fn calculate_for_txaux(&self, _txaux: &TxAux) -> std::result::Result<Fee, CoinError> {
            Ok(Fee::new(Coin::zero()))
        }
    }

    #[test]
    fn check_wallet_flow() {
        let wallet = DefaultWalletClient::builder()
            .with_wallet(MemoryStorage::default())
            .build()
            .unwrap();

        assert!(wallet
            .addresses("name", &SecStr::from("passphrase"))
            .is_err());

        wallet
            .new_wallet("name", &SecStr::from("passphrase"))
            .expect("Unable to create a new wallet");

        assert_eq!(
            0,
            wallet
                .addresses("name", &SecStr::from("passphrase"))
                .unwrap()
                .len()
        );
        assert_eq!("name".to_string(), wallet.wallets().unwrap()[0]);
        assert_eq!(1, wallet.wallets().unwrap().len());

        let address = wallet
            .new_address("name", &SecStr::from("passphrase"))
            .expect("Unable to generate new address");

        let addresses = wallet
            .addresses("name", &SecStr::from("passphrase"))
            .unwrap();

        assert_eq!(1, addresses.len());
        assert_eq!(address, addresses[0], "Addresses don't match");

        assert!(wallet
            .private_key("name", &SecStr::from("passphrase"), &address)
            .unwrap()
            .is_some());

        assert_eq!(
            ErrorKind::WalletNotFound,
            wallet
                .public_keys("name_new", &SecStr::from("passphrase"))
                .expect_err("Found public keys for non existent wallet")
                .kind(),
            "Invalid public key present in database"
        );

        assert_eq!(
            ErrorKind::WalletNotFound,
            wallet
                .new_public_key("name_new", &SecStr::from("passphrase"))
                .expect_err("Generated public key for non existent wallet")
                .kind(),
            "Error of invalid kind received"
        );
    }

    #[test]
    fn check_transaction_flow() {
        let storage = MemoryStorage::default();
        let wallet = DefaultWalletClient::builder()
            .with_wallet(storage.clone())
            .build()
            .unwrap();

        wallet
            .new_wallet("wallet_1", &SecStr::from("passphrase"))
            .unwrap();
        let addr_1 = wallet
            .new_address("wallet_1", &SecStr::from("passphrase"))
            .unwrap();
        wallet
            .new_wallet("wallet_2", &SecStr::from("passphrase"))
            .unwrap();
        let addr_2 = wallet
            .new_address("wallet_2", &SecStr::from("passphrase"))
            .unwrap();
        wallet
            .new_wallet("wallet_3", &SecStr::from("passphrase"))
            .unwrap();
        let addr_3 = wallet
            .new_address("wallet_3", &SecStr::from("passphrase"))
            .unwrap();

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .balance("wallet_1", &SecStr::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        let wallet = DefaultWalletClient::builder()
            .with_wallet(storage.clone())
            .with_transaction_read(MockIndex::new(
                addr_1.clone(),
                addr_2.clone(),
                addr_3.clone(),
            ))
            .build()
            .unwrap();

        assert_eq!(
            Coin::new(0).unwrap(),
            wallet
                .balance("wallet_1", &SecStr::from("passphrase"))
                .unwrap()
        );
        assert_eq!(
            Coin::new(30).unwrap(),
            wallet
                .balance("wallet_2", &SecStr::from("passphrase"))
                .unwrap()
        );
        assert_eq!(
            Coin::new(0).unwrap(),
            wallet
                .balance("wallet_3", &SecStr::from("passphrase"))
                .unwrap()
        );

        assert_eq!(
            2,
            wallet
                .history("wallet_1", &SecStr::from("passphrase"))
                .unwrap()
                .len()
        );
        assert_eq!(
            1,
            wallet
                .history("wallet_2", &SecStr::from("passphrase"))
                .unwrap()
                .len()
        );
        assert_eq!(
            0,
            wallet
                .history("wallet_3", &SecStr::from("passphrase"))
                .unwrap()
                .len()
        );

        assert!(wallet.sync().is_ok());
        assert!(wallet.sync_all().is_ok());

        let wallet = DefaultWalletClient::builder()
            .with_wallet(storage)
            .with_transaction_read(wallet.index)
            .with_transaction_write(DefaultTransactionBuilder::new(ZeroFeeAlgorithm::default()))
            .build()
            .unwrap();

        assert!(wallet
            .create_and_broadcast_transaction(
                "wallet_2",
                &SecStr::from("passphrase"),
                vec![TxOut {
                    address: addr_3.clone(),
                    value: Coin::new(30).unwrap(),
                    valid_from: None,
                }],
                TxAttributes::new(171),
            )
            .is_ok());

        assert_eq!(
            Coin::new(0).unwrap(),
            wallet
                .balance("wallet_1", &SecStr::from("passphrase"))
                .unwrap()
        );
        assert_eq!(
            Coin::new(0).unwrap(),
            wallet
                .balance("wallet_2", &SecStr::from("passphrase"))
                .unwrap()
        );
        assert_eq!(
            Coin::new(30).unwrap(),
            wallet
                .balance("wallet_3", &SecStr::from("passphrase"))
                .unwrap()
        );

        assert_eq!(
            2,
            wallet
                .history("wallet_1", &SecStr::from("passphrase"))
                .unwrap()
                .len()
        );
        assert_eq!(
            2,
            wallet
                .history("wallet_2", &SecStr::from("passphrase"))
                .unwrap()
                .len()
        );
        assert_eq!(
            1,
            wallet
                .history("wallet_3", &SecStr::from("passphrase"))
                .unwrap()
                .len()
        );

        assert!(wallet
            .create_and_broadcast_transaction(
                "wallet_3",
                &SecStr::from("passphrase"),
                vec![TxOut {
                    address: addr_2.clone(),
                    value: Coin::new(20).unwrap(),
                    valid_from: None,
                }],
                TxAttributes::new(171),
            )
            .is_ok());

        assert_eq!(
            ErrorKind::InsufficientBalance,
            wallet
                .create_and_broadcast_transaction(
                    "wallet_2",
                    &SecStr::from("passphrase"),
                    vec![TxOut {
                        address: addr_3.clone(),
                        value: Coin::new(30).unwrap(),
                        valid_from: None,
                    }],
                    TxAttributes::new(171),
                )
                .unwrap_err()
                .kind()
        );
    }

    #[test]
    fn check_unauthorized_wallet() {
        let wallet = DefaultWalletClient::builder().build().unwrap();

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet.wallets().unwrap_err().kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .new_wallet("name", &SecStr::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .private_keys("name", &SecStr::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .public_keys("name", &SecStr::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .addresses("name", &SecStr::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .private_key(
                    "name",
                    &SecStr::from("passphrase"),
                    &ExtendedAddr::BasicRedeem(
                        RedeemAddress::from_str("790661a2fd9da3fee53caab80859ecae125a20a5")
                            .unwrap(),
                    )
                )
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .new_public_key("name", &SecStr::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .new_address("name", &SecStr::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .balance("name", &SecStr::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .history("name", &SecStr::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .unspent_transactions("name", &SecStr::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet.output(&TxId::repeat_byte(1), 0).unwrap_err().kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .create_and_broadcast_transaction(
                    "name",
                    &SecStr::from("passphrase"),
                    Vec::new(),
                    TxAttributes::new(171)
                )
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet.sync().unwrap_err().kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet.sync_all().unwrap_err().kind()
        );
    }

    #[test]
    fn invalid_wallet_building() {
        let builder = DefaultWalletClient::builder()
            .with_transaction_write(DefaultTransactionBuilder::new(ZeroFeeAlgorithm::default()));

        assert_eq!(ErrorKind::InvalidInput, builder.build().unwrap_err().kind());
    }
}
