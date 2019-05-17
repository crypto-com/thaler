use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::{sum_coins, Coin};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::TxId;
use client_common::balance::TransactionChange;
use client_common::{ErrorKind, Result, Storage};
use client_index::Index;
use failure::ResultExt;
use parity_codec::Encode;
use secstr::SecStr;
use zeroize::Zeroize;

use crate::service::*;
use crate::{PrivateKey, PublicKey, TransactionBuilder, WalletClient};

/// Default implementation of `WalletClient` based on `Storage` and `Index`
#[derive(Default, Clone)]
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
    pub fn new(storage: S, index: I, transaction_builder: T) -> Self {
        Self {
            key_service: KeyService::new(storage.clone()),
            wallet_service: WalletService::new(storage),
            index,
            transaction_builder,
        }
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

        self.index.broadcast_transaction(&tx_aux.encode())
    }

    fn sync(&self) -> Result<()> {
        self.index.sync()
    }

    fn sync_all(&self) -> Result<()> {
        self.index.sync_all()
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
                        transaction_id: [0u8; 32],
                        address: address.clone(),
                        balance_change: BalanceChange::Incoming(Coin::new(30).unwrap()),
                        height: 1,
                        time: DateTime::from(SystemTime::now()),
                    },
                    TransactionChange {
                        transaction_id: [1u8; 32],
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
                            transaction_id: [1u8; 32],
                            address: address.clone(),
                            balance_change: BalanceChange::Incoming(Coin::new(30).unwrap()),
                            height: 1,
                            time: DateTime::from(SystemTime::now()),
                        },
                        TransactionChange {
                            transaction_id: [2u8; 32],
                            address: address.clone(),
                            balance_change: BalanceChange::Outgoing(Coin::new(30).unwrap()),
                            height: 2,
                            time: DateTime::from(SystemTime::now()),
                        },
                    ])
                } else {
                    Ok(vec![TransactionChange {
                        transaction_id: [1u8; 32],
                        address: address.clone(),
                        balance_change: BalanceChange::Incoming(Coin::new(30).unwrap()),
                        height: 2,
                        time: DateTime::from(SystemTime::now()),
                    }])
                }
            } else if *self.changed.read().unwrap() && address == &self.addr_3 {
                Ok(vec![TransactionChange {
                    transaction_id: [1u8; 32],
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
                        TxoPointer::new([1u8; 32], 0),
                        Coin::new(30).unwrap(),
                    )])
                }
            } else if *self.changed.read().unwrap() && address == &self.addr_3 {
                Ok(vec![(
                    TxoPointer::new([2u8; 32], 0),
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
            if id == &[0u8; 32] && index == 0 {
                Ok(TxOut {
                    address: self.addr_1.clone(),
                    value: Coin::new(30).unwrap(),
                    valid_from: None,
                })
            } else if id == &[1u8; 32] && index == 0 {
                Ok(TxOut {
                    address: self.addr_2.clone(),
                    value: Coin::new(30).unwrap(),
                    valid_from: None,
                })
            } else if *self.changed.read().unwrap() && id == &[2u8; 32] && index == 0 {
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

    #[test]
    fn check_wallet_flow() {
        let wallet = DefaultWalletClient::new(
            MemoryStorage::default(),
            MockIndex::default(),
            DefaultTransactionBuilder::new(ZeroFeeAlgorithm::default()),
        );

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
        let temp_wallet = DefaultWalletClient::new(
            storage.clone(),
            MockIndex::default(),
            DefaultTransactionBuilder::new(ZeroFeeAlgorithm::default()),
        );
        temp_wallet
            .new_wallet("wallet_1", &SecStr::from("passphrase"))
            .unwrap();
        let addr_1 = temp_wallet
            .new_address("wallet_1", &SecStr::from("passphrase"))
            .unwrap();
        temp_wallet
            .new_wallet("wallet_2", &SecStr::from("passphrase"))
            .unwrap();
        let addr_2 = temp_wallet
            .new_address("wallet_2", &SecStr::from("passphrase"))
            .unwrap();
        temp_wallet
            .new_wallet("wallet_3", &SecStr::from("passphrase"))
            .unwrap();
        let addr_3 = temp_wallet
            .new_address("wallet_3", &SecStr::from("passphrase"))
            .unwrap();

        let wallet = DefaultWalletClient::new(
            storage,
            MockIndex::new(addr_1.clone(), addr_2.clone(), addr_3.clone()),
            DefaultTransactionBuilder::new(ZeroFeeAlgorithm::default()),
        );

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
}
