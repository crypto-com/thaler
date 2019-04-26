use failure::ResultExt;
use rlp::encode;
use zeroize::Zeroize;

use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::{sum_coins, Coin};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::Tx;
use chain_core::tx::TxAux;
use client_common::balance::TransactionChange;
use client_common::{Error, ErrorKind, Result, Storage};
use client_index::Index;

use crate::service::*;
use crate::{PrivateKey, PublicKey, WalletClient};

/// Default implementation of `WalletClient` based on `Storage` and `Index`
#[derive(Default, Clone)]
pub struct DefaultWalletClient<S, I>
where
    S: Storage,
    I: Index,
{
    key_service: KeyService<S>,
    wallet_service: WalletService<S>,
    index: I,
}

impl<S, I> DefaultWalletClient<S, I>
where
    S: Storage + Clone,
    I: Index,
{
    /// Creates a new instance of `DefaultWalletClient`
    pub fn new(storage: S, index: I) -> Self {
        Self {
            key_service: KeyService::new(storage.clone()),
            wallet_service: WalletService::new(storage),
            index,
        }
    }
}

impl<S, I> WalletClient for DefaultWalletClient<S, I>
where
    S: Storage,
    I: Index,
{
    fn wallets(&self) -> Result<Vec<String>> {
        self.wallet_service.names()
    }

    fn new_wallet(&self, name: &str, passphrase: &str) -> Result<String> {
        self.wallet_service.create(name, passphrase)
    }

    fn private_keys(&self, name: &str, passphrase: &str) -> Result<Vec<PrivateKey>> {
        let wallet_id = self.wallet_service.get(name, passphrase)?;

        match wallet_id {
            None => Err(ErrorKind::WalletNotFound.into()),
            Some(wallet_id) => Ok(self
                .key_service
                .get_keys(&wallet_id, passphrase)?
                .unwrap_or_default()),
        }
    }

    fn public_keys(&self, name: &str, passphrase: &str) -> Result<Vec<PublicKey>> {
        let keys = self.private_keys(name, passphrase)?;
        let public_keys = keys.iter().map(PublicKey::from).collect::<Vec<PublicKey>>();
        Ok(public_keys)
    }

    fn addresses(&self, name: &str, passphrase: &str) -> Result<Vec<ExtendedAddr>> {
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
        passphrase: &str,
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

    fn new_public_key(&self, name: &str, passphrase: &str) -> Result<PublicKey> {
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

    fn new_address(&self, name: &str, passphrase: &str) -> Result<ExtendedAddr> {
        let public_key = self.new_public_key(name, passphrase)?;

        Ok(ExtendedAddr::BasicRedeem(RedeemAddress::from(&public_key)))
    }

    fn balance(&self, name: &str, passphrase: &str) -> Result<Coin> {
        let addresses = self.addresses(name, passphrase)?;

        let balances = addresses
            .iter()
            .map(|address| self.index.balance(address))
            .collect::<Result<Vec<Coin>>>()?;

        Ok(sum_coins(balances.into_iter()).context(ErrorKind::BalanceAdditionError)?)
    }

    fn history(&self, name: &str, passphrase: &str) -> Result<Vec<TransactionChange>> {
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

    fn create_and_broadcast_transaction(
        &self,
        name: &str,
        passphrase: &str,
        mut outputs: Vec<TxOut>,
        attributes: TxAttributes,
    ) -> Result<()> {
        let addresses = self.addresses(name, passphrase)?;

        let mut unspent_transactions = Vec::new();
        for address in addresses {
            unspent_transactions.extend(self.index.unspent_transactions(&address)?);
        }

        let mut amount_to_transfer = Coin::zero();
        for output in outputs.iter() {
            amount_to_transfer =
                (amount_to_transfer + output.value).context(ErrorKind::BalanceAdditionError)?;
        }

        let mut selected_unspent_transactions = Vec::new();
        let mut transferred_amount = Coin::zero();
        for (unspent_transaction, value) in unspent_transactions {
            selected_unspent_transactions.push(unspent_transaction);
            transferred_amount =
                (transferred_amount + value).context(ErrorKind::BalanceAdditionError)?;

            if transferred_amount >= amount_to_transfer {
                break;
            }
        }

        let transaction = if transferred_amount < amount_to_transfer {
            Err(Error::from(ErrorKind::InsufficientBalance))
        } else if transferred_amount == amount_to_transfer {
            Ok(Tx {
                inputs: selected_unspent_transactions,
                outputs,
                attributes,
            })
        } else {
            let new_address = self.new_address(name, passphrase)?;
            outputs.push(TxOut::new(
                new_address,
                (transferred_amount - amount_to_transfer)
                    .context(ErrorKind::BalanceAdditionError)?,
            ));

            Ok(Tx {
                inputs: selected_unspent_transactions,
                outputs,
                attributes,
            })
        }?;

        self.broadcast_transaction(name, passphrase, transaction)
    }

    fn broadcast_transaction(&self, name: &str, passphrase: &str, transaction: Tx) -> Result<()> {
        println!("Tx: {:?}", transaction);

        let mut witnesses = Vec::with_capacity(transaction.inputs.len());

        for input in &transaction.inputs {
            let input = self.index.output(&input.id, input.index)?;

            match self.private_key(name, passphrase, &input.address)? {
                None => return Err(ErrorKind::PrivateKeyNotFound.into()),
                Some(private_key) => witnesses.push(private_key.sign(&transaction.id())?),
            }
        }

        let tx_aux = TxAux::new(transaction, witnesses.into());

        self.index.broadcast_transaction(&encode(&tx_aux))
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

    use chain_core::init::coin::Coin;
    use chain_core::tx::data::address::ExtendedAddr;
    use chain_core::tx::data::attribute::TxAttributes;
    use chain_core::tx::data::input::TxoPointer;
    use chain_core::tx::data::output::TxOut;
    use chain_core::tx::data::{Tx, TxId};
    use client_common::balance::{BalanceChange, TransactionChange};
    use client_common::storage::MemoryStorage;
    use client_common::Result;
    use client_index::Index;

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

    #[test]
    fn check_wallet_flow() {
        let wallet = DefaultWalletClient::new(MemoryStorage::default(), MockIndex::default());

        assert!(wallet.addresses("name", "passphrase").is_err());

        wallet
            .new_wallet("name", "passphrase")
            .expect("Unable to create a new wallet");

        assert_eq!(0, wallet.addresses("name", "passphrase").unwrap().len());
        assert_eq!("name".to_string(), wallet.wallets().unwrap()[0]);
        assert_eq!(1, wallet.wallets().unwrap().len());

        let address = wallet
            .new_address("name", "passphrase")
            .expect("Unable to generate new address");

        let addresses = wallet.addresses("name", "passphrase").unwrap();

        assert_eq!(1, addresses.len());
        assert_eq!(address, addresses[0], "Addresses don't match");

        assert!(wallet
            .private_key("name", "passphrase", &address)
            .unwrap()
            .is_some());

        assert_eq!(
            ErrorKind::WalletNotFound,
            wallet
                .public_keys("name_new", "passphrase")
                .expect_err("Found public keys for non existent wallet")
                .kind(),
            "Invalid public key present in database"
        );

        assert_eq!(
            ErrorKind::WalletNotFound,
            wallet
                .new_public_key("name_new", "passphrase")
                .expect_err("Generated public key for non existent wallet")
                .kind(),
            "Error of invalid kind received"
        );
    }

    #[test]
    fn check_transaction_flow() {
        let storage = MemoryStorage::default();
        let temp_wallet = DefaultWalletClient::new(storage.clone(), MockIndex::default());
        temp_wallet.new_wallet("wallet_1", "passphrase").unwrap();
        let addr_1 = temp_wallet.new_address("wallet_1", "passphrase").unwrap();
        temp_wallet.new_wallet("wallet_2", "passphrase").unwrap();
        let addr_2 = temp_wallet.new_address("wallet_2", "passphrase").unwrap();
        temp_wallet.new_wallet("wallet_3", "passphrase").unwrap();
        let addr_3 = temp_wallet.new_address("wallet_3", "passphrase").unwrap();

        let wallet = DefaultWalletClient::new(
            storage,
            MockIndex::new(addr_1.clone(), addr_2.clone(), addr_3.clone()),
        );

        assert_eq!(
            Coin::new(0).unwrap(),
            wallet.balance("wallet_1", "passphrase").unwrap()
        );
        assert_eq!(
            Coin::new(30).unwrap(),
            wallet.balance("wallet_2", "passphrase").unwrap()
        );
        assert_eq!(
            Coin::new(0).unwrap(),
            wallet.balance("wallet_3", "passphrase").unwrap()
        );

        assert_eq!(2, wallet.history("wallet_1", "passphrase").unwrap().len());
        assert_eq!(1, wallet.history("wallet_2", "passphrase").unwrap().len());
        assert_eq!(0, wallet.history("wallet_3", "passphrase").unwrap().len());

        assert!(wallet.sync().is_ok());
        assert!(wallet.sync_all().is_ok());

        assert!(wallet
            .create_and_broadcast_transaction(
                "wallet_2",
                "passphrase",
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
            wallet.balance("wallet_1", "passphrase").unwrap()
        );
        assert_eq!(
            Coin::new(0).unwrap(),
            wallet.balance("wallet_2", "passphrase").unwrap()
        );
        assert_eq!(
            Coin::new(30).unwrap(),
            wallet.balance("wallet_3", "passphrase").unwrap()
        );

        assert_eq!(2, wallet.history("wallet_1", "passphrase").unwrap().len());
        assert_eq!(2, wallet.history("wallet_2", "passphrase").unwrap().len());
        assert_eq!(1, wallet.history("wallet_3", "passphrase").unwrap().len());

        assert!(wallet
            .create_and_broadcast_transaction(
                "wallet_3",
                "passphrase",
                vec![TxOut {
                    address: addr_2.clone(),
                    value: Coin::new(20).unwrap(),
                    valid_from: None,
                }],
                TxAttributes::new(171),
            )
            .is_ok());

        assert!(wallet
            .create_and_broadcast_transaction(
                "wallet_2",
                "passphrase",
                vec![TxOut {
                    address: addr_3.clone(),
                    value: Coin::new(30).unwrap(),
                    valid_from: None,
                }],
                TxAttributes::new(171),
            )
            .is_err());
    }
}
