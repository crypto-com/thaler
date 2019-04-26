use failure::ResultExt;
use rlp::encode;
use zeroize::Zeroize;

use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::{sum_coins, Coin};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::Tx;
use chain_core::tx::TxAux;
use client_common::balance::TransactionChange;
use client_common::{ErrorKind, Result, Storage};
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

    fn broadcast_transaction(&self, name: &str, passphrase: &str, transaction: Tx) -> Result<()> {
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

    #[derive(Default)]
    pub struct MockIndex;

    impl Index for MockIndex {
        fn sync(&self) -> Result<()> {
            Ok(())
        }

        fn sync_all(&self) -> Result<()> {
            Ok(())
        }

        fn transaction_changes(&self, address: &ExtendedAddr) -> Result<Vec<TransactionChange>> {
            Ok(vec![TransactionChange {
                transaction_id: TxId::zero(),
                address: address.clone(),
                balance_change: BalanceChange::Incoming(Coin::new(30).unwrap()),
                height: 1,
                time: DateTime::from(SystemTime::now()),
            }])
        }

        fn balance(&self, _: &ExtendedAddr) -> Result<Coin> {
            Ok(Coin::new(30).unwrap())
        }

        fn transaction(&self, _: &TxId) -> Result<Option<Tx>> {
            Ok(Some(Tx {
                inputs: vec![TxoPointer {
                    id: TxId::zero(),
                    index: 1,
                }],
                outputs: Default::default(),
                attributes: TxAttributes::new(171),
            }))
        }

        fn output(&self, _id: &TxId, _index: usize) -> Result<TxOut> {
            Ok(TxOut {
                address: ExtendedAddr::BasicRedeem(
                    RedeemAddress::from_str("0x1fdf22497167a793ca794963ad6c95e6ffa0b971").unwrap(),
                ),
                value: Coin::new(10000000000000000000).unwrap(),
                valid_from: None,
            })
        }

        fn broadcast_transaction(&self, _transaction: &[u8]) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn check_flow() {
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

        assert_eq!(
            Coin::new(30).unwrap(),
            wallet.balance("name", "passphrase").unwrap()
        );

        assert_eq!(1, wallet.history("name", "passphrase").unwrap().len());

        assert!(wallet.new_address("name", "passphrase").is_ok());

        assert_eq!(
            Coin::new(60).unwrap(),
            wallet.balance("name", "passphrase").unwrap()
        );

        assert_eq!(2, wallet.history("name", "passphrase").unwrap().len());

        assert!(wallet.history("new_name", "passphrase").is_err());
        assert!(wallet.balance("new_name", "passphrase").is_err());

        assert!(wallet.sync().is_ok());
        assert!(wallet.sync_all().is_ok());

        assert!(wallet
            .broadcast_transaction(
                "name",
                "passphrase",
                Tx {
                    inputs: vec![TxoPointer {
                        id: TxId::zero(),
                        index: 0,
                    }],
                    outputs: Default::default(),
                    attributes: TxAttributes::new(171),
                }
            )
            .is_err());
    }
}
