use either::Either;
use failure::ResultExt;
use parity_codec::Encode;
use secp256k1::schnorrsig::SchnorrSignature;
use secstr::SecUtf8;

use chain_core::common::{Proof, H256};
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::{sum_coins, Coin};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::TxId;
use chain_core::tx::witness::tree::RawPubkey;
use chain_core::tx::TxAux;
use client_common::balance::TransactionChange;
use client_common::storage::UnauthorizedStorage;
use client_common::{Error, ErrorKind, Result, Storage};
use client_index::index::{Index, UnauthorizedIndex};

use crate::service::*;
use crate::transaction_builder::UnauthorizedTransactionBuilder;
use crate::{
    InputSelectionStrategy, MultiSigWalletClient, PrivateKey, PublicKey, TransactionBuilder,
    UnspentTransactions, WalletClient,
};

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
    root_hash_service: RootHashService<S>,
    multi_sig_session_service: MultiSigSessionService<S>,
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
            wallet_service: WalletService::new(storage.clone()),
            root_hash_service: RootHashService::new(storage.clone()),
            multi_sig_session_service: MultiSigSessionService::new(storage),
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

    fn new_wallet(&self, name: &str, passphrase: &SecUtf8) -> Result<()> {
        self.wallet_service.create(name, passphrase)
    }

    fn public_keys(&self, name: &str, passphrase: &SecUtf8) -> Result<Vec<PublicKey>> {
        self.wallet_service.public_keys(name, passphrase)
    }

    fn root_hashes(&self, name: &str, passphrase: &SecUtf8) -> Result<Vec<H256>> {
        self.wallet_service.root_hashes(name, passphrase)
    }

    fn redeem_addresses(&self, name: &str, passphrase: &SecUtf8) -> Result<Vec<ExtendedAddr>> {
        self.wallet_service.redeem_addresses(name, passphrase)
    }

    fn tree_addresses(&self, name: &str, passphrase: &SecUtf8) -> Result<Vec<ExtendedAddr>> {
        self.wallet_service.tree_addresses(name, passphrase)
    }

    fn addresses(&self, name: &str, passphrase: &SecUtf8) -> Result<Vec<ExtendedAddr>> {
        self.wallet_service.addresses(name, passphrase)
    }

    fn find(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        address: &ExtendedAddr,
    ) -> Result<Option<Either<PublicKey, H256>>> {
        self.wallet_service.find(name, passphrase, address)
    }

    fn private_key(
        &self,
        passphrase: &SecUtf8,
        public_key: &PublicKey,
    ) -> Result<Option<PrivateKey>> {
        self.key_service.private_key(public_key, passphrase)
    }

    fn new_public_key(&self, name: &str, passphrase: &SecUtf8) -> Result<PublicKey> {
        let (public_key, _) = self.key_service.generate_keypair(passphrase)?;
        self.wallet_service
            .add_public_key(name, passphrase, public_key.clone())?;

        Ok(public_key)
    }

    fn new_redeem_address(&self, name: &str, passphrase: &SecUtf8) -> Result<ExtendedAddr> {
        let public_key = self.new_public_key(name, passphrase)?;
        Ok(ExtendedAddr::BasicRedeem(RedeemAddress::from(&public_key)))
    }

    fn new_tree_address(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
        m: usize,
        n: usize,
    ) -> Result<ExtendedAddr> {
        // To verify if the passphrase is correct or not
        self.tree_addresses(name, passphrase)?;

        let root_hash =
            self.root_hash_service
                .new_root_hash(public_keys, self_public_key, m, n, passphrase)?;

        self.wallet_service
            .add_root_hash(name, passphrase, root_hash)?;

        Ok(ExtendedAddr::OrTree(root_hash))
    }

    fn generate_proof(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        address: &ExtendedAddr,
        public_keys: Vec<PublicKey>,
    ) -> Result<Proof<RawPubkey>> {
        // To verify if the passphrase is correct or not
        self.tree_addresses(name, passphrase)?;

        match address {
            ExtendedAddr::BasicRedeem(_) => Err(ErrorKind::InvalidInput.into()),
            ExtendedAddr::OrTree(ref address) => {
                self.root_hash_service
                    .generate_proof(address, public_keys, passphrase)
            }
        }
    }

    fn required_cosigners(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        root_hash: &H256,
    ) -> Result<usize> {
        // To verify if the passphrase is correct or not
        self.tree_addresses(name, passphrase)?;

        self.root_hash_service
            .required_signers(root_hash, passphrase)
    }

    fn balance(&self, name: &str, passphrase: &SecUtf8) -> Result<Coin> {
        let addresses = self.addresses(name, passphrase)?;

        let balances = addresses
            .iter()
            .map(|address| self.index.balance(address))
            .collect::<Result<Vec<Coin>>>()?;

        Ok(sum_coins(balances.into_iter()).context(ErrorKind::BalanceAdditionError)?)
    }

    fn history(&self, name: &str, passphrase: &SecUtf8) -> Result<Vec<TransactionChange>> {
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
        passphrase: &SecUtf8,
    ) -> Result<UnspentTransactions> {
        let addresses = self.addresses(name, passphrase)?;

        let mut unspent_transactions = Vec::new();
        for address in addresses {
            unspent_transactions.extend(self.index.unspent_transactions(&address)?);
        }

        Ok(UnspentTransactions::new(unspent_transactions))
    }

    fn output(&self, id: &TxId, index: usize) -> Result<TxOut> {
        self.index.output(id, index)
    }

    fn create_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
        input_selection_strategy: Option<InputSelectionStrategy>,
        return_address: ExtendedAddr,
    ) -> Result<TxAux> {
        let mut unspent_transactions = self.unspent_transactions(name, passphrase)?;
        unspent_transactions.apply_all(input_selection_strategy.unwrap_or_default().as_ref());

        self.transaction_builder.build(
            name,
            passphrase,
            outputs,
            attributes,
            unspent_transactions,
            return_address,
        )
    }

    fn broadcast_transaction(&self, tx_aux: &TxAux) -> Result<()> {
        self.index.broadcast_transaction(&tx_aux.encode())
    }

    fn sync(&self) -> Result<()> {
        self.index.sync()
    }

    fn sync_all(&self) -> Result<()> {
        self.index.sync_all()
    }
}

impl<S, I, T> MultiSigWalletClient for DefaultWalletClient<S, I, T>
where
    S: Storage,
    I: Index,
    T: TransactionBuilder,
{
    fn schnorr_signature(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        message: &H256,
        public_key: &PublicKey,
    ) -> Result<SchnorrSignature> {
        // To verify if the passphrase is correct or not
        self.tree_addresses(name, passphrase)?;

        let private_key = match self.private_key(passphrase, public_key)? {
            None => Err(Error::from(ErrorKind::PrivateKeyNotFound)),
            Some(private_key) => Ok(private_key),
        }?;
        private_key.schnorr_sign(message)
    }

    fn new_multi_sig_session(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        message: H256,
        signer_public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
    ) -> Result<H256> {
        // To verify if the passphrase is correct or not
        self.tree_addresses(name, passphrase)?;

        match self.private_key(passphrase, &self_public_key)? {
            None => Err(ErrorKind::PrivateKeyNotFound.into()),
            Some(self_private_key) => self.multi_sig_session_service.new_session(
                message,
                signer_public_keys,
                self_public_key,
                self_private_key,
                passphrase,
            ),
        }
    }

    fn nonce_commitment(&self, session_id: &H256, passphrase: &SecUtf8) -> Result<H256> {
        self.multi_sig_session_service
            .nonce_commitment(session_id, passphrase)
    }

    fn add_nonce_commitment(
        &self,
        session_id: &H256,
        passphrase: &SecUtf8,
        nonce_commitment: H256,
        public_key: &PublicKey,
    ) -> Result<()> {
        self.multi_sig_session_service.add_nonce_commitment(
            session_id,
            nonce_commitment,
            public_key,
            passphrase,
        )
    }

    fn nonce(&self, session_id: &H256, passphrase: &SecUtf8) -> Result<PublicKey> {
        self.multi_sig_session_service.nonce(session_id, passphrase)
    }

    fn add_nonce(
        &self,
        session_id: &H256,
        passphrase: &SecUtf8,
        nonce: PublicKey,
        public_key: &PublicKey,
    ) -> Result<()> {
        self.multi_sig_session_service
            .add_nonce(session_id, nonce, public_key, passphrase)
    }

    fn partial_signature(&self, session_id: &H256, passphrase: &SecUtf8) -> Result<H256> {
        self.multi_sig_session_service
            .partial_signature(session_id, passphrase)
    }

    fn add_partial_signature(
        &self,
        session_id: &H256,
        passphrase: &SecUtf8,
        partial_signature: H256,
        public_key: &PublicKey,
    ) -> Result<()> {
        self.multi_sig_session_service.add_partial_signature(
            session_id,
            partial_signature,
            public_key,
            passphrase,
        )
    }

    fn signature(&self, session_id: &H256, passphrase: &SecUtf8) -> Result<SchnorrSignature> {
        self.multi_sig_session_service
            .signature(session_id, passphrase)
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

    use chain_core::init::coin::CoinError;
    use chain_core::tx::data::input::TxoPointer;
    use chain_core::tx::data::Tx;
    use chain_core::tx::fee::{Fee, FeeAlgorithm};
    use chain_core::tx::witness::TxInWitness;
    use chain_core::tx::TransactionId;
    use client_common::balance::BalanceChange;
    use client_common::storage::MemoryStorage;

    use crate::signer::DefaultSigner;
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

        fn unspent_transactions(&self, address: &ExtendedAddr) -> Result<Vec<(TxoPointer, TxOut)>> {
            if address == &self.addr_1 {
                Ok(Default::default())
            } else if address == &self.addr_2 {
                if *self.changed.read().unwrap() {
                    Ok(Default::default())
                } else {
                    Ok(vec![(
                        TxoPointer::new([1u8; 32], 0),
                        TxOut {
                            address: self.addr_2.clone(),
                            value: Coin::new(30).unwrap(),
                            valid_from: None,
                        },
                    )])
                }
            } else if *self.changed.read().unwrap() && address == &self.addr_3 {
                Ok(vec![(
                    TxoPointer::new([2u8; 32], 0),
                    TxOut {
                        address: self.addr_3.clone(),
                        value: Coin::new(30).unwrap(),
                        valid_from: None,
                    },
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
            .addresses("name", &SecUtf8::from("passphrase"))
            .is_err());

        wallet
            .new_wallet("name", &SecUtf8::from("passphrase"))
            .expect("Unable to create a new wallet");

        assert_eq!(
            0,
            wallet
                .addresses("name", &SecUtf8::from("passphrase"))
                .unwrap()
                .len()
        );
        assert_eq!("name".to_string(), wallet.wallets().unwrap()[0]);
        assert_eq!(1, wallet.wallets().unwrap().len());

        let address = wallet
            .new_redeem_address("name", &SecUtf8::from("passphrase"))
            .expect("Unable to generate new address");

        let addresses = wallet
            .addresses("name", &SecUtf8::from("passphrase"))
            .unwrap();

        assert_eq!(1, addresses.len());
        assert_eq!(address, addresses[0], "Addresses don't match");

        assert!(wallet
            .find("name", &SecUtf8::from("passphrase"), &address)
            .unwrap()
            .is_some());

        assert!(wallet
            .private_key(
                &SecUtf8::from("passphrase"),
                &wallet
                    .find("name", &SecUtf8::from("passphrase"), &address)
                    .unwrap()
                    .unwrap()
                    .left()
                    .unwrap()
            )
            .unwrap()
            .is_some());

        assert_eq!(
            ErrorKind::WalletNotFound,
            wallet
                .public_keys("name_new", &SecUtf8::from("passphrase"))
                .expect_err("Found public keys for non existent wallet")
                .kind(),
            "Invalid public key present in database"
        );

        assert_eq!(
            ErrorKind::WalletNotFound,
            wallet
                .new_public_key("name_new", &SecUtf8::from("passphrase"))
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
            .new_wallet("wallet_1", &SecUtf8::from("passphrase"))
            .unwrap();
        let addr_1 = wallet
            .new_redeem_address("wallet_1", &SecUtf8::from("passphrase"))
            .unwrap();
        wallet
            .new_wallet("wallet_2", &SecUtf8::from("passphrase"))
            .unwrap();
        let addr_2 = wallet
            .new_redeem_address("wallet_2", &SecUtf8::from("passphrase"))
            .unwrap();
        wallet
            .new_wallet("wallet_3", &SecUtf8::from("passphrase"))
            .unwrap();
        let addr_3 = wallet
            .new_redeem_address("wallet_3", &SecUtf8::from("passphrase"))
            .unwrap();

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .balance("wallet_1", &SecUtf8::from("passphrase"))
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
                .balance("wallet_1", &SecUtf8::from("passphrase"))
                .unwrap()
        );
        assert_eq!(
            Coin::new(30).unwrap(),
            wallet
                .balance("wallet_2", &SecUtf8::from("passphrase"))
                .unwrap()
        );
        assert_eq!(
            Coin::new(0).unwrap(),
            wallet
                .balance("wallet_3", &SecUtf8::from("passphrase"))
                .unwrap()
        );

        assert_eq!(
            2,
            wallet
                .history("wallet_1", &SecUtf8::from("passphrase"))
                .unwrap()
                .len()
        );
        assert_eq!(
            1,
            wallet
                .history("wallet_2", &SecUtf8::from("passphrase"))
                .unwrap()
                .len()
        );
        assert_eq!(
            0,
            wallet
                .history("wallet_3", &SecUtf8::from("passphrase"))
                .unwrap()
                .len()
        );

        assert!(wallet.sync().is_ok());
        assert!(wallet.sync_all().is_ok());

        let signer = DefaultSigner::new(storage.clone());

        let wallet = DefaultWalletClient::builder()
            .with_wallet(storage)
            .with_transaction_read(wallet.index)
            .with_transaction_write(DefaultTransactionBuilder::new(
                signer,
                ZeroFeeAlgorithm::default(),
            ))
            .build()
            .unwrap();

        let transaction = wallet
            .create_transaction(
                "wallet_2",
                &SecUtf8::from("passphrase"),
                vec![TxOut {
                    address: addr_3.clone(),
                    value: Coin::new(30).unwrap(),
                    valid_from: None,
                }],
                TxAttributes::new(171),
                None,
                addr_1.clone(),
            )
            .unwrap();

        assert!(wallet.broadcast_transaction(&transaction).is_ok());

        assert_eq!(
            Coin::new(0).unwrap(),
            wallet
                .balance("wallet_1", &SecUtf8::from("passphrase"))
                .unwrap()
        );
        assert_eq!(
            Coin::new(0).unwrap(),
            wallet
                .balance("wallet_2", &SecUtf8::from("passphrase"))
                .unwrap()
        );
        assert_eq!(
            Coin::new(30).unwrap(),
            wallet
                .balance("wallet_3", &SecUtf8::from("passphrase"))
                .unwrap()
        );

        assert_eq!(
            2,
            wallet
                .history("wallet_1", &SecUtf8::from("passphrase"))
                .unwrap()
                .len()
        );
        assert_eq!(
            2,
            wallet
                .history("wallet_2", &SecUtf8::from("passphrase"))
                .unwrap()
                .len()
        );
        assert_eq!(
            1,
            wallet
                .history("wallet_3", &SecUtf8::from("passphrase"))
                .unwrap()
                .len()
        );

        let transaction = wallet
            .create_transaction(
                "wallet_3",
                &SecUtf8::from("passphrase"),
                vec![TxOut {
                    address: addr_2.clone(),
                    value: Coin::new(20).unwrap(),
                    valid_from: None,
                }],
                TxAttributes::new(171),
                None,
                addr_1.clone(),
            )
            .unwrap();

        assert!(wallet.broadcast_transaction(&transaction).is_ok());

        assert_eq!(
            ErrorKind::InsufficientBalance,
            wallet
                .create_transaction(
                    "wallet_2",
                    &SecUtf8::from("passphrase"),
                    vec![TxOut {
                        address: addr_3.clone(),
                        value: Coin::new(30).unwrap(),
                        valid_from: None,
                    }],
                    TxAttributes::new(171),
                    None,
                    addr_1.clone()
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
                .new_wallet("name", &SecUtf8::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .public_keys("name", &SecUtf8::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .addresses("name", &SecUtf8::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .private_key(
                    &SecUtf8::from("passphrase"),
                    &PublicKey::from(&PrivateKey::new().unwrap())
                )
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .new_public_key("name", &SecUtf8::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .new_redeem_address("name", &SecUtf8::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .balance("name", &SecUtf8::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .history("name", &SecUtf8::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .unspent_transactions("name", &SecUtf8::from("passphrase"))
                .unwrap_err()
                .kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet.output(&[1u8; 32], 0).unwrap_err().kind()
        );

        assert_eq!(
            ErrorKind::PermissionDenied,
            wallet
                .create_transaction(
                    "name",
                    &SecUtf8::from("passphrase"),
                    Vec::new(),
                    TxAttributes::new(171),
                    None,
                    ExtendedAddr::BasicRedeem(RedeemAddress::from(&PublicKey::from(
                        &PrivateKey::new().unwrap()
                    )))
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
        let storage = MemoryStorage::default();
        let signer = DefaultSigner::new(storage);
        let builder = DefaultWalletClient::builder().with_transaction_write(
            DefaultTransactionBuilder::new(signer, ZeroFeeAlgorithm::default()),
        );

        assert_eq!(ErrorKind::InvalidInput, builder.build().unwrap_err().kind());
    }

    #[test]
    fn check_multi_sig_address_generation() {
        let storage = MemoryStorage::default();
        let wallet = DefaultWalletClient::builder()
            .with_wallet(storage.clone())
            .build()
            .unwrap();

        let passphrase = SecUtf8::from("passphrase");
        let name = "name";

        assert_eq!(
            ErrorKind::WalletNotFound,
            wallet
                .tree_addresses(name, &passphrase)
                .expect_err("Found non-existent addresses")
                .kind()
        );

        wallet
            .new_wallet(name, &passphrase)
            .expect("Unable to create a new wallet");

        assert_eq!(0, wallet.tree_addresses(name, &passphrase).unwrap().len());

        let public_keys = vec![
            PublicKey::from(&PrivateKey::new().unwrap()),
            PublicKey::from(&PrivateKey::new().unwrap()),
            PublicKey::from(&PrivateKey::new().unwrap()),
        ];

        let tree_address = wallet
            .new_tree_address(
                name,
                &passphrase,
                public_keys.clone(),
                public_keys[0].clone(),
                2,
                3,
            )
            .unwrap();

        assert_eq!(1, wallet.tree_addresses(name, &passphrase).unwrap().len());

        let root_hash = wallet
            .find(name, &passphrase, &tree_address)
            .unwrap()
            .unwrap()
            .right()
            .unwrap();

        assert_eq!(
            2,
            wallet
                .required_cosigners(name, &passphrase, &root_hash)
                .unwrap()
        );
    }

    #[test]
    fn check_multi_sig_transaction_signing() {
        let storage = MemoryStorage::default();
        let wallet = DefaultWalletClient::builder()
            .with_wallet(storage.clone())
            .build()
            .unwrap();

        let passphrase = &SecUtf8::from("passphrase");
        let name = "name";

        wallet.new_wallet(name, passphrase).unwrap();

        let public_key_1 = wallet.new_public_key(name, passphrase).unwrap();
        let public_key_2 = wallet.new_public_key(name, passphrase).unwrap();
        let public_key_3 = wallet.new_public_key(name, passphrase).unwrap();

        let public_keys = vec![
            public_key_1.clone(),
            public_key_2.clone(),
            public_key_3.clone(),
        ];

        let multi_sig_address = wallet
            .new_tree_address(
                name,
                passphrase,
                public_keys.clone(),
                public_keys[0].clone(),
                2,
                3,
            )
            .unwrap();

        let transaction = Tx::new();

        let session_id_1 = wallet
            .new_multi_sig_session(
                name,
                passphrase,
                transaction.id(),
                vec![public_key_1.clone(), public_key_2.clone()],
                public_key_1.clone(),
            )
            .unwrap();
        let session_id_2 = wallet
            .new_multi_sig_session(
                name,
                passphrase,
                transaction.id(),
                vec![public_key_1.clone(), public_key_2.clone()],
                public_key_2.clone(),
            )
            .unwrap();

        let nonce_commitment_1 = wallet.nonce_commitment(&session_id_1, passphrase).unwrap();
        let nonce_commitment_2 = wallet.nonce_commitment(&session_id_2, passphrase).unwrap();

        assert!(wallet
            .add_nonce_commitment(&session_id_1, passphrase, nonce_commitment_2, &public_key_2)
            .is_ok());
        assert!(wallet
            .add_nonce_commitment(&session_id_2, passphrase, nonce_commitment_1, &public_key_1)
            .is_ok());

        let nonce_1 = wallet.nonce(&session_id_1, passphrase).unwrap();
        let nonce_2 = wallet.nonce(&session_id_2, passphrase).unwrap();

        assert!(wallet
            .add_nonce(&session_id_1, passphrase, nonce_2, &public_key_2)
            .is_ok());
        assert!(wallet
            .add_nonce(&session_id_2, passphrase, nonce_1, &public_key_1)
            .is_ok());

        let partial_signature_1 = wallet.partial_signature(&session_id_1, passphrase).unwrap();
        let partial_signature_2 = wallet.partial_signature(&session_id_2, passphrase).unwrap();

        assert!(wallet
            .add_partial_signature(
                &session_id_1,
                passphrase,
                partial_signature_2,
                &public_key_2
            )
            .is_ok());
        assert!(wallet
            .add_partial_signature(
                &session_id_2,
                passphrase,
                partial_signature_1,
                &public_key_1
            )
            .is_ok());

        let signature = wallet.signature(&session_id_1, passphrase).unwrap();
        let proof = wallet
            .generate_proof(
                name,
                passphrase,
                &multi_sig_address,
                vec![public_key_1.clone(), public_key_2.clone()],
            )
            .unwrap();

        let witness = TxInWitness::TreeSig(signature, proof);

        assert!(witness
            .verify_tx_address(&transaction.id(), &multi_sig_address)
            .is_ok())
    }

    #[test]
    fn check_1_of_n_schnorr_signature() {
        let storage = MemoryStorage::default();
        let wallet = DefaultWalletClient::builder()
            .with_wallet(storage.clone())
            .build()
            .unwrap();

        let passphrase = &SecUtf8::from("passphrase");
        let name = "name";

        wallet.new_wallet(name, passphrase).unwrap();

        let public_key_1 = wallet.new_public_key(name, passphrase).unwrap();
        let public_key_2 = wallet.new_public_key(name, passphrase).unwrap();
        let public_key_3 = wallet.new_public_key(name, passphrase).unwrap();

        let public_keys = vec![
            public_key_1.clone(),
            public_key_2.clone(),
            public_key_3.clone(),
        ];

        let tree_address = wallet
            .new_tree_address(
                name,
                passphrase,
                public_keys.clone(),
                public_keys[0].clone(),
                1,
                3,
            )
            .unwrap();

        let transaction = Tx::new();

        let signature = wallet
            .schnorr_signature(name, passphrase, &transaction.id(), &public_key_1)
            .unwrap();

        println!("Signature");

        let proof = wallet
            .generate_proof(name, passphrase, &tree_address, vec![public_key_1.clone()])
            .unwrap();

        let witness = TxInWitness::TreeSig(signature, proof);

        assert!(witness
            .verify_tx_address(&transaction.id(), &tree_address)
            .is_ok())
    }
}
