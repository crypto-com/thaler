use std::collections::BTreeSet;

use crate::service::*;
use crate::transaction_builder::UnauthorizedTransactionBuilder;
use crate::types::WalletKind;
use crate::types::{BalanceChange, TransactionChange};
use crate::{
    InputSelectionStrategy, MultiSigWalletClient, TransactionBuilder, UnspentTransactions,
    WalletClient,
};
use bip39::{Language, Mnemonic};
use chain_core::common::{Proof, H256};
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::state::account::StakedStateAddress;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::Tx;
use chain_core::tx::witness::tree::RawPubkey;
use chain_core::tx::witness::{TxInWitness, TxWitness};
use chain_core::tx::TxAux;
use client_common::tendermint::types::BroadcastTxResult;
use client_common::tendermint::{Client, UnauthorizedClient};
use client_common::{
    Error, ErrorKind, PrivateKey, PublicKey, Result, ResultExt, SignedTransaction, Storage,
};
use parity_scale_codec::Encode;
use secp256k1::schnorrsig::SchnorrSignature;
use secstr::SecUtf8;

/// Default implementation of `WalletClient` based on `Storage` and `Index`
#[derive(Debug, Default, Clone)]
pub struct DefaultWalletClient<S, C, T>
where
    S: Storage,
    C: Client,
    T: TransactionBuilder,
{
    key_service: KeyService<S>,
    wallet_service: WalletService<S>,
    wallet_state_service: WalletStateService<S>,
    root_hash_service: RootHashService<S>,
    multi_sig_session_service: MultiSigSessionService<S>,

    tendermint_client: C,
    transaction_builder: T,
}

impl<S, C, T> DefaultWalletClient<S, C, T>
where
    S: Storage + Clone,
    C: Client,
    T: TransactionBuilder,
{
    /// Creates a new instance of `DefaultWalletClient`
    pub fn new(storage: S, tendermint_client: C, transaction_builder: T) -> Self {
        Self {
            key_service: KeyService::new(storage.clone()),
            wallet_service: WalletService::new(storage.clone()),
            wallet_state_service: WalletStateService::new(storage.clone()),
            root_hash_service: RootHashService::new(storage.clone()),
            multi_sig_session_service: MultiSigSessionService::new(storage),
            tendermint_client,
            transaction_builder,
        }
    }
}

impl<S> DefaultWalletClient<S, UnauthorizedClient, UnauthorizedTransactionBuilder>
where
    S: Storage + Clone,
{
    /// Creates a new read-only instance of `DefaultWalletClient`
    pub fn new_read_only(storage: S) -> Self {
        Self::new(storage, UnauthorizedClient, UnauthorizedTransactionBuilder)
    }
}

impl<S, C, T> WalletClient for DefaultWalletClient<S, C, T>
where
    S: Storage,
    C: Client,
    T: TransactionBuilder,
{
    #[inline]
    fn wallets(&self) -> Result<Vec<String>> {
        self.wallet_service.names()
    }

    fn new_wallet(&self, name: &str, passphrase: &SecUtf8) -> Result<()> {
        log::debug!("DefaultWalletClient New Wallet");
        log::debug!(
            "is hd wallet={}",
            self.key_service.get_wallet_type(name, passphrase)? == WalletKind::HD
        );
        let view_key = self
            .key_service
            .generate_keypair_auto(name, passphrase, false)?
            .0;

        self.wallet_service.create(name, passphrase, view_key)
    }

    /// Creates mnemonics
    fn new_mnemonics(&self) -> Result<Mnemonic> {
        Ok(get_random_mnemonic())
    }

    /// Creates a new hd-wallet with given name and passphrase
    fn new_hdwallet(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        mnemonics_phrase: &SecUtf8,
    ) -> Result<()> {
        let mnemonic =
            Mnemonic::from_phrase(mnemonics_phrase.unsecure(), Language::English).unwrap();

        // load seed
        self.key_service.generate_seed(&mnemonic, name, passphrase)
    }

    #[inline]
    fn view_key(&self, name: &str, passphrase: &SecUtf8) -> Result<PublicKey> {
        self.wallet_service.view_key(name, passphrase)
    }

    #[inline]
    fn public_keys(&self, name: &str, passphrase: &SecUtf8) -> Result<BTreeSet<PublicKey>> {
        self.wallet_service.public_keys(name, passphrase)
    }

    #[inline]
    fn staking_keys(&self, name: &str, passphrase: &SecUtf8) -> Result<BTreeSet<PublicKey>> {
        self.wallet_service.staking_keys(name, passphrase)
    }

    #[inline]
    fn root_hashes(&self, name: &str, passphrase: &SecUtf8) -> Result<BTreeSet<H256>> {
        self.wallet_service.root_hashes(name, passphrase)
    }

    #[inline]
    fn staking_addresses(
        &self,
        name: &str,
        passphrase: &SecUtf8,
    ) -> Result<BTreeSet<StakedStateAddress>> {
        self.wallet_service.staking_addresses(name, passphrase)
    }

    #[inline]
    fn transfer_addresses(
        &self,
        name: &str,
        passphrase: &SecUtf8,
    ) -> Result<BTreeSet<ExtendedAddr>> {
        self.wallet_service.transfer_addresses(name, passphrase)
    }

    #[inline]
    fn find_staking_key(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        redeem_address: &RedeemAddress,
    ) -> Result<Option<PublicKey>> {
        self.wallet_service
            .find_staking_key(name, passphrase, redeem_address)
    }

    #[inline]
    fn find_root_hash(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        address: &ExtendedAddr,
    ) -> Result<Option<H256>> {
        self.wallet_service
            .find_root_hash(name, passphrase, address)
    }

    #[inline]
    fn private_key(
        &self,
        passphrase: &SecUtf8,
        public_key: &PublicKey,
    ) -> Result<Option<PrivateKey>> {
        self.key_service.private_key(public_key, passphrase)
    }

    fn new_public_key(&self, name: &str, passphrase: &SecUtf8) -> Result<PublicKey> {
        let (public_key, _) = self
            .key_service
            .generate_keypair_auto(name, passphrase, false)?;
        self.wallet_service
            .add_public_key(name, passphrase, &public_key)?;

        Ok(public_key)
    }

    fn new_staking_address(&self, name: &str, passphrase: &SecUtf8) -> Result<StakedStateAddress> {
        let (staking_key, _) = self
            .key_service
            .generate_keypair_auto(name, passphrase, true)?;
        self.wallet_service
            .add_staking_key(name, passphrase, &staking_key)?;

        Ok(StakedStateAddress::BasicRedeem(RedeemAddress::from(
            &staking_key,
        )))
    }

    fn new_transfer_address(&self, name: &str, passphrase: &SecUtf8) -> Result<ExtendedAddr> {
        let (public_key, _) = self
            .key_service
            .generate_keypair_auto(name, passphrase, false)?;
        self.new_multisig_transfer_address(
            name,
            passphrase,
            vec![public_key.clone()],
            public_key,
            1,
            1,
        )
    }

    fn new_multisig_transfer_address(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
        m: usize,
        n: usize,
    ) -> Result<ExtendedAddr> {
        // Check if self public key belongs to current wallet
        let _ = self.private_key(passphrase, &self_public_key)?.chain(|| {
            (
                ErrorKind::InvalidInput,
                "Self public key does not belong to current wallet",
            )
        })?;

        if !public_keys.contains(&self_public_key) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Signer public keys does not contain self public key",
            ));
        }

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
        self.wallet_service.view_key(name, passphrase)?;

        match address {
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
        self.wallet_service.view_key(name, passphrase)?;

        self.root_hash_service
            .required_signers(root_hash, passphrase)
    }

    #[inline]
    fn balance(&self, name: &str, passphrase: &SecUtf8) -> Result<Coin> {
        // Check if wallet exists
        self.wallet_service.view_key(name, passphrase)?;
        self.wallet_state_service.get_balance(name, passphrase)
    }

    fn history(&self, name: &str, passphrase: &SecUtf8) -> Result<Vec<TransactionChange>> {
        // Check if wallet exists
        self.wallet_service.view_key(name, passphrase)?;

        let history_map = self
            .wallet_state_service
            .get_transaction_history(name, passphrase)?;

        let mut history = history_map
            .values()
            .filter(|change| BalanceChange::NoChange != change.balance_change)
            .map(Clone::clone)
            .collect::<Vec<TransactionChange>>();

        history.sort_by(|current, other| current.block_height.cmp(&other.block_height).reverse());

        Ok(history)
    }

    fn unspent_transactions(
        &self,
        name: &str,
        passphrase: &SecUtf8,
    ) -> Result<UnspentTransactions> {
        // Check if wallet exists
        self.wallet_service.view_key(name, passphrase)?;

        let unspent_transactions = self
            .wallet_state_service
            .get_unspent_transactions(name, passphrase)?;

        Ok(UnspentTransactions::new(
            unspent_transactions.into_iter().collect(),
        ))
    }

    #[inline]
    fn output(&self, name: &str, passphrase: &SecUtf8, input: &TxoPointer) -> Result<TxOut> {
        // Check if wallet exists
        self.wallet_service.view_key(name, passphrase)?;

        self.wallet_state_service
            .get_output(name, passphrase, input)
            .and_then(|optional| {
                optional.chain(|| {
                    (
                        ErrorKind::InvalidInput,
                        "Output details not found for given transaction input",
                    )
                })
            })
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

    #[inline]
    fn broadcast_transaction(&self, tx_aux: &TxAux) -> Result<BroadcastTxResult> {
        self.tendermint_client
            .broadcast_transaction(&tx_aux.encode())
    }
}

impl<S, C, T> MultiSigWalletClient for DefaultWalletClient<S, C, T>
where
    S: Storage,
    C: Client,
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
        self.transfer_addresses(name, passphrase)?;

        let private_key = self.private_key(passphrase, public_key)?.chain(|| {
            (
                ErrorKind::InvalidInput,
                format!("Public key ({}) is not owned by current wallet", public_key),
            )
        })?;
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
        self.transfer_addresses(name, passphrase)?;

        let self_private_key = self.private_key(passphrase, &self_public_key)?.chain(|| {
            (
                ErrorKind::InvalidInput,
                format!(
                    "Self public key ({}) is not owned by current wallet",
                    self_public_key
                ),
            )
        })?;

        self.multi_sig_session_service.new_session(
            message,
            signer_public_keys,
            self_public_key,
            self_private_key,
            passphrase,
        )
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
        nonce: &PublicKey,
        public_key: &PublicKey,
    ) -> Result<()> {
        self.multi_sig_session_service
            .add_nonce(session_id, &nonce, public_key, passphrase)
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

    fn transaction(
        &self,
        name: &str,
        session_id: &H256,
        passphrase: &SecUtf8,
        unsigned_transaction: Tx,
    ) -> Result<TxAux> {
        if unsigned_transaction.inputs.len() != 1 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Multi-Sig Signing is only supported for transactions with only one input",
            ));
        }

        let output_to_spend = self.output(name, passphrase, &unsigned_transaction.inputs[0])?;
        let root_hash = self
            .wallet_service
            .find_root_hash(name, passphrase, &output_to_spend.address)?
            .chain(|| {
                (
                    ErrorKind::IllegalInput,
                    "Output address is not owned by current wallet; cannot spend output in given transaction",
                )
            })?;
        let public_keys = self
            .multi_sig_session_service
            .public_keys(session_id, passphrase)?;

        let proof = self
            .root_hash_service
            .generate_proof(&root_hash, public_keys, passphrase)?;
        let signature = self.signature(session_id, passphrase)?;

        let witness = TxWitness::from(vec![TxInWitness::TreeSig(signature, proof)]);
        let signed_transaction =
            SignedTransaction::TransferTransaction(unsigned_transaction, witness);

        self.transaction_builder.obfuscate(signed_transaction)
    }
}
