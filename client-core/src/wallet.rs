//! Wallet management
mod default_wallet_client;

pub use default_wallet_client::DefaultWalletClient;

use secp256k1::schnorrsig::SchnorrSignature;
use secstr::SecUtf8;

use chain_core::common::{Proof, H256};
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::state::account::StakedStateAddress;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::witness::tree::RawPubkey;
use chain_core::tx::TxAux;
use client_common::balance::TransactionChange;
use client_common::{PrivateKey, PublicKey, Result};

use crate::{InputSelectionStrategy, UnspentTransactions};

/// Interface for a generic wallet
pub trait WalletClient: Send + Sync {
    /// Retrieves names of all wallets stored
    fn wallets(&self) -> Result<Vec<String>>;

    /// Creates a new wallet with given name and passphrase
    fn new_wallet(&self, name: &str, passphrase: &SecUtf8) -> Result<()>;

    /// Retrieves view key corresponding to a given wallet
    fn view_key(&self, name: &str, passphrase: &SecUtf8) -> Result<PublicKey>;

    /// Retrieves all public keys corresponding to given wallet
    fn public_keys(&self, name: &str, passphrase: &SecUtf8) -> Result<Vec<PublicKey>>;

    /// Retrieves all root hashes corresponding to given wallet
    fn root_hashes(&self, name: &str, passphrase: &SecUtf8) -> Result<Vec<H256>>;

    /// Returns all staking addresses in current wallet
    fn staking_addresses(
        &self,
        name: &str,
        passphrase: &SecUtf8,
    ) -> Result<Vec<StakedStateAddress>>;

    /// Returns all the multi-sig transfer addresses in current wallet
    fn transfer_addresses(&self, name: &str, passphrase: &SecUtf8) -> Result<Vec<ExtendedAddr>>;

    /// Finds public key corresponding to given redeem address
    fn find_public_key(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        redeem_address: &RedeemAddress,
    ) -> Result<Option<PublicKey>>;

    /// Checks if root hash exists in current wallet and returns root hash if exists
    fn find_root_hash(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        address: &ExtendedAddr,
    ) -> Result<Option<H256>>;

    /// Retrieves private key corresponding to given public key
    fn private_key(
        &self,
        passphrase: &SecUtf8,
        public_key: &PublicKey,
    ) -> Result<Option<PrivateKey>>;

    /// Generates a new public key for given wallet
    fn new_public_key(&self, name: &str, passphrase: &SecUtf8) -> Result<PublicKey>;

    /// Generates a new redeem address for given wallet
    fn new_staking_address(&self, name: &str, passphrase: &SecUtf8) -> Result<StakedStateAddress>;

    /// Generates a new 1-of-1 transfer address
    fn new_single_transfer_address(&self, name: &str, passphrase: &SecUtf8)
        -> Result<ExtendedAddr>;

    /// Generates a new multi-sig transfer address for creating m-of-n transactions
    ///
    /// # Arguments
    ///
    /// `name`: Name of wallet
    /// `passphrase`: passphrase of wallet
    /// `public_keys`: Public keys of co-signers (including public key of current co-signer)
    /// `self_public_key`: Public key of current co-signer
    /// `m`: Number of required co-signers
    /// `n`: Total number of co-signers
    fn new_transfer_address(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
        m: usize,
        n: usize,
    ) -> Result<ExtendedAddr>;

    /// Generates inclusion proof for set of public keys in multi-sig address
    fn generate_proof(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        address: &ExtendedAddr,
        public_keys: Vec<PublicKey>,
    ) -> Result<Proof<RawPubkey>>;

    /// Returns number of cosigners required to sign the transaction
    fn required_cosigners(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        root_hash: &H256,
    ) -> Result<usize>;

    /// Retrieves current balance of wallet
    fn balance(&self, name: &str, passphrase: &SecUtf8) -> Result<Coin>;

    /// Retrieves transaction history of wallet
    fn history(&self, name: &str, passphrase: &SecUtf8) -> Result<Vec<TransactionChange>>;

    /// Retrieves all unspent transactions of wallet
    fn unspent_transactions(&self, name: &str, passphrase: &SecUtf8)
        -> Result<UnspentTransactions>;

    /// Returns output of transaction with given input details
    fn output(&self, id: &TxoPointer) -> Result<TxOut>;

    /// Builds a transaction
    ///
    /// # Attributes
    ///
    /// - `name`: Name of wallet
    /// - `passphrase`: Passphrase of wallet
    /// - `outputs`: Transaction outputs
    /// - `attributes`: Transaction attributes,
    /// - `input_selection_strategy`: Strategy to use while selecting unspent transactions
    /// - `return_address`: Address to which change amount will get returned
    fn create_transaction(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
        input_selection_strategy: Option<InputSelectionStrategy>,
        return_address: ExtendedAddr,
    ) -> Result<TxAux>;

    /// Broadcasts a transaction to Crypto.com Chain
    fn broadcast_transaction(&self, tx_aux: &TxAux) -> Result<()>;
}

/// Interface for a generic wallet for multi-signature transactions
pub trait MultiSigWalletClient: WalletClient {
    /// Creates a 1-of-n schnorr signature.
    fn schnorr_signature(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        message: &H256,
        public_key: &PublicKey,
    ) -> Result<SchnorrSignature>;

    /// Creates a new multi-sig session and returns session-id
    ///
    /// # Arguments
    ///
    /// `name`: Name of wallet
    /// `passphrase`: passphrase of wallet
    /// `message`: Message to be signed,
    /// `signer_public_keys`: Public keys of all co-signers (including current signer)
    /// `self_public_key`: Public key of current signer
    fn new_multi_sig_session(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        message: H256,
        signer_public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
    ) -> Result<H256>;

    /// Returns nonce commitment of current signer
    fn nonce_commitment(&self, session_id: &H256, passphrase: &SecUtf8) -> Result<H256>;

    /// Adds a nonce commitment from a public key to session with given id
    fn add_nonce_commitment(
        &self,
        session_id: &H256,
        passphrase: &SecUtf8,
        nonce_commitment: H256,
        public_key: &PublicKey,
    ) -> Result<()>;

    /// Returns nonce of current signer. This function will fail if nonce commitments from all co-signers are not
    /// received.
    fn nonce(&self, session_id: &H256, passphrase: &SecUtf8) -> Result<PublicKey>;

    /// Adds a nonce from a public key to session with given id
    fn add_nonce(
        &self,
        session_id: &H256,
        passphrase: &SecUtf8,
        nonce: &PublicKey,
        public_key: &PublicKey,
    ) -> Result<()>;

    /// Returns partial signature of current signer. This function will fail if nonces from all co-signers are not
    /// received.
    fn partial_signature(&self, session_id: &H256, passphrase: &SecUtf8) -> Result<H256>;

    /// Adds a partial signature from a public key to session with given id
    fn add_partial_signature(
        &self,
        session_id: &H256,
        passphrase: &SecUtf8,
        partial_signature: H256,
        public_key: &PublicKey,
    ) -> Result<()>;

    /// Returns final signature. This function will fail if partial signatures from all co-signers are not received.
    fn signature(&self, session_id: &H256, passphrase: &SecUtf8) -> Result<SchnorrSignature>;
}
