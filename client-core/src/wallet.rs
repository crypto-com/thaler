//! Wallet management
mod default_wallet_client;
/// Wallet synchronizer
pub mod syncer;
mod syncer_logic;

pub use default_wallet_client::DefaultWalletClient;

use std::collections::BTreeSet;

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
use chain_core::tx::data::{Tx, TxId};
use chain_core::tx::witness::tree::RawPubkey;
use chain_core::tx::TxAux;
use client_common::tendermint::types::BroadcastTxResponse;
use client_common::{PrivateKey, PublicKey, Result, SecKey};

use crate::types::{AddressType, TransactionChange, TransactionPending, WalletBalance, WalletKind};
use crate::{InputSelectionStrategy, Mnemonic, UnspentTransactions};

/// Interface for a generic wallet
pub trait WalletClient: Send + Sync {
    /// Retrieves names of all wallets stored
    fn wallets(&self) -> Result<Vec<String>>;

    /// Creates a new wallet with given name, enckey and kind. Returns mnemonics if `wallet_kind` was `HD`.
    fn new_wallet(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        wallet_kind: WalletKind,
    ) -> Result<(SecKey, Option<Mnemonic>)>;

    /// Restores a HD wallet from given mnemonic
    fn restore_wallet(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        mnemonic: &Mnemonic,
    ) -> Result<SecKey>;

    /// Restore a watch only wallet with view key
    fn restore_basic_wallet(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        view_key: &PrivateKey,
    ) -> Result<SecKey>;

    /// get auth token client
    fn auth_token(&self, name: &str, passphrase: &SecUtf8) -> Result<SecKey>;

    /// Retrieves view key corresponding to a given wallet
    fn view_key(&self, name: &str, enckey: &SecKey) -> Result<PublicKey>;

    /// Retrieves private view key corresponding to a given wallet
    fn view_key_private(&self, name: &str, enckey: &SecKey) -> Result<PrivateKey>;

    /// Retrieves all public keys corresponding to given wallet
    fn public_keys(&self, name: &str, enckey: &SecKey) -> Result<BTreeSet<PublicKey>>;

    /// Retrieves all public keys corresponding to staking addresses stored in given wallet
    fn staking_keys(&self, name: &str, enckey: &SecKey) -> Result<BTreeSet<PublicKey>>;

    /// Retrieves all root hashes corresponding to given wallet
    fn root_hashes(&self, name: &str, enckey: &SecKey) -> Result<BTreeSet<H256>>;

    /// Returns all staking addresses in current wallet
    fn staking_addresses(
        &self,
        name: &str,
        enckey: &SecKey,
    ) -> Result<BTreeSet<StakedStateAddress>>;

    /// Returns all the multi-sig transfer addresses in current wallet
    fn transfer_addresses(&self, name: &str, enckey: &SecKey) -> Result<BTreeSet<ExtendedAddr>>;

    /// Finds staking key corresponding to given redeem address
    fn find_staking_key(
        &self,
        name: &str,
        enckey: &SecKey,
        redeem_address: &RedeemAddress,
    ) -> Result<Option<PublicKey>>;

    /// Checks if root hash exists in current wallet and returns root hash if exists
    fn find_root_hash(
        &self,
        name: &str,
        enckey: &SecKey,
        address: &ExtendedAddr,
    ) -> Result<Option<H256>>;

    /// Retrieves private key corresponding to given public key
    fn private_key(&self, enckey: &SecKey, public_key: &PublicKey) -> Result<Option<PrivateKey>>;

    /// Generates a new public key for given wallet
    fn new_public_key(
        &self,
        name: &str,
        enckey: &SecKey,
        address_type: Option<AddressType>,
    ) -> Result<PublicKey>;

    /// Generates a new redeem address for given wallet
    fn new_staking_address(&self, name: &str, enckey: &SecKey) -> Result<StakedStateAddress>;

    /// Generates a new 1-of-1 transfer address
    fn new_transfer_address(&self, name: &str, enckey: &SecKey) -> Result<ExtendedAddr>;

    /// Add watch only staking address
    fn new_watch_staking_address(
        &self,
        name: &str,
        enckey: &SecKey,
        public_key: &PublicKey,
    ) -> Result<StakedStateAddress>;

    /// Add watch only transfer address
    fn new_watch_transfer_address(
        &self,
        name: &str,
        enckey: &SecKey,
        public_key: &PublicKey,
    ) -> Result<ExtendedAddr>;

    /// Generates a new multi-sig transfer address for creating m-of-n transactions
    ///
    /// # Arguments
    ///
    /// `name`: Name of wallet
    /// `enckey`: enckey of wallet
    /// `public_keys`: Public keys of co-signers (including public key of current co-signer)
    /// `self_public_key`: Public key of current co-signer
    /// `m`: Number of required co-signers
    fn new_multisig_transfer_address(
        &self,
        name: &str,
        enckey: &SecKey,
        public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
        m: usize,
    ) -> Result<ExtendedAddr>;

    /// Generates inclusion proof for set of public keys in multi-sig address
    fn generate_proof(
        &self,
        name: &str,
        enckey: &SecKey,
        address: &ExtendedAddr,
        public_keys: Vec<PublicKey>,
    ) -> Result<Proof<RawPubkey>>;

    /// Returns number of cosigners required to sign the transaction
    fn required_cosigners(&self, name: &str, enckey: &SecKey, root_hash: &H256) -> Result<usize>;

    /// Retrieves current balance of wallet
    fn balance(&self, name: &str, enckey: &SecKey) -> Result<WalletBalance>;

    /// Retrieves transaction history of wallet
    fn history(
        &self,
        name: &str,
        enckey: &SecKey,
        limit: usize,
        offset: usize,
        reversed: bool,
    ) -> Result<Vec<TransactionChange>>;

    /// Retrieves all unspent transactions of wallet
    fn unspent_transactions(&self, name: &str, enckey: &SecKey) -> Result<UnspentTransactions>;

    /// Checks if all the provided transaction inputs are present in unspent transaction for given wallet
    fn has_unspent_transactions(
        &self,
        name: &str,
        enckey: &SecKey,
        inputs: &[TxoPointer],
    ) -> Result<bool>;

    /// Returns output of transaction with given input details
    fn output(&self, name: &str, enckey: &SecKey, input: &TxoPointer) -> Result<TxOut>;

    /// Builds a transaction
    ///
    /// # Attributes
    ///
    /// - `name`: Name of wallet
    /// - `enckey`: Passphrase of wallet
    /// - `outputs`: Transaction outputs
    /// - `attributes`: Transaction attributes,
    /// - `input_selection_strategy`: Strategy to use while selecting unspent transactions
    /// - `return_address`: Address to which change amount will get returned
    fn create_transaction(
        &self,
        name: &str,
        enckey: &SecKey,
        outputs: Vec<TxOut>,
        attributes: TxAttributes,
        input_selection_strategy: Option<InputSelectionStrategy>,
        return_address: ExtendedAddr,
    ) -> Result<(TxAux, Vec<TxoPointer>, Coin)>;

    /// Broadcasts a transaction to Crypto.com Chain
    fn broadcast_transaction(&self, tx_aux: &TxAux) -> Result<BroadcastTxResponse>;

    /// When receiver's view key not included in the transaction, the receiver can't collect the outputs.
    /// The sender have to get the plain transaction and send it to the receiver by email or something
    /// so that the receiver can sync it into the wallet DB and get the outputs.
    ///
    /// # Return
    ///
    /// base64 encoded of `Transaction` json string
    fn export_plain_tx(&self, name: &str, passphras: &SecKey, txid: &str) -> Result<String>;

    /// import a plain transaction, put the outputs of the transaction into wallet DB
    ///
    /// # Return
    /// the sum of unused outputs coin
    fn import_plain_tx(&self, name: &str, enckey: &SecKey, tx_str: &str) -> Result<Coin>;
    /// Get the current block height
    fn get_current_block_height(&self) -> Result<u64>;

    /// Update the wallet state
    fn update_tx_pending_state(
        &self,
        name: &str,
        enckey: &SecKey,
        tx_id: TxId,
        tx_pending: TransactionPending,
    ) -> Result<()>;
}

/// Interface for a generic wallet for multi-signature transactions
pub trait MultiSigWalletClient: WalletClient {
    /// Creates a 1-of-n schnorr signature.
    fn schnorr_signature(
        &self,
        name: &str,
        enckey: &SecKey,
        message: &H256,
        public_key: &PublicKey,
    ) -> Result<SchnorrSignature>;

    /// Creates a new multi-sig session and returns session-id
    ///
    /// # Arguments
    ///
    /// `name`: Name of wallet
    /// `enckey`: enckey of wallet
    /// `message`: Message to be signed,
    /// `signer_public_keys`: Public keys of all co-signers (including current signer)
    /// `self_public_key`: Public key of current signer
    fn new_multi_sig_session(
        &self,
        name: &str,
        enckey: &SecKey,
        message: H256,
        signer_public_keys: Vec<PublicKey>,
        self_public_key: PublicKey,
    ) -> Result<H256>;

    /// Returns nonce commitment of current signer
    fn nonce_commitment(&self, session_id: &H256, enckey: &SecKey) -> Result<H256>;

    /// Adds a nonce commitment from a public key to session with given id
    fn add_nonce_commitment(
        &self,
        session_id: &H256,
        enckey: &SecKey,
        nonce_commitment: H256,
        public_key: &PublicKey,
    ) -> Result<()>;

    /// Returns nonce of current signer. This function will fail if nonce commitments from all co-signers are not
    /// received.
    fn nonce(&self, session_id: &H256, enckey: &SecKey) -> Result<PublicKey>;

    /// Adds a nonce from a public key to session with given id
    fn add_nonce(
        &self,
        session_id: &H256,
        enckey: &SecKey,
        nonce: &PublicKey,
        public_key: &PublicKey,
    ) -> Result<()>;

    /// Returns partial signature of current signer. This function will fail if nonces from all co-signers are not
    /// received.
    fn partial_signature(&self, session_id: &H256, enckey: &SecKey) -> Result<H256>;

    /// Adds a partial signature from a public key to session with given id
    fn add_partial_signature(
        &self,
        session_id: &H256,
        enckey: &SecKey,
        partial_signature: H256,
        public_key: &PublicKey,
    ) -> Result<()>;

    /// Returns final signature. This function will fail if partial signatures from all co-signers are not received.
    fn signature(&self, session_id: &H256, enckey: &SecKey) -> Result<SchnorrSignature>;

    /// Returns obfuscated transaction by signing given transaction with signature produced by current session id.
    fn transaction(
        &self,
        name: &str,
        session_id: &H256,
        enckey: &SecKey,
        unsigned_transaction: Tx,
    ) -> Result<TxAux>;
}
