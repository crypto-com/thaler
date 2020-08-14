//! Wallet management
mod default_wallet_client;
/// Wallet synchronizer
pub mod syncer;
mod syncer_logic;

pub use default_wallet_client::DefaultWalletClient;

use indexmap::IndexSet;
#[cfg(feature = "experimental")]
use secp256k1::schnorrsig::SchnorrSignature;
use secstr::SecUtf8;
use std::collections::BTreeSet;

use chain_core::common::{Proof, H256};
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::state::account::StakedStateAddress;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
#[cfg(feature = "experimental")]
use chain_core::tx::data::Tx;
use chain_core::tx::data::TxId;
use chain_core::tx::witness::tree::RawXOnlyPubkey;
use chain_core::tx::TxAux;
use client_common::tendermint::types::BroadcastTxResponse;
use client_common::{
    MultiSigAddress, PrivateKey, PrivateKeyAction, PublicKey, Result, SecKey, Transaction,
    TransactionInfo,
};
use serde::{Deserialize, Serialize};

use crate::hd_wallet::HardwareKind;
use crate::service::{SyncState, WalletInfo};
use crate::transaction_builder::{SignedTransferTransaction, UnsignedTransferTransaction};
use crate::types::{AddressType, TransactionChange, TransactionPending, WalletBalance, WalletKind};
use crate::{InputSelectionStrategy, Mnemonic, UnspentTransactions};

/// information needed when create/delete a wallet
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CreateWalletRequest {
    /// the name of the wallet
    pub name: String,
    /// the passphares of the wallet
    pub passphrase: SecUtf8,
}

/// information needed when operate the a wallet
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WalletRequest {
    /// the name of the wallet
    pub name: String,
    /// the auth token of the wallet
    #[serde(alias = "auth_token", alias = "enckey")]
    pub enckey: SecKey,
}

/// Interface for a generic wallet
pub trait WalletClient: Send + Sync {
    /// if the view key included in the transaction, return the Transaction
    fn get_transaction(&self, name: &str, enckey: &SecKey, txid: TxId) -> Result<Transaction>;

    /// update hardware wallet service
    fn update_hw_service(&mut self, hardware_type: HardwareKind) -> Result<()>;

    /// get wallet kind
    fn get_wallet_kind(&self, name: &str, enckey: &SecKey) -> Result<WalletKind>;

    /// Send balance to a transfer address, return the transaction id directly
    fn send_to_address(
        &self,
        name: &str,
        enckey: &SecKey,
        amount: Coin,
        address: ExtendedAddr,
        view_keys: &mut BTreeSet<PublicKey>,
        network_id: u8,
    ) -> Result<TxId>;

    /// send balance to a transfer address, waiting it transaction confirmed then return transaction id
    fn send_to_address_commit(
        &self,
        name: &str,
        enckey: &SecKey,
        amount: Coin,
        address: ExtendedAddr,
        view_keys: &mut BTreeSet<PublicKey>,
        network_id: u8,
    ) -> Result<TxId>;

    /// Retrieves names of all wallets stored
    fn wallets(&self) -> Result<Vec<String>>;

    /// Creates a new wallet with given name, enckey and kind. Returns mnemonics if `wallet_kind` was `HD`.
    /// TODO: separate two apis
    /// new_wallet_basic(name, passphrase)
    /// new_wallet_hd(name, passphrase, mnemonics_word_count)
    fn new_wallet(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        wallet_kind: WalletKind,
        mnemonics_word_count: Option<u32>,
    ) -> Result<(SecKey, Option<Mnemonic>)>;

    /// export wallet info including private key, transfer address, staking address and so on
    fn export_wallet(&self, name: &str, enckey: &SecKey) -> Result<WalletInfo>;

    /// import wallet info to the storage
    fn import_wallet(
        &self,
        name: &str,
        passphrase: &SecUtf8,
        wallet_info: &mut WalletInfo,
    ) -> Result<SecKey>;

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

    /// Remove a wallet
    fn delete_wallet(&self, name: &str, passphrase: &SecUtf8) -> Result<()>;

    /// get auth token client
    fn auth_token(&self, name: &str, passphrase: &SecUtf8) -> Result<SecKey>;

    /// Retrieves view key corresponding to a given wallet
    fn view_key(&self, name: &str, enckey: &SecKey) -> Result<PublicKey>;

    /// Retrieves private view key corresponding to a given wallet
    fn view_key_private(&self, name: &str, enckey: &SecKey) -> Result<PrivateKey>;

    /// Retrieves all public keys corresponding to given wallet
    fn public_keys(&self, name: &str, enckey: &SecKey) -> Result<IndexSet<PublicKey>>;

    /// Retrieves all public keys corresponding to staking addresses stored in given wallet
    fn staking_keys(&self, name: &str, enckey: &SecKey) -> Result<IndexSet<PublicKey>>;

    /// Retrieves all root hashes corresponding to given wallet
    fn root_hashes(&self, name: &str, enckey: &SecKey) -> Result<IndexSet<H256>>;

    /// Returns all staking addresses in current wallet
    fn staking_addresses(
        &self,
        name: &str,
        enckey: &SecKey,
        offset: u64,
        limit: u64,
        reversed: bool,
    ) -> Result<IndexSet<StakedStateAddress>>;

    /// Returns all the multi-sig transfer addresses in current wallet
    fn transfer_addresses(
        &self,
        name: &str,
        enckey: &SecKey,
        offset: u64,
        limit: u64,
        reversed: bool,
    ) -> Result<IndexSet<ExtendedAddr>>;

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

    /// Retrieves private key corresponding to given wallet name
    fn wallet_private_key(
        &self,
        name: &str,
        enckey: &SecKey,
        wallet_kind: WalletKind,
    ) -> Result<Option<PrivateKey>>;

    /// Retrieves sign key(local private key or hardware key) corresponding to given public key
    fn sign_key(
        &self,
        name: &str,
        enckey: &SecKey,
        public_key: &PublicKey,
    ) -> Result<Box<dyn PrivateKeyAction>>;

    /// Retrieves private key corresponding to given public key
    fn private_key(
        &self,
        name: &str,
        enckey: &SecKey,
        public_key: &PublicKey,
    ) -> Result<Option<PrivateKey>>;

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

    /// get the multisig addresses
    fn get_multisig_addresses(&self, name: &str, enckey: &SecKey) -> Result<Vec<MultiSigAddress>>;

    /// Generates inclusion proof for set of public keys in multi-sig address
    fn generate_proof(
        &self,
        name: &str,
        enckey: &SecKey,
        address: &ExtendedAddr,
        public_keys: Vec<PublicKey>,
    ) -> Result<Proof<RawXOnlyPubkey>>;

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

    /// Retrieves transaction change corresponding to given transaction ID
    fn get_transaction_change(
        &self,
        name: &str,
        enckey: &SecKey,
        transaction_id: &TxId,
    ) -> Result<Option<TransactionChange>>;

    /// Retrieves all unspent transactions of wallet
    fn unspent_transactions(&self, name: &str, enckey: &SecKey) -> Result<UnspentTransactions>;

    /// Checks if all the provided transaction inputs are present in unspent transaction for given wallet
    fn has_unspent_transactions(
        &self,
        name: &str,
        enckey: &SecKey,
        inputs: &[TxoPointer],
    ) -> Result<bool>;

    /// Returns `true` or `false` depending if input is unspent or not. `true` if the input is unspent, `false`
    /// otherwise
    fn are_inputs_unspent(
        &self,
        name: &str,
        enckey: &SecKey,
        inputs: Vec<TxoPointer>,
    ) -> Result<Vec<(TxoPointer, bool)>>;

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
    fn export_plain_tx(
        &self,
        name: &str,
        passphras: &SecKey,
        txid: &str,
    ) -> Result<TransactionInfo>;

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

    /// build raw transfer tx
    ///
    fn build_raw_transfer_tx(
        &self,
        name: &str,
        enckey: &SecKey,
        to_address: ExtendedAddr,
        amount: Coin,
        view_keys: Vec<PublicKey>,
        network_id: u8,
    ) -> Result<UnsignedTransferTransaction>;

    /// sign raw transaction transfer
    ///
    fn sign_raw_transfer_tx(
        &self,
        name: &str,
        enckey: &SecKey,
        unsigned_tx: UnsignedTransferTransaction,
    ) -> Result<SignedTransferTransaction>;

    /// send signed transfer transaction_builder
    ///
    fn broadcast_signed_transfer_tx(
        &self,
        name: &str,
        enckey: &SecKey,
        signed_tx: SignedTransferTransaction,
    ) -> Result<TxId>;

    /// Get current sync state of wallet, return genesis one if not exists.
    fn get_sync_state(&self, name: &str) -> Result<SyncState>;

    ///Flush databaase
    fn flush_database(&self) -> Result<()>;
}

#[cfg(feature = "experimental")]
/// Interface for a generic wallet for multi-signature transactions
pub trait MultiSigWalletClient: WalletClient {
    /// Creates a 1-of-n schnorr signature.
    fn schnorr_signature(
        &self,
        name: &str,
        enckey: &SecKey,
        tx: &Transaction,
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
    fn nonce(&self, session_id: &H256, enckey: &SecKey) -> Result<H256>;

    /// Adds a nonce from a public key to session with given id
    fn add_nonce(
        &self,
        session_id: &H256,
        enckey: &SecKey,
        nonce: &H256,
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
