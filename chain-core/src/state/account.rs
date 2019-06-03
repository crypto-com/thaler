use crate::common::{hash256, Timespec, HASH_SIZE_256};
use crate::init::address::RedeemAddress;
use crate::init::coin::Coin;
use crate::init::coin::{sum_coins, CoinError};
use crate::tx::data::attribute::TxAttributes;
use crate::tx::data::input::TxoPointer;
use crate::tx::data::output::TxOut;
use crate::tx::data::TxId;
use crate::tx::witness::{tree::RawSignature, EcdsaSignature};
use crate::tx::TransactionId;
use blake2::Blake2s;
use parity_codec::{Decode, Encode, Input, Output};
use secp256k1::{Message, Secp256k1};
use secp256k1::{RecoverableSignature, RecoveryId};
use serde::{Deserialize, Serialize};
use std::fmt;

/// reference counter in the sparse patricia merkle tree/trie
pub type Count = u64;

/// account state update counter
pub type Nonce = u64;

/// represents the account state (involved in staking)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct Account {
    pub nonce: Nonce,
    pub bonded: Coin,
    pub unbonded: Coin,
    pub unbonded_from: Timespec,
    pub address: RedeemAddress,
    // TODO: slashing + jailing
}

/// the tree used in account storage db has a hardcoded 32-byte keys,
/// this computes a key as blake2s(account.address) where
/// the account address itself is ETH-style address (20 bytes from keccak hash of public key)
pub fn to_account_key(address: &RedeemAddress) -> [u8; HASH_SIZE_256] {
    hash256::<Blake2s>(address)
}

impl Default for Account {
    fn default() -> Self {
        Account::new(0, Coin::zero(), Coin::zero(), 0, RedeemAddress::default())
    }
}

impl Account {
    /// creates a new account with given parameters
    pub fn new(
        nonce: Nonce,
        bonded: Coin,
        unbonded: Coin,
        unbonded_from: Timespec,
        address: RedeemAddress,
    ) -> Self {
        Account {
            nonce,
            bonded,
            unbonded,
            unbonded_from,
            address,
        }
    }

    /// creates a account at "genesis" (amount is either all bonded or unbonded depending on `bonded` argument)
    pub fn new_init(
        amount: Coin,
        genesis_time: Timespec,
        address: RedeemAddress,
        bonded: bool,
    ) -> Self {
        if bonded {
            Account {
                nonce: 0,
                bonded: amount,
                unbonded: Coin::zero(),
                unbonded_from: genesis_time,
                address,
            }
        } else {
            Account {
                nonce: 0,
                bonded: Coin::zero(),
                unbonded: amount,
                unbonded_from: genesis_time,
                address,
            }
        }
    }

    /// in-place update after depositing a stake
    pub fn deposit(&mut self, amount: Coin) {
        self.nonce += 1;
        self.bonded = (self.bonded + amount).expect("should not be over the max supply");
    }

    /// in-place update after unbonding a bonded stake
    pub fn unbond(&mut self, amount: Coin, fee: Coin, unbonded_from: Timespec) {
        self.nonce += 1;
        self.unbonded_from = unbonded_from;
        self.bonded = (self.bonded - amount)
            .and_then(|x| x - fee)
            .expect("should not go below zero");
        self.unbonded = (self.unbonded + amount).expect("should not be over the max supply");
    }

    /// in-place update after withdrawing unbonded stake
    pub fn withdraw(&mut self) {
        self.nonce += 1;
        self.bonded = Coin::zero();
    }

    /// the tree used in account storage db has a hardcoded 32-byte keys,
    /// this computes a key as blake2s(account.address) where
    /// the account address itself is ETH-style address (20 bytes from keccak hash of public key)
    pub fn key(&self) -> [u8; HASH_SIZE_256] {
        to_account_key(&self.address)
    }
}

/// attributes in account-related transactions
#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct AccountOpAttributes {
    pub chain_hex_id: u8,
    // TODO: Other attributes?
}

impl AccountOpAttributes {
    pub fn new(chain_hex_id: u8) -> Self {
        AccountOpAttributes { chain_hex_id }
    }
}

impl Encode for AccountOpAttributes {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        dest.push_byte(0);
        dest.push_byte(1);
        dest.push_byte(self.chain_hex_id);
    }
}

impl Decode for AccountOpAttributes {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        let tag = input.read_byte()?;
        let constructor_len = input.read_byte()?;
        match (tag, constructor_len) {
            (0, 1) => {
                let chain_hex_id: u8 = input.read_byte()?;
                Some(AccountOpAttributes { chain_hex_id })
            }
            _ => None,
        }
    }
}

/// takes UTXOs inputs, deposits them in the specified account's bonded amount - fee
/// (updates account's bonded + nonce)
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct DepositBondTx {
    pub inputs: Vec<TxoPointer>,
    pub to_account: RedeemAddress,
    pub attributes: AccountOpAttributes,
}

impl TransactionId for DepositBondTx {}

impl DepositBondTx {
    pub fn new(
        inputs: Vec<TxoPointer>,
        to_account: RedeemAddress,
        attributes: AccountOpAttributes,
    ) -> Self {
        DepositBondTx {
            inputs,
            to_account,
            attributes,
        }
    }
}

impl fmt::Display for DepositBondTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for input in self.inputs.iter() {
            writeln!(f, "-> {}", input)?;
        }
        writeln!(f, "   {} (bonded) ->", self.to_account)?;
        write!(f, "")
    }
}

/// updates the account (TODO: implicit from the witness?) by moving some of the bonded amount - fee into unbonded,
/// and setting the unbonded_from to last_block_time+min_unbonding_time (network parameter)
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct UnbondTx {
    pub value: Coin,
    pub nonce: Nonce,
    pub attributes: AccountOpAttributes,
}

impl TransactionId for UnbondTx {}

impl UnbondTx {
    pub fn new(value: Coin, nonce: Nonce, attributes: AccountOpAttributes) -> Self {
        UnbondTx {
            value,
            nonce,
            attributes,
        }
    }
}

impl fmt::Display for UnbondTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "unbonded: {} (nonce: {})", self.value, self.nonce)?;
        write!(f, "")
    }
}

/// takes the account (TODO: implicit from the witness?) and creates UTXOs
/// (update's account's unbonded + nonce)
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct WithdrawUnbondedTx {
    pub nonce: Nonce,
    pub outputs: Vec<TxOut>,
    pub attributes: TxAttributes,
}

impl TransactionId for WithdrawUnbondedTx {}

impl WithdrawUnbondedTx {
    pub fn new(nonce: Nonce, outputs: Vec<TxOut>, attributes: TxAttributes) -> Self {
        WithdrawUnbondedTx {
            nonce,
            outputs,
            attributes,
        }
    }
}

impl WithdrawUnbondedTx {
    /// returns the total transaction output amount (sum of all output amounts)
    pub fn get_output_total(&self) -> Result<Coin, CoinError> {
        sum_coins(self.outputs.iter().map(|x| x.value))
    }
}

impl fmt::Display for WithdrawUnbondedTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "-> (unbonded) (nonce: {})", self.nonce)?;
        for output in self.outputs.iter() {
            writeln!(f, "   {} ->", output)?;
        }
        write!(f, "")
    }
}

/// A witness for account operations
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountOpWitness(EcdsaSignature);

impl AccountOpWitness {
    pub fn new(sig: EcdsaSignature) -> Self {
        AccountOpWitness(sig)
    }

    /// verify the signature against the given transation `Tx`
    /// and recovers the address from it
    ///
    pub fn verify_tx_recover_address(
        &self,
        txid: &TxId,
    ) -> Result<RedeemAddress, secp256k1::Error> {
        let secp = Secp256k1::verification_only();
        let message = Message::from_slice(txid)?;
        let pk = secp.recover(&message, &self.0)?;
        secp.verify(&message, &self.0.to_standard(), &pk)?;
        Ok(RedeemAddress::from(&pk))
    }
}

impl Encode for AccountOpWitness {
    fn encode_to<W: Output>(&self, dest: &mut W) {
        let (recovery_id, serialized_sig) = self.0.serialize_compact();
        // recovery_id is one of 0 | 1 | 2 | 3
        let rid = recovery_id.to_i32() as u8;
        dest.push_byte(rid);
        serialized_sig.encode_to(dest);
    }
}

impl Decode for AccountOpWitness {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        let rid: u8 = input.read_byte()?;
        let raw_sig = RawSignature::decode(input)?;
        let recovery_id = RecoveryId::from_i32(i32::from(rid)).ok()?;
        let sig = RecoverableSignature::from_compact(&raw_sig, recovery_id).ok()?;
        Some(AccountOpWitness(sig))
    }
}
