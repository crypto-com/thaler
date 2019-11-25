#![cfg_attr(all(feature = "mesalock_sgx", not(target_env = "sgx")), no_std)]
#![cfg_attr(
    all(target_env = "sgx", target_vendor = "mesalock"),
    feature(rustc_private)
)]
#![deny(missing_docs, unsafe_code, unstable_features)]
//! This crate contains functionality for transaction validation. It's currently tested in chain-abci. (TODO: move tests)
//! WARNING: all validation is pure functions / without DB access => it assumes double-spending BitVec is checked in chain-abci

/// transaction witness verification
pub mod witness;

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

use chain_core::common::Timespec;
use chain_core::init::coin::Coin;
use chain_core::state::account::StakedStateAddress;
use chain_core::state::account::{
    DepositBondTx, StakedState, UnbondTx, UnjailTx, WithdrawUnbondedTx,
};
use chain_core::state::tendermint::{TendermintValidatorAddress, TendermintVotePower};
use chain_core::state::validator::NodeJoinRequestTx;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::Tx;
use chain_core::tx::data::TxId;
use chain_core::tx::fee::Fee;
use chain_core::tx::witness::TxWitness;
use chain_core::tx::TransactionId;
pub use chain_core::tx::TxWithOutputs;
pub use chain_core::ChainInfo;
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::convert::From;
use std::fmt;
use std::prelude::v1::Vec;
use witness::verify_tx_address;

/// All possible TX validation errors
#[derive(Debug, Encode, Decode)]
pub enum Error {
    /// chain hex ID does not match
    WrongChainHexId,
    /// transaction has no inputs
    NoInputs,
    /// transaction has no outputs
    NoOutputs,
    /// transaction has duplicated inputs
    DuplicateInputs,
    /// output with no credited value
    ZeroCoin,
    /// input or output summation error
    /// FIXME: InvalidSum(CoinError),
    InvalidSum,
    /// transaction has more witnesses than inputs
    UnexpectedWitnesses,
    /// transaction has more inputs than witnesses
    MissingWitnesses,
    /// transaction spends an invalid input
    InvalidInput,
    /// transaction spends an input that was already spent
    InputSpent,
    /// transaction input output coin (plus fee) sums don't match
    InputOutputDoNotMatch,
    /// output transaction is in timelock that hasn't passed
    OutputInTimelock,
    /// cryptographic library error
    /// FIXME: EcdsaCrypto(secp256k1::Error),
    EcdsaCrypto,
    /// DB read error
    /// FIXME: IoError(io::Error),
    IoError,
    /// enclave error or invalid TX,
    EnclaveRejected,
    /// staked state not found
    AccountNotFound,
    /// staked state not unbounded
    AccountNotUnbonded,
    /// outputs created out of a staked state are not time-locked to unbonding period
    AccountWithdrawOutputNotLocked,
    /// mismatch staked address from witness
    MismatchAccountAddress,
    /// incorrect nonce supplied in staked state operation
    AccountIncorrectNonce,
    /// Account is jailed
    AccountJailed,
    /// Account is not jailed
    AccountNotJailed,
    /// Bonded amount < minimal required stake
    NotEnoughStake,
    /// Validator data already present in node state
    DuplicateValidator,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::Error::*;
        match self {
            WrongChainHexId => write!(f, "chain hex ID does not match"),
            DuplicateInputs => write!(f, "duplicated inputs"),
            UnexpectedWitnesses => write!(f, "transaction has more witnesses than inputs"),
            MissingWitnesses => write!(f, "transaction has more inputs than witnesses"),
            NoInputs => write!(f, "transaction has no inputs"),
            NoOutputs => write!(f, "transaction has no outputs"),
            ZeroCoin => write!(f, "output with no credited value"),
            // FIXME: InvalidSum(ref err) => write!(f, "input or output sum error: {}", err),
            InvalidSum => write!(
                f,
                "input or output sum error (summation more than the total supply)"
            ),
            InvalidInput => write!(f, "transaction spends an invalid input"),
            InputSpent => write!(f, "transaction spends an input that was already spent"),
            InputOutputDoNotMatch => write!(
                f,
                "transaction input output coin (plus fee) sums don't match"
            ),
            OutputInTimelock => write!(f, "output transaction is in timelock"),
            // FIXME: EcdsaCrypto(ref err) => write!(f, "ECDSA crypto error: {}", err),
            EcdsaCrypto => write!(
                f,
                "cryptographic error (signature verification or public key recovery failed)"
            ),
            // FIXME: IoError(ref err) => write!(f, "IO error: {}", err),
            IoError => write!(f, "database lookup error"),
            EnclaveRejected => write!(f, "enclave error or invalid TX"),
            AccountNotFound => write!(f, "account not found"),
            AccountNotUnbonded => write!(f, "account not unbonded for withdrawal"),
            AccountWithdrawOutputNotLocked => write!(
                f,
                "account withdrawal outputs not time-locked to unbonded_from"
            ),
            AccountIncorrectNonce => write!(f, "incorrect transaction count for account operation"),
            MismatchAccountAddress => write!(f, "mismatch account address"),
            AccountJailed => write!(f, "account is jailed"),
            AccountNotJailed => write!(f, "account is not jailed"),
            NotEnoughStake => write!(f, "staked state bonded amount is less than the minimal required stake"),
            DuplicateValidator => write!(f, "council node with the same staked state address or validator public key already added"),
        }
    }
}

fn check_attributes(tx_chain_hex_id: u8, extra_info: &ChainInfo) -> Result<(), Error> {
    // TODO: check other attributes?
    // check that chain IDs match
    if extra_info.chain_hex_id != tx_chain_hex_id {
        return Err(Error::WrongChainHexId);
    }
    Ok(())
}

/// Applies basic checks on transaction inputs
pub fn check_inputs_basic(inputs: &[TxoPointer], witness: &TxWitness) -> Result<(), Error> {
    // check that there are inputs
    if inputs.is_empty() {
        return Err(Error::NoInputs);
    }

    // check that there are no duplicate inputs
    let mut inputs_s = BTreeSet::new();
    if !inputs.iter().all(|x| inputs_s.insert(x)) {
        return Err(Error::DuplicateInputs);
    }

    // verify transaction witnesses
    if inputs.len() < witness.len() {
        return Err(Error::UnexpectedWitnesses);
    }

    if inputs.len() > witness.len() {
        return Err(Error::MissingWitnesses);
    }

    Ok(())
}

fn check_inputs(
    main_txid: &TxId,
    inputs: &[TxoPointer],
    witness: &TxWitness,
    extra_info: &ChainInfo,
    transaction_inputs: Vec<TxWithOutputs>,
) -> Result<Coin, Error> {
    let mut incoins = Coin::zero();
    // verify that txids of inputs correspond to the owner/signer
    // and it'd check they are not spent
    // TODO: zip3 / itertools?
    for (txin, (tx, in_witness)) in inputs
        .iter()
        .zip(transaction_inputs.iter().zip(witness.iter()))
    {
        if txin.id != tx.id() {
            return Err(Error::InvalidInput);
        }
        let input_index = txin.index as usize;
        let outputs = tx.outputs();
        if input_index >= outputs.len() {
            return Err(Error::InvalidInput);
        }
        let txout = &outputs[input_index];
        if let Some(valid_from) = &txout.valid_from {
            if *valid_from > extra_info.previous_block_time {
                return Err(Error::OutputInTimelock);
            }
        }
        let wv = verify_tx_address(&in_witness, main_txid, &txout.address);
        if let Err(_e) = wv {
            return Err(Error::EcdsaCrypto); // FIXME: Err(Error::EcdsaCrypto(e));
        }
        let sum = incoins + txout.value;
        if let Err(_e) = sum {
            return Err(Error::InvalidSum); // FIXME: Err(Error::InvalidSum(e));
        } else {
            incoins = sum.unwrap();
        }
    }
    Ok(incoins)
}

/// Applies basic checks on transaction outputs
pub fn check_outputs_basic(outputs: &[TxOut]) -> Result<(), Error> {
    // check that there are outputs
    if outputs.is_empty() {
        return Err(Error::NoOutputs);
    }

    // check that all outputs have a non-zero amount
    if !outputs.iter().all(|x| x.value > Coin::zero()) {
        return Err(Error::ZeroCoin);
    }

    // Note: we don't need to check against MAX_COIN because Coin's
    // constructor should already do it.

    // TODO: check address attributes?
    Ok(())
}

fn check_input_output_sums(
    incoins: Coin,
    outcoins: Coin,
    extra_info: &ChainInfo,
) -> Result<Fee, Error> {
    // check sum(input amounts) >= sum(output amounts) + minimum fee
    let min_fee: Coin = extra_info.min_fee_computed.to_coin();
    let total_outsum = outcoins + min_fee;
    if let Err(_coin_err) = total_outsum {
        return Err(Error::InvalidSum); // FIXME: Err(Error::InvalidSum(coin_err));
    }
    if incoins < total_outsum.unwrap() {
        return Err(Error::InputOutputDoNotMatch);
    }
    let fee_paid = (incoins - outcoins).unwrap();
    Ok(Fee::new(fee_paid))
}

/// checks TransferTx -- TODO: this will be moved to an enclave
/// WARNING: it assumes double-spending BitVec of inputs is checked in chain-abci
pub fn verify_transfer(
    maintx: &Tx,
    witness: &TxWitness,
    extra_info: ChainInfo,
    transaction_inputs: Vec<TxWithOutputs>,
) -> Result<Fee, Error> {
    check_attributes(maintx.attributes.chain_hex_id, &extra_info)?;
    check_inputs_basic(&maintx.inputs, witness)?;
    check_outputs_basic(&maintx.outputs)?;
    let incoins = check_inputs(
        &maintx.id(),
        &maintx.inputs,
        witness,
        &extra_info,
        transaction_inputs,
    )?;
    let outcoins = maintx.get_output_total();
    if let Err(_coin_err) = outcoins {
        return Err(Error::InvalidSum); // FIXME: Err(Error::InvalidSum(coin_err));
    }
    check_input_output_sums(incoins, outcoins.unwrap(), &extra_info)
}

/// checks depositing to a staked state -- TODO: this will be moved to an enclave
/// WARNING: it assumes double-spending BitVec of inputs is checked in chain-abci
pub fn verify_bonded_deposit_core(
    maintx: &DepositBondTx,
    witness: &TxWitness,
    extra_info: ChainInfo,
    transaction_inputs: Vec<TxWithOutputs>,
) -> Result<Coin, Error> {
    check_attributes(maintx.attributes.chain_hex_id, &extra_info)?;
    check_inputs_basic(&maintx.inputs, witness)?;
    let incoins = check_inputs(
        &maintx.id(),
        &maintx.inputs,
        witness,
        &extra_info,
        transaction_inputs,
    )?;
    if incoins <= extra_info.min_fee_computed.to_coin() {
        return Err(Error::InputOutputDoNotMatch);
    }
    Ok(incoins)
}

/// checks depositing to a staked state
/// WARNING: it assumes double-spending BitVec of inputs is checked in chain-abci
/// TODO: move this to chain-abci? (the account creation / update)
pub fn verify_bonded_deposit(
    maintx: &DepositBondTx,
    witness: &TxWitness,
    extra_info: ChainInfo,
    transaction_inputs: Vec<TxWithOutputs>,
    maccount: Option<StakedState>,
) -> Result<(Fee, Option<StakedState>), Error> {
    if let Some(ref account) = maccount {
        verify_unjailed(account)?;
    }

    let incoins = verify_bonded_deposit_core(maintx, witness, extra_info, transaction_inputs)?;
    let deposit_amount = (incoins - extra_info.min_fee_computed.to_coin()).expect("init");
    let account = match maccount {
        Some(mut a) => {
            a.deposit(deposit_amount);
            Some(a)
        }
        None => Some(StakedState::new_init_bonded(
            deposit_amount,
            extra_info.previous_block_time,
            maintx.to_staked_account,
            None,
        )),
    };
    Ok((extra_info.min_fee_computed, account))
}

/// checks moving some amount from bonded to unbonded in staked states
/// NOTE: witness is assumed to be checked in chain-abci
pub fn verify_unbonding(
    maintx: &UnbondTx,
    extra_info: ChainInfo,
    mut account: StakedState,
) -> Result<(Fee, Option<StakedState>), Error> {
    verify_unjailed(&account)?;
    check_attributes(maintx.attributes.chain_hex_id, &extra_info)?;

    if maintx.from_staked_account != account.address {
        return Err(Error::MismatchAccountAddress);
    }
    // checks that account transaction count matches to the one in transaction
    if maintx.nonce != account.nonce {
        return Err(Error::AccountIncorrectNonce);
    }
    // check that a non-zero amount is being unbound
    if maintx.value == Coin::zero() {
        return Err(Error::ZeroCoin);
    }
    check_input_output_sums(account.bonded, maintx.value, &extra_info)?;
    account.unbond(
        maintx.value,
        extra_info.min_fee_computed.to_coin(),
        extra_info.previous_block_time + Timespec::from(extra_info.unbonding_period),
    );
    // only pay the minimal fee from the bonded amount if correct; the rest remains in bonded
    Ok((extra_info.min_fee_computed, Some(account)))
}

/// checks wihdrawing from a staked state -- TODO: this will be moved to an enclave
/// NOTE: witness is assumed to be checked in chain-abci
pub fn verify_unbonded_withdraw_core(
    maintx: &WithdrawUnbondedTx,
    extra_info: ChainInfo,
    account: &StakedState,
) -> Result<Fee, Error> {
    verify_unjailed(account)?;

    check_attributes(maintx.attributes.chain_hex_id, &extra_info)?;
    check_outputs_basic(&maintx.outputs)?;
    // checks that account transaction count matches to the one in transaction
    if maintx.nonce != account.nonce {
        return Err(Error::AccountIncorrectNonce);
    }
    // checks that account can withdraw to outputs
    if account.unbonded_from > extra_info.previous_block_time {
        return Err(Error::AccountNotUnbonded);
    }
    // checks that there is something to wihdraw
    if account.unbonded == Coin::zero() {
        return Err(Error::ZeroCoin);
    }
    // checks that outputs are locked to the unbonded time
    if !maintx
        .outputs
        .iter()
        .all(|x| x.valid_from == Some(account.unbonded_from))
    {
        return Err(Error::AccountWithdrawOutputNotLocked);
    }
    let outcoins = maintx.get_output_total();
    if let Err(_coin_err) = outcoins {
        return Err(Error::InvalidSum); // FIXME: Err(Error::InvalidSum(coin_err));
    }
    check_input_output_sums(account.unbonded, outcoins.unwrap(), &extra_info)
}

/// checks wihdrawing from a staked state
/// NOTE: witness is assumed to be checked in chain-abci
/// TODO: move this to chain-abci? (the account update)
pub fn verify_unbonded_withdraw(
    maintx: &WithdrawUnbondedTx,
    extra_info: ChainInfo,
    mut account: StakedState,
) -> Result<(Fee, Option<StakedState>), Error> {
    let fee = verify_unbonded_withdraw_core(maintx, extra_info, &account)?;
    account.withdraw();
    Ok((fee, Some(account)))
}

/// Verifies if an account can be unjailed
pub fn verify_unjailing(
    maintx: &UnjailTx,
    extra_info: ChainInfo,
    mut account: StakedState,
) -> Result<(Fee, Option<StakedState>), Error> {
    check_attributes(maintx.attributes.chain_hex_id, &extra_info)?;

    // checks that account transaction count matches to the one in transaction
    if maintx.nonce != account.nonce {
        return Err(Error::AccountIncorrectNonce);
    }

    // checks that the address in unjail transaction is same as that of account recovered from witness
    if maintx.address != account.address {
        return Err(Error::MismatchAccountAddress);
    }

    match account.jailed_until() {
        None => Err(Error::AccountNotJailed),
        Some(jailed_until) => {
            if jailed_until > extra_info.previous_block_time {
                Err(Error::AccountJailed)
            } else {
                account.unjail();
                Ok((Fee::new(Coin::zero()), Some(account))) // Zero fee for unjail transaction
            }
        }
    }
}

/// Verifies if the account is unjailed
pub fn verify_unjailed(account: &StakedState) -> Result<(), Error> {
    if account.is_jailed() {
        Err(Error::AccountJailed)
    } else {
        Ok(())
    }
}

/// information needed for NodeJoinRequestTx verification
pub struct NodeInfo<'a> {
    /// minimal required stake
    pub minimal_stake: Coin,
    /// current validator addresses
    pub tendermint_validator_addresses:
        &'a BTreeMap<TendermintValidatorAddress, StakedStateAddress>,
    /// current validator staking addresses
    pub validator_voting_power: &'a BTreeMap<StakedStateAddress, TendermintVotePower>,
}

/// Verifies if a new council node can be added
pub fn verify_node_join(
    maintx: &NodeJoinRequestTx,
    extra_info: ChainInfo,
    node_info: NodeInfo,
    mut account: StakedState,
) -> Result<(Fee, Option<StakedState>), Error> {
    verify_unjailed(&account)?;
    check_attributes(maintx.attributes.chain_hex_id, &extra_info)?;

    // checks that staked state transaction count matches to the one in transaction
    if maintx.nonce != account.nonce {
        return Err(Error::AccountIncorrectNonce);
    }

    // checks that the address in unjail transaction is same as that of staked state recovered from witness
    if maintx.address != account.address {
        return Err(Error::MismatchAccountAddress);
    }

    // checks that the bonded amount >= minimal required stake
    if account.bonded < node_info.minimal_stake {
        return Err(Error::NotEnoughStake);
    }
    let validator_address = TendermintValidatorAddress::from(&maintx.node_meta.consensus_pubkey);
    // checks that validator hasn't joined yet
    if node_info
        .validator_voting_power
        .contains_key(&maintx.address)
        || node_info
            .tendermint_validator_addresses
            .contains_key(&validator_address)
    {
        return Err(Error::DuplicateValidator);
    }

    account.join_node(maintx.node_meta.clone());
    Ok((Fee::new(Coin::zero()), Some(account))) // Zero fee for node join request
}
