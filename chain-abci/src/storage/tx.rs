use crate::storage::account::AccountStorage;
use crate::storage::account::AccountWrapper;
use crate::storage::{COL_BODIES, COL_TX_META};
use bit_vec::BitVec;
use chain_core::common::Timespec;
use chain_core::init::coin::{Coin, CoinError};
use chain_core::state::account::{
    to_account_key, Account, AccountAddress, AccountOpWitness, DepositBondTx, UnbondTx,
    WithdrawUnbondedTx,
};
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::TxId;
use chain_core::tx::fee::Fee;
use chain_core::tx::witness::TxWitness;
use chain_core::tx::TransactionId;
use chain_core::tx::{data::Tx, TxAux};
use kvdb::KeyValueDB;
use parity_codec::{Decode, Encode};
use secp256k1;
use starling::constants::KEY_LEN;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::{fmt, io};

pub type StarlingFixedKey = [u8; KEY_LEN];

/// All possible TX validation errors
#[derive(Debug)]
pub enum Error {
    WrongChainHexId,
    NoInputs,
    NoOutputs,
    DuplicateInputs,
    ZeroCoin,
    InvalidSum(CoinError),
    UnexpectedWitnesses,
    MissingWitnesses,
    InvalidInput,
    InputSpent,
    InputOutputDoNotMatch,
    OutputInTimelock,
    EcdsaCrypto(secp256k1::Error),
    IoError(io::Error),
    AccountLookupError(starling::traits::Exception),
    AccountNotFound,
    AccountNotUnbonded,
    AccountWithdrawOutputNotLocked,
    AccountIncorrectNonce,
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
            InvalidSum(ref err) => write!(f, "input or output sum error: {}", err),
            InvalidInput => write!(f, "transaction spends an invalid input"),
            InputSpent => write!(f, "transaction spends an input that was already spent"),
            InputOutputDoNotMatch => write!(
                f,
                "transaction input output coin (plus fee) sums don't match"
            ),
            OutputInTimelock => write!(f, "output transaction is in timelock"),
            EcdsaCrypto(ref err) => write!(f, "ECDSA crypto error: {}", err),
            IoError(ref err) => write!(f, "IO error: {}", err),
            AccountLookupError(ref err) => write!(f, "Account lookup error: {}", err),
            AccountNotFound => write!(f, "account not found"),
            AccountNotUnbonded => write!(f, "account not unbonded for withdrawal"),
            AccountWithdrawOutputNotLocked => write!(
                f,
                "account withdrawal outputs not time-locked to unbonded_from"
            ),
            AccountIncorrectNonce => write!(f, "incorrect transaction count for account operation"),
        }
    }
}

/// External information needed for TX validation
#[derive(Clone, Copy)]
pub struct ChainInfo {
    pub min_fee_computed: Fee,
    pub chain_hex_id: u8,
    pub previous_block_time: Timespec,
    pub last_account_root_hash: StarlingFixedKey,
    pub unbonding_period: u32,
}

fn check_attributes(tx_chain_hex_id: u8, extra_info: &ChainInfo) -> Result<(), Error> {
    // TODO: check other attributes?
    // check that chain IDs match
    if extra_info.chain_hex_id != tx_chain_hex_id {
        return Err(Error::WrongChainHexId);
    }
    Ok(())
}

fn check_inputs_basic(inputs: &[TxoPointer], witness: &TxWitness) -> Result<(), Error> {
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

#[derive(Encode, Decode)]
pub enum TxWithOutputs {
    Transfer(Tx),
    StakeWithdraw(WithdrawUnbondedTx),
}

impl TxWithOutputs {
    pub fn outputs(&self) -> &[TxOut] {
        match self {
            TxWithOutputs::Transfer(tx) => &tx.outputs,
            TxWithOutputs::StakeWithdraw(tx) => &tx.outputs,
        }
    }
}

fn check_inputs_lookup(
    main_txid: &TxId,
    inputs: &[TxoPointer],
    witness: &TxWitness,
    extra_info: &ChainInfo,
    db: Arc<dyn KeyValueDB>,
) -> Result<Coin, Error> {
    let mut incoins = Coin::zero();
    // verify that txids of inputs correspond to the owner/signer
    // and it'd check they are not spent
    for (txin, in_witness) in inputs.iter().zip(witness.iter()) {
        let txo = db.get(COL_TX_META, &txin.id[..]);
        match txo {
            Ok(Some(v)) => {
                let input_index = txin.index as usize;
                let bv = BitVec::from_bytes(&v).get(input_index);
                if bv.is_none() {
                    return Err(Error::InvalidInput);
                }
                if bv.unwrap() {
                    return Err(Error::InputSpent);
                }
                let txdata = db.get(COL_BODIES, &txin.id[..]).unwrap().unwrap().to_vec();
                // only TxWithOutputs should have an entry in COL_TX_META
                let tx = TxWithOutputs::decode(&mut txdata.as_slice()).unwrap();
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

                let wv = in_witness.verify_tx_address(main_txid, &txout.address);
                if let Err(e) = wv {
                    return Err(Error::EcdsaCrypto(e));
                }
                let sum = incoins + txout.value;
                if let Err(e) = sum {
                    return Err(Error::InvalidSum(e));
                } else {
                    incoins = sum.unwrap();
                }
            }
            Ok(None) => {
                return Err(Error::InvalidInput);
            }
            Err(e) => {
                return Err(Error::IoError(e));
            }
        }
    }
    Ok(incoins)
}

fn check_outputs_basic(outputs: &[TxOut]) -> Result<(), Error> {
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
    if let Err(coin_err) = total_outsum {
        return Err(Error::InvalidSum(coin_err));
    }
    if incoins < total_outsum.unwrap() {
        return Err(Error::InputOutputDoNotMatch);
    }
    let fee_paid = (incoins - outcoins).unwrap();
    Ok(Fee::new(fee_paid))
}

/// checks TransferTx -- TODO: this will be moved to an enclave
/// TODO: when more address/sigs available, check Redeem addresses are never in outputs?
fn verify_transfer(
    maintx: &Tx,
    witness: &TxWitness,
    extra_info: ChainInfo,
    db: Arc<dyn KeyValueDB>,
) -> Result<Fee, Error> {
    check_attributes(maintx.attributes.chain_hex_id, &extra_info)?;
    check_inputs_basic(&maintx.inputs, witness)?;
    check_outputs_basic(&maintx.outputs)?;
    let incoins = check_inputs_lookup(&maintx.id(), &maintx.inputs, witness, &extra_info, db)?;
    let outcoins = maintx.get_output_total();
    if let Err(coin_err) = outcoins {
        return Err(Error::InvalidSum(coin_err));
    }
    check_input_output_sums(incoins, outcoins.unwrap(), &extra_info)
}

fn verify_bonded_deposit(
    maintx: &DepositBondTx,
    witness: &TxWitness,
    extra_info: ChainInfo,
    db: Arc<dyn KeyValueDB>,
    accounts: &AccountStorage,
) -> Result<(Fee, Option<Account>), Error> {
    check_attributes(maintx.attributes.chain_hex_id, &extra_info)?;
    check_inputs_basic(&maintx.inputs, witness)?;
    let incoins = check_inputs_lookup(&maintx.id(), &maintx.inputs, witness, &extra_info, db)?;
    if incoins <= extra_info.min_fee_computed.to_coin() {
        return Err(Error::InputOutputDoNotMatch);
    }
    let deposit_amount = (incoins - extra_info.min_fee_computed.to_coin()).expect("init");
    // TODO: check account not jailed etc.?
    let maccount = get_account(
        &maintx.to_account,
        &extra_info.last_account_root_hash,
        accounts,
    );
    let account = match maccount {
        Ok(mut a) => {
            a.deposit(deposit_amount);
            Ok(a)
        }
        Err(Error::AccountNotFound) => Ok(Account::new_init(
            deposit_amount,
            extra_info.previous_block_time,
            maintx.to_account,
            true,
        )),
        e => e,
    };
    Ok((extra_info.min_fee_computed, Some(account?)))
}

/// checks that the account can be retrieved from the trie storage
pub fn get_account(
    account_address: &AccountAddress,
    last_root: &StarlingFixedKey,
    accounts: &AccountStorage,
) -> Result<Account, Error> {
    let account_key = to_account_key(account_address);
    let items = accounts.get(last_root, &mut [&account_key]);
    if let Err(e) = items {
        return Err(Error::AccountLookupError(e));
    }
    let account = items.unwrap()[&account_key].clone();
    match account {
        None => Err(Error::AccountNotFound),
        Some(AccountWrapper(a)) => Ok(a),
    }
}

fn verify_unbonding(
    maintx: &UnbondTx,
    witness: &AccountOpWitness,
    extra_info: ChainInfo,
    accounts: &AccountStorage,
) -> Result<(Fee, Option<Account>), Error> {
    check_attributes(maintx.attributes.chain_hex_id, &extra_info)?;
    let account_address = witness.verify_tx_recover_address(&maintx.id());
    if let Err(e) = account_address {
        return Err(Error::EcdsaCrypto(e));
    }
    let mut account = get_account(
        &account_address.unwrap(),
        &extra_info.last_account_root_hash,
        accounts,
    )?;
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
        extra_info.previous_block_time + i64::from(extra_info.unbonding_period),
    );
    // only pay the minimal fee from the bonded amount if correct; the rest remains in bonded
    Ok((extra_info.min_fee_computed, Some(account)))
}

fn verify_unbonded_withdraw(
    maintx: &WithdrawUnbondedTx,
    witness: &AccountOpWitness,
    extra_info: ChainInfo,
    accounts: &AccountStorage,
) -> Result<(Fee, Option<Account>), Error> {
    check_attributes(maintx.attributes.chain_hex_id, &extra_info)?;
    check_outputs_basic(&maintx.outputs)?;
    let account_address = witness.verify_tx_recover_address(&maintx.id());
    if let Err(e) = account_address {
        return Err(Error::EcdsaCrypto(e));
    }
    let mut account = get_account(
        &account_address.unwrap(),
        &extra_info.last_account_root_hash,
        accounts,
    )?;
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
    if let Err(coin_err) = outcoins {
        return Err(Error::InvalidSum(coin_err));
    }
    let fee = check_input_output_sums(account.unbonded, outcoins.unwrap(), &extra_info)?;
    account.withdraw();
    Ok((fee, Some(account)))
}

/// Checks TX against the current DB and returns an `Error` if something fails.
/// If OK, returns the paid fee.
pub fn verify(
    txaux: &TxAux,
    extra_info: ChainInfo,
    db: Arc<dyn KeyValueDB>,
    accounts: &AccountStorage,
) -> Result<(Fee, Option<Account>), Error> {
    let paid_fee = match txaux {
        TxAux::TransferTx(maintx, witness) => {
            (verify_transfer(maintx, witness, extra_info, db)?, None)
        }
        TxAux::DepositStakeTx(maintx, witness) => {
            verify_bonded_deposit(maintx, witness, extra_info, db, accounts)?
        }
        TxAux::UnbondStakeTx(maintx, witness) => {
            verify_unbonding(maintx, witness, extra_info, accounts)?
        }
        TxAux::WithdrawUnbondedStakeTx(maintx, witness) => {
            verify_unbonded_withdraw(maintx, witness, extra_info, accounts)?
        }
    };
    Ok(paid_fee)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::storage::{Storage, COL_TX_META, NUM_COLUMNS};
    use chain_core::init::address::RedeemAddress;
    use chain_core::state::account::AccountOpAttributes;
    use chain_core::tx::data::{
        address::ExtendedAddr, attribute::TxAttributes, input::TxoPointer, output::TxOut,
    };
    use chain_core::tx::fee::FeeAlgorithm;
    use chain_core::tx::fee::{LinearFee, Milli};
    use chain_core::tx::witness::{TxInWitness, TxWitness};
    use kvdb_memorydb::create;
    use parity_codec::Encode;
    use secp256k1::{key::PublicKey, key::SecretKey, Message, Secp256k1, Signing};
    use std::fmt::Debug;
    use std::mem;

    pub fn get_tx_witness<C: Signing>(
        secp: Secp256k1<C>,
        txid: &TxId,
        secret_key: &SecretKey,
    ) -> TxInWitness {
        let message = Message::from_slice(&txid[..]).expect("32 bytes");
        let sig = secp.sign_recoverable(&message, &secret_key);
        return TxInWitness::BasicRedeem(sig);
    }

    pub fn get_account_op_witness<C: Signing>(
        secp: Secp256k1<C>,
        txid: &TxId,
        secret_key: &SecretKey,
    ) -> AccountOpWitness {
        let message = Message::from_slice(&txid[..]).expect("32 bytes");
        let sig = secp.sign_recoverable(&message, &secret_key);
        return AccountOpWitness::new(sig);
    }

    fn create_db() -> Arc<dyn KeyValueDB> {
        Arc::new(create(NUM_COLUMNS.unwrap()))
    }

    fn prepate_init_tx(
        timelocked: bool,
    ) -> (Arc<dyn KeyValueDB>, TxoPointer, ExtendedAddr, SecretKey) {
        let db = create_db();

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let addr = ExtendedAddr::BasicRedeem(RedeemAddress::from(&public_key));
        let mut old_tx = Tx::new();

        if timelocked {
            old_tx.add_output(TxOut::new_with_timelock(addr.clone(), Coin::one(), 20));
        } else {
            old_tx.add_output(TxOut::new_with_timelock(addr.clone(), Coin::one(), -20));
        }

        let old_tx_id = old_tx.id();

        let mut inittx = db.transaction();
        inittx.put(
            COL_BODIES,
            &old_tx_id[..],
            &TxWithOutputs::Transfer(old_tx).encode(),
        );

        inittx.put(
            COL_TX_META,
            &old_tx_id[..],
            &BitVec::from_elem(1, false).to_bytes(),
        );
        db.write(inittx).unwrap();
        let txp = TxoPointer::new(old_tx_id, 0);
        (db, txp, addr, secret_key)
    }

    fn prepare_app_valid_transfer_tx(
        timelocked: bool,
    ) -> (
        Arc<dyn KeyValueDB>,
        TxAux,
        Tx,
        TxWitness,
        SecretKey,
        AccountStorage,
    ) {
        let (db, txp, addr, secret_key) = prepate_init_tx(timelocked);
        let secp = Secp256k1::new();
        let mut tx = Tx::new();
        tx.add_input(txp);
        tx.add_output(TxOut::new(addr, Coin::new(9).unwrap()));
        let sk2 = SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order");
        let pk2 = PublicKey::from_secret_key(&secp, &sk2);
        tx.add_output(TxOut::new(
            ExtendedAddr::BasicRedeem(RedeemAddress::from(&pk2)),
            Coin::new(1).unwrap(),
        ));

        let witness: Vec<TxInWitness> = vec![get_tx_witness(secp, &tx.id(), &secret_key)];
        let txaux = TxAux::new(tx.clone(), witness.clone().into());
        (
            db,
            txaux,
            tx.clone(),
            witness.into(),
            secret_key,
            AccountStorage::new(Storage::new_db(create_db()), 20).expect("account db"),
        )
    }

    fn prepare_app_valid_unbond_tx(
    ) -> (TxAux, UnbondTx, SecretKey, AccountStorage, StarlingFixedKey) {
        let mut tree = AccountStorage::new(Storage::new_db(create_db()), 20).expect("account db");
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let addr = RedeemAddress::from(&public_key);
        let account = Account::new(1, Coin::one(), Coin::zero(), 0, addr);
        let key = account.key();
        let wrapped = AccountWrapper(account);
        let new_root = tree
            .insert(None, &mut [&key], &mut vec![&wrapped])
            .expect("insert");
        let tx = UnbondTx::new(
            Coin::new(9).unwrap(),
            1,
            AccountOpAttributes::new(DEFAULT_CHAIN_ID),
        );
        let witness = get_account_op_witness(secp, &tx.id(), &secret_key);
        let txaux = TxAux::UnbondStakeTx(tx.clone(), witness.clone());
        (txaux, tx.clone(), secret_key, tree, new_root)
    }

    #[test]
    fn existing_account_unbond_tx_should_verify() {
        let (txaux, _, _, accounts, last_account_root_hash) = prepare_app_valid_unbond_tx();
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0,
            last_account_root_hash,
            unbonding_period: 1,
        };
        let result = verify(&txaux, extra_info, create_db(), &accounts);
        assert!(result.is_ok());
    }

    #[test]
    fn test_account_unbond_verify_fail() {
        let db = create_db();
        let (txaux, tx, secret_key, accounts, last_account_root_hash) =
            prepare_app_valid_unbond_tx();
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0,
            last_account_root_hash,
            unbonding_period: 1,
        };
        // WrongChainHexId
        {
            let mut extra_info = extra_info.clone();
            extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::WrongChainHexId);
        }
        // AccountNotFound
        {
            let mut extra_info = extra_info.clone();
            extra_info.last_account_root_hash = [0; 32];
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::AccountNotFound);
        }
        // AccountIncorrectNonce
        {
            let mut tx = tx.clone();
            tx.nonce = 0;
            let txaux = TxAux::UnbondStakeTx(
                tx.clone(),
                get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
            );
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::AccountIncorrectNonce);
        }
        // ZeroCoin
        {
            let mut tx = tx.clone();
            tx.value = Coin::zero();
            let txaux = TxAux::UnbondStakeTx(
                tx.clone(),
                get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
            );
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::ZeroCoin);
        }
        // InputOutputDoNotMatch
        {
            let mut tx = tx.clone();
            tx.value = (tx.value + Coin::one()).unwrap();
            let txaux = TxAux::UnbondStakeTx(
                tx.clone(),
                get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
            );
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::InputOutputDoNotMatch);
        }
    }

    fn prepare_app_valid_withdraw_tx(
        unbonded_from: Timespec,
    ) -> (
        TxAux,
        WithdrawUnbondedTx,
        AccountOpWitness,
        SecretKey,
        AccountStorage,
        StarlingFixedKey,
    ) {
        let mut tree = AccountStorage::new(Storage::new_db(create_db()), 20).expect("account db");
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let addr = RedeemAddress::from(&public_key);
        let account = Account::new(1, Coin::zero(), Coin::one(), unbonded_from, addr);
        let key = account.key();
        let wrapped = AccountWrapper(account);
        let new_root = tree
            .insert(None, &mut [&key], &mut vec![&wrapped])
            .expect("insert");

        let sk2 = SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order");
        let pk2 = PublicKey::from_secret_key(&secp, &sk2);

        let outputs = vec![
            TxOut::new_with_timelock(ExtendedAddr::BasicRedeem(addr), Coin::new(9).unwrap(), 0),
            TxOut::new_with_timelock(
                ExtendedAddr::BasicRedeem(RedeemAddress::from(&pk2)),
                Coin::new(1).unwrap(),
                0,
            ),
        ];

        let tx = WithdrawUnbondedTx::new(1, outputs, TxAttributes::new(DEFAULT_CHAIN_ID));
        let witness = get_account_op_witness(secp, &tx.id(), &secret_key);
        let txaux = TxAux::WithdrawUnbondedStakeTx(tx.clone(), witness.clone());
        (txaux, tx.clone(), witness, secret_key, tree, new_root)
    }

    #[test]
    fn existing_account_withdraw_tx_should_verify() {
        let (txaux, _, _, _, accounts, last_account_root_hash) = prepare_app_valid_withdraw_tx(0);
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0,
            last_account_root_hash,
            unbonding_period: 1,
        };
        let result = verify(&txaux, extra_info, create_db(), &accounts);
        assert!(result.is_ok());
    }

    #[test]
    fn test_account_withdraw_verify_fail() {
        let db = create_db();
        let (txaux, tx, witness, secret_key, accounts, last_account_root_hash) =
            prepare_app_valid_withdraw_tx(0);
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0,
            last_account_root_hash,
            unbonding_period: 1,
        };
        // WrongChainHexId
        {
            let mut extra_info = extra_info.clone();
            extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::WrongChainHexId);
        }
        // NoOutputs
        {
            let mut tx = tx.clone();
            tx.outputs.clear();
            let txaux = TxAux::WithdrawUnbondedStakeTx(tx, witness.clone());
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::NoOutputs);
        }
        // ZeroCoin
        {
            let mut tx = tx.clone();
            tx.outputs[0].value = Coin::zero();
            let txaux = TxAux::WithdrawUnbondedStakeTx(tx, witness.clone());
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::ZeroCoin);
        }
        // InvalidSum
        {
            let mut tx = tx.clone();
            tx.outputs[0].value = Coin::max();
            let outp = tx.outputs[0].clone();
            tx.outputs.push(outp);
            let txaux = TxAux::WithdrawUnbondedStakeTx(
                tx.clone(),
                get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
            );
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(
                &result,
                Error::InvalidSum(CoinError::OutOfBound(Coin::max().into())),
            );
        }
        // InputOutputDoNotMatch
        {
            let mut tx = tx.clone();
            tx.outputs[0].value = (tx.outputs[0].value + Coin::one()).unwrap();
            let txaux = TxAux::WithdrawUnbondedStakeTx(
                tx.clone(),
                get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
            );
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::InputOutputDoNotMatch);
        }
        // AccountNotFound
        {
            let mut extra_info = extra_info.clone();
            extra_info.last_account_root_hash = [0; 32];
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::AccountNotFound);
        }
        // AccountIncorrectNonce
        {
            let mut tx = tx.clone();
            tx.nonce = 0;
            let txaux = TxAux::WithdrawUnbondedStakeTx(
                tx.clone(),
                get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
            );
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::AccountIncorrectNonce);
        }
        // AccountWithdrawOutputNotLocked
        {
            let mut tx = tx.clone();
            tx.outputs[0].valid_from = None;
            let txaux = TxAux::WithdrawUnbondedStakeTx(
                tx.clone(),
                get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key),
            );
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::AccountWithdrawOutputNotLocked);
        }
        // AccountNotUnbonded
        {
            let (txaux, _, _, _, accounts, last_account_root_hash) =
                prepare_app_valid_withdraw_tx(20);
            let mut extra_info = extra_info.clone();
            extra_info.last_account_root_hash = last_account_root_hash;
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::AccountNotUnbonded);
        }
    }

    fn prepare_app_valid_deposit_tx(
        timelocked: bool,
    ) -> (
        Arc<dyn KeyValueDB>,
        TxAux,
        DepositBondTx,
        TxWitness,
        AccountStorage,
    ) {
        let (db, txp, _, secret_key) = prepate_init_tx(timelocked);
        let secp = Secp256k1::new();
        let sk2 = SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order");
        let pk2 = PublicKey::from_secret_key(&secp, &sk2);
        let tx = DepositBondTx::new(
            vec![txp],
            RedeemAddress::from(&pk2),
            AccountOpAttributes::new(DEFAULT_CHAIN_ID),
        );

        let witness: Vec<TxInWitness> = vec![get_tx_witness(secp, &tx.id(), &secret_key)];
        let txaux = TxAux::DepositStakeTx(tx.clone(), witness.clone().into());
        (
            db,
            txaux,
            tx.clone(),
            witness.into(),
            AccountStorage::new(Storage::new_db(create_db()), 20).expect("account db"),
        )
    }

    const DEFAULT_CHAIN_ID: u8 = 0;

    #[test]
    fn existing_utxo_input_tx_should_verify() {
        let (db, txaux, _, _, _, accounts) = prepare_app_valid_transfer_tx(false);
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0,
            last_account_root_hash: [0u8; 32],
            unbonding_period: 1,
        };
        let result = verify(&txaux, extra_info, db, &accounts);
        assert!(result.is_ok());
        let (db, txaux, _, _, accounts) = prepare_app_valid_deposit_tx(false);
        let result = verify(&txaux, extra_info, db, &accounts);
        assert!(result.is_ok());
    }

    fn expect_error<T, Error>(res: &Result<T, Error>, expected: Error)
    where
        Error: Debug,
    {
        match res {
            Err(err) if mem::discriminant(&expected) == mem::discriminant(err) => {}
            Err(err) => panic!("Expected error {:?} but got {:?}", expected, err),
            Ok(_) => panic!("Expected error {:?} but succeeded", expected),
        }
    }

    #[test]
    fn test_deposit_verify_fail() {
        let (db, txaux, tx, witness, accounts) = prepare_app_valid_deposit_tx(false);
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0,
            last_account_root_hash: [0u8; 32],
            unbonding_period: 1,
        };
        // WrongChainHexId
        {
            let mut extra_info = extra_info.clone();
            extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::WrongChainHexId);
        }
        // NoInputs
        {
            let mut tx = tx.clone();
            tx.inputs.clear();
            let txaux = TxAux::DepositStakeTx(tx, witness.clone());
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::NoInputs);
        }
        // DuplicateInputs
        {
            let mut tx = tx.clone();
            let inp = tx.inputs[0].clone();
            tx.inputs.push(inp);
            let txaux = TxAux::DepositStakeTx(tx, witness.clone());
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::DuplicateInputs);
        }
        // UnexpectedWitnesses
        {
            let mut witness = witness.clone();
            let wp = witness[0].clone();
            witness.push(wp);
            let txaux = TxAux::DepositStakeTx(tx.clone(), witness);
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::UnexpectedWitnesses);
        }
        // MissingWitnesses
        {
            let txaux = TxAux::DepositStakeTx(tx.clone(), vec![].into());
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::MissingWitnesses);
        }
        // InputSpent
        {
            let mut inittx = db.transaction();
            inittx.put(
                COL_TX_META,
                &tx.inputs[0].id[..],
                &BitVec::from_elem(1, true).to_bytes(),
            );
            db.write(inittx).unwrap();

            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::InputSpent);

            let mut reset = db.transaction();
            reset.put(
                COL_TX_META,
                &tx.inputs[0].id[..],
                &BitVec::from_elem(1, false).to_bytes(),
            );
            db.write(reset).unwrap();
        }
        // Invalid signature (EcdsaCrypto)
        {
            let secp = Secp256k1::new();
            let mut witness = witness.clone();
            witness[0] = get_tx_witness(
                secp.clone(),
                &tx.id(),
                &SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order"),
            );
            let txaux = TxAux::DepositStakeTx(tx.clone(), witness);
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(
                &result,
                Error::EcdsaCrypto(secp256k1::Error::InvalidPublicKey),
            );
        }
        // InvalidInput
        {
            let result = verify(&txaux, extra_info, create_db(), &accounts);
            expect_error(&result, Error::InvalidInput);
        }
        // InputOutputDoNotMatch
        {
            let mut extra_info = extra_info.clone();
            extra_info.min_fee_computed = Fee::new(Coin::one());
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::InputOutputDoNotMatch);
        }
    }

    #[test]
    fn test_transfer_verify_fail() {
        let (db, txaux, tx, witness, secret_key, accounts) = prepare_app_valid_transfer_tx(false);
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0,
            last_account_root_hash: [0u8; 32],
            unbonding_period: 1,
        };
        // WrongChainHexId
        {
            let mut extra_info = extra_info.clone();
            extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::WrongChainHexId);
        }
        // NoInputs
        {
            let mut tx = tx.clone();
            tx.inputs.clear();
            let txaux = TxAux::TransferTx(tx, witness.clone());
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::NoInputs);
        }
        // NoOutputs
        {
            let mut tx = tx.clone();
            tx.outputs.clear();
            let txaux = TxAux::TransferTx(tx, witness.clone());
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::NoOutputs);
        }
        // DuplicateInputs
        {
            let mut tx = tx.clone();
            let inp = tx.inputs[0].clone();
            tx.inputs.push(inp);
            let txaux = TxAux::TransferTx(tx, witness.clone());
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::DuplicateInputs);
        }
        // ZeroCoin
        {
            let mut tx = tx.clone();
            tx.outputs[0].value = Coin::zero();
            let txaux = TxAux::TransferTx(tx, witness.clone());
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::ZeroCoin);
        }
        // UnexpectedWitnesses
        {
            let mut witness = witness.clone();
            let wp = witness[0].clone();
            witness.push(wp);
            let txaux = TxAux::TransferTx(tx.clone(), witness);
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::UnexpectedWitnesses);
        }
        // MissingWitnesses
        {
            let txaux = TxAux::TransferTx(tx.clone(), vec![].into());
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::MissingWitnesses);
        }
        // InvalidSum
        {
            let mut tx = tx.clone();
            tx.outputs[0].value = Coin::max();
            let outp = tx.outputs[0].clone();
            tx.outputs.push(outp);
            let mut witness = witness.clone();
            witness[0] = get_tx_witness(Secp256k1::new(), &tx.id(), &secret_key);
            let txaux = TxAux::TransferTx(tx, witness);
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(
                &result,
                Error::InvalidSum(CoinError::OutOfBound(Coin::max().into())),
            );
        }
        // InputSpent
        {
            let mut inittx = db.transaction();
            inittx.put(
                COL_TX_META,
                &tx.inputs[0].id[..],
                &BitVec::from_elem(1, true).to_bytes(),
            );
            db.write(inittx).unwrap();

            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::InputSpent);

            let mut reset = db.transaction();
            reset.put(
                COL_TX_META,
                &tx.inputs[0].id[..],
                &BitVec::from_elem(1, false).to_bytes(),
            );
            db.write(reset).unwrap();
        }
        // Invalid signature (EcdsaCrypto)
        {
            let secp = Secp256k1::new();
            let mut witness = witness.clone();
            witness[0] = get_tx_witness(
                secp.clone(),
                &tx.id(),
                &SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order"),
            );
            let txaux = TxAux::TransferTx(tx.clone(), witness);
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(
                &result,
                Error::EcdsaCrypto(secp256k1::Error::InvalidPublicKey),
            );
        }
        // InvalidInput
        {
            let result = verify(&txaux, extra_info, create_db(), &accounts);
            expect_error(&result, Error::InvalidInput);
        }
        // InputOutputDoNotMatch
        {
            let mut tx = tx.clone();
            let mut witness = witness.clone();

            tx.outputs[0].value = (tx.outputs[0].value + Coin::one()).unwrap();
            witness[0] = get_tx_witness(Secp256k1::new(), &tx.id(), &secret_key);
            let txaux = TxAux::TransferTx(tx, witness);
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::InputOutputDoNotMatch);
        }
        // OutputInTimelock
        {
            let (db, txaux, _, _, _, accounts) = prepare_app_valid_transfer_tx(true);
            let result = verify(&txaux, extra_info, db.clone(), &accounts);
            expect_error(&result, Error::OutputInTimelock);
        }
    }

}
