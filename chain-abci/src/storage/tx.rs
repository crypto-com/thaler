use crate::storage::account::AccountStorage;
use crate::storage::account::AccountWrapper;
use crate::storage::{COL_BODIES, COL_TX_META};
use bit_vec::BitVec;
use chain_core::state::account::{to_stake_key, StakedState, StakedStateAddress};
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::fee::Fee;
use chain_core::tx::TransactionId;
use chain_core::tx::TxAux;
use chain_tx_validation::{
    verify_bonded_deposit, verify_transfer, verify_unbonded_withdraw, verify_unbonding,
    witness::verify_tx_recover_address, ChainInfo, Error, TxWithOutputs,
};
use kvdb::KeyValueDB;
use parity_codec::Decode;
use starling::constants::KEY_LEN;
use std::sync::Arc;

/// key type for looking up accounts/staked states in the merkle tree storage
pub type StarlingFixedKey = [u8; KEY_LEN];

/// checks that the account can be retrieved from the trie storage
pub fn get_account(
    account_address: &StakedStateAddress,
    last_root: &StarlingFixedKey,
    accounts: &AccountStorage,
) -> Result<StakedState, Error> {
    let account_key = to_stake_key(account_address);
    let items = accounts.get(last_root, &mut [&account_key]);
    if let Err(e) = items {
        return Err(Error::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            e,
        )));
    }
    let account = items.unwrap()[&account_key].clone();
    match account {
        None => Err(Error::AccountNotFound),
        Some(AccountWrapper(a)) => Ok(a),
    }
}

fn check_spent_input_lookup(
    inputs: &[TxoPointer],
    db: Arc<dyn KeyValueDB>,
) -> Result<Vec<TxWithOutputs>, Error> {
    // check that there are inputs
    if inputs.is_empty() {
        return Err(Error::NoInputs);
    }
    let mut result = Vec::with_capacity(inputs.len());
    for txin in inputs.iter() {
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
                result.push(tx);
            }
            Ok(None) => {
                return Err(Error::InvalidInput);
            }
            Err(e) => {
                return Err(Error::IoError(e));
            }
        }
    }
    Ok(result)
}

/// Checks TX against the current DB and returns an `Error` if something fails.
/// If OK, returns the paid fee.
pub fn verify(
    txaux: &TxAux,
    extra_info: ChainInfo,
    last_account_root_hash: &StarlingFixedKey,
    db: Arc<dyn KeyValueDB>,
    accounts: &AccountStorage,
) -> Result<(Fee, Option<StakedState>), Error> {
    let paid_fee = match txaux {
        TxAux::TransferTx(maintx, witness) => {
            let input_transactions = check_spent_input_lookup(&maintx.inputs, db)?;
            (
                verify_transfer(maintx, witness, extra_info, input_transactions)?,
                None,
            )
        }
        TxAux::DepositStakeTx(maintx, witness) => {
            let maccount = get_account(&maintx.to_staked_account, last_account_root_hash, accounts);
            let account = match maccount {
                Ok(a) => Some(a),
                Err(Error::AccountNotFound) => None,
                Err(e) => {
                    return Err(e);
                }
            };
            let input_transactions = check_spent_input_lookup(&maintx.inputs, db)?;

            verify_bonded_deposit(maintx, witness, extra_info, input_transactions, account)?
        }
        TxAux::UnbondStakeTx(maintx, witness) => {
            let account_address = verify_tx_recover_address(&witness, &maintx.id());
            if let Err(e) = account_address {
                return Err(Error::EcdsaCrypto(e));
            }
            let account = get_account(&account_address.unwrap(), last_account_root_hash, accounts)?;
            verify_unbonding(maintx, extra_info, account)?
        }
        TxAux::WithdrawUnbondedStakeTx(maintx, witness) => {
            let account_address = verify_tx_recover_address(&witness, &maintx.id());
            if let Err(e) = account_address {
                return Err(Error::EcdsaCrypto(e));
            }
            let account = get_account(&account_address.unwrap(), last_account_root_hash, accounts)?;
            verify_unbonded_withdraw(maintx, extra_info, account)?
        }
    };
    Ok(paid_fee)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::storage::{Storage, COL_TX_META, NUM_COLUMNS};
    use chain_core::common::Timespec;
    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::{Coin, CoinError};
    use chain_core::state::account::StakedStateOpAttributes;
    use chain_core::state::account::{
        DepositBondTx, StakedStateOpWitness, UnbondTx, WithdrawUnbondedTx,
    };
    use chain_core::tx::data::{
        address::ExtendedAddr, attribute::TxAttributes, input::TxoPointer, output::TxOut,
    };
    use chain_core::tx::data::{Tx, TxId};
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
    ) -> StakedStateOpWitness {
        let message = Message::from_slice(&txid[..]).expect("32 bytes");
        let sig = secp.sign_recoverable(&message, &secret_key);
        return StakedStateOpWitness::new(sig);
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
        let account = StakedState::new(1, Coin::one(), Coin::zero(), 0, addr.into());
        let key = account.key();
        let wrapped = AccountWrapper(account);
        let new_root = tree
            .insert(None, &mut [&key], &mut vec![&wrapped])
            .expect("insert");
        let tx = UnbondTx::new(
            Coin::new(9).unwrap(),
            1,
            StakedStateOpAttributes::new(DEFAULT_CHAIN_ID),
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
            unbonding_period: 1,
        };
        let result = verify(
            &txaux,
            extra_info,
            &last_account_root_hash,
            create_db(),
            &accounts,
        );
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
            unbonding_period: 1,
        };
        // WrongChainHexId
        {
            let mut extra_info = extra_info.clone();
            extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::WrongChainHexId);
        }
        // AccountNotFound
        {
            let result = verify(&txaux, extra_info, &[0; 32], db.clone(), &accounts);
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
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
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
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
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
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::InputOutputDoNotMatch);
        }
    }

    fn prepare_app_valid_withdraw_tx(
        unbonded_from: Timespec,
    ) -> (
        TxAux,
        WithdrawUnbondedTx,
        StakedStateOpWitness,
        SecretKey,
        AccountStorage,
        StarlingFixedKey,
    ) {
        let mut tree = AccountStorage::new(Storage::new_db(create_db()), 20).expect("account db");
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let addr = RedeemAddress::from(&public_key);
        let account = StakedState::new(1, Coin::zero(), Coin::one(), unbonded_from, addr.into());
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
            unbonding_period: 1,
        };
        let result = verify(
            &txaux,
            extra_info,
            &last_account_root_hash,
            create_db(),
            &accounts,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_account_withdraw_verify_fail() {
        let db = create_db();
        let (txaux, tx, _, secret_key, accounts, last_account_root_hash) =
            prepare_app_valid_withdraw_tx(0);
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0,
            unbonding_period: 1,
        };
        // WrongChainHexId
        {
            let mut extra_info = extra_info.clone();
            extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::WrongChainHexId);
        }
        // NoOutputs
        {
            let mut tx = tx.clone();
            tx.outputs.clear();
            let witness = get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key);
            let txaux = TxAux::WithdrawUnbondedStakeTx(tx, witness);
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::NoOutputs);
        }
        // ZeroCoin
        {
            let mut tx = tx.clone();
            tx.outputs[0].value = Coin::zero();
            let witness = get_account_op_witness(Secp256k1::new(), &tx.id(), &secret_key);
            let txaux = TxAux::WithdrawUnbondedStakeTx(tx, witness);
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
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
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
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
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::InputOutputDoNotMatch);
        }
        // AccountNotFound
        {
            let result = verify(&txaux, extra_info, &[0; 32], db.clone(), &accounts);
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
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
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
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::AccountWithdrawOutputNotLocked);
        }
        // AccountNotUnbonded
        {
            let (txaux, _, _, _, accounts, last_account_root_hash) =
                prepare_app_valid_withdraw_tx(20);
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
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
            RedeemAddress::from(&pk2).into(),
            StakedStateOpAttributes::new(DEFAULT_CHAIN_ID),
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
            unbonding_period: 1,
        };
        let last_account_root_hash = [0u8; 32];
        let result = verify(&txaux, extra_info, &last_account_root_hash, db, &accounts);
        assert!(result.is_ok());
        let (db, txaux, _, _, accounts) = prepare_app_valid_deposit_tx(false);
        let result = verify(&txaux, extra_info, &last_account_root_hash, db, &accounts);
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
            unbonding_period: 1,
        };
        let last_account_root_hash = [0u8; 32];
        // WrongChainHexId
        {
            let mut extra_info = extra_info.clone();
            extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::WrongChainHexId);
        }
        // NoInputs
        {
            let mut tx = tx.clone();
            tx.inputs.clear();
            let txaux = TxAux::DepositStakeTx(tx, witness.clone());
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::NoInputs);
        }
        // DuplicateInputs
        {
            let mut tx = tx.clone();
            let inp = tx.inputs[0].clone();
            tx.inputs.push(inp);
            let txaux = TxAux::DepositStakeTx(tx, witness.clone());
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::DuplicateInputs);
        }
        // UnexpectedWitnesses
        {
            let mut witness = witness.clone();
            let wp = witness[0].clone();
            witness.push(wp);
            let txaux = TxAux::DepositStakeTx(tx.clone(), witness);
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::UnexpectedWitnesses);
        }
        // MissingWitnesses
        {
            let txaux = TxAux::DepositStakeTx(tx.clone(), vec![].into());
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
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

            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
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
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(
                &result,
                Error::EcdsaCrypto(secp256k1::Error::InvalidPublicKey),
            );
        }
        // InvalidInput
        {
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                create_db(),
                &accounts,
            );
            expect_error(&result, Error::InvalidInput);
        }
        // InputOutputDoNotMatch
        {
            let mut extra_info = extra_info.clone();
            extra_info.min_fee_computed = Fee::new(Coin::one());
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
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
            unbonding_period: 1,
        };
        let last_account_root_hash = [0u8; 32];
        // WrongChainHexId
        {
            let mut extra_info = extra_info.clone();
            extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::WrongChainHexId);
        }
        // NoInputs
        {
            let mut tx = tx.clone();
            tx.inputs.clear();
            let txaux = TxAux::TransferTx(tx, witness.clone());
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::NoInputs);
        }
        // NoOutputs
        {
            let mut tx = tx.clone();
            tx.outputs.clear();
            let txaux = TxAux::TransferTx(tx, witness.clone());
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::NoOutputs);
        }
        // DuplicateInputs
        {
            let mut tx = tx.clone();
            let inp = tx.inputs[0].clone();
            tx.inputs.push(inp);
            let txaux = TxAux::TransferTx(tx, witness.clone());
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::DuplicateInputs);
        }
        // ZeroCoin
        {
            let mut tx = tx.clone();
            tx.outputs[0].value = Coin::zero();
            let txaux = TxAux::TransferTx(tx, witness.clone());
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::ZeroCoin);
        }
        // UnexpectedWitnesses
        {
            let mut witness = witness.clone();
            let wp = witness[0].clone();
            witness.push(wp);
            let txaux = TxAux::TransferTx(tx.clone(), witness);
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::UnexpectedWitnesses);
        }
        // MissingWitnesses
        {
            let txaux = TxAux::TransferTx(tx.clone(), vec![].into());
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
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
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
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

            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
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
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(
                &result,
                Error::EcdsaCrypto(secp256k1::Error::InvalidPublicKey),
            );
        }
        // InvalidInput
        {
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                create_db(),
                &accounts,
            );
            expect_error(&result, Error::InvalidInput);
        }
        // InputOutputDoNotMatch
        {
            let mut tx = tx.clone();
            let mut witness = witness.clone();

            tx.outputs[0].value = (tx.outputs[0].value + Coin::one()).unwrap();
            witness[0] = get_tx_witness(Secp256k1::new(), &tx.id(), &secret_key);
            let txaux = TxAux::TransferTx(tx, witness);
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::InputOutputDoNotMatch);
        }
        // OutputInTimelock
        {
            let (db, txaux, _, _, _, accounts) = prepare_app_valid_transfer_tx(true);
            let result = verify(
                &txaux,
                extra_info,
                &last_account_root_hash,
                db.clone(),
                &accounts,
            );
            expect_error(&result, Error::OutputInTimelock);
        }
    }

}
