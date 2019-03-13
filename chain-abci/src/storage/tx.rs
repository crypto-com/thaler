use crate::storage::{COL_BODIES, COL_TX_META};
use bit_vec::BitVec;
use chain_core::tx::{data::Tx, TxAux};
use kvdb::{DBTransaction, KeyValueDB};
use serde_cbor::from_slice;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::{fmt, io};

/// All possible TX validation errors
#[derive(Debug)]
pub enum Error {
    InvalidInput,
    InputSpent,
    NoInputs,
    DuplicateInputs,
    IoError(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::Error::*;
        match self {
            InvalidInput => write!(f, "transaction spends an invalid input"),
            NoInputs => write!(f, "transaction has no inputs"),
            DuplicateInputs => write!(f, "duplicated inputs"),
            InputSpent => write!(f, "transaction spends an input that was already spent"),
            IoError(ref err) => write!(f, "IO error: {}", err),
        }
    }
}

/// Given a db and a DB transaction, it will go through TX inputs and mark them as spent
/// in the TX_META storage.
pub fn spend_utxos(txaux: &TxAux, db: Arc<dyn KeyValueDB>, dbtx: &mut DBTransaction) {
    let mut updated_txs = BTreeMap::new();
    for txin in txaux.tx.inputs.iter() {
        updated_txs
            .entry(txin.id)
            .or_insert_with(|| {
                BitVec::from_bytes(&db.get(COL_TX_META, &txin.id[..]).unwrap().unwrap())
            })
            .set(txin.index, true);
    }
    for (txid, bv) in &updated_txs {
        dbtx.put(COL_TX_META, txid, &bv.to_bytes());
    }
}

/// Given a db and a DB transaction, it will go through TX inputs and mark them as spent
/// in the TX_META storage and it will create a new entry for TX in TX_META with all outputs marked as unspent.
pub fn update_utxos_commit(txaux: &TxAux, db: Arc<dyn KeyValueDB>, dbtx: &mut DBTransaction) {
    spend_utxos(txaux, db, dbtx);
    let txid = txaux.tx.id();
    dbtx.put(
        COL_TX_META,
        &txid,
        &BitVec::from_elem(txaux.tx.outputs.len(), false).to_bytes(),
    );
}

pub fn basic_verify_collect_inputs(
    txaux: &TxAux,
    db: Arc<dyn KeyValueDB>,
) -> Result<Vec<Tx>, Error> {
    // check that there are inputs
    if txaux.tx.inputs.is_empty() {
        return Err(Error::NoInputs);
    }

    // check that there are no duplicate inputs
    let mut inputs = BTreeSet::new();
    if !txaux.tx.inputs.iter().all(|x| inputs.insert(x)) {
        return Err(Error::DuplicateInputs);
    }
    let mut result: Vec<Tx> = Vec::with_capacity(txaux.tx.inputs.len());
    // check inputs are not spent and look up corresponding transactions
    for txin in txaux.tx.inputs.iter() {
        let txo = db.get(COL_TX_META, &txin.id[..]);
        match txo {
            Ok(Some(v)) => {
                let bv = BitVec::from_bytes(&v).get(txin.index);
                if bv.is_none() {
                    return Err(Error::InvalidInput);
                }
                if bv.unwrap() {
                    return Err(Error::InputSpent);
                }
                result
                    .push(from_slice(&db.get(COL_BODIES, &txin.id[..]).unwrap().unwrap()).unwrap());
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::storage::{COL_TX_META, NUM_COLUMNS};
    use abci_enclave_protocol::{verify_with_storage, Error as EError};
    use chain_core::init::address::RedeemAddress;
    use chain_core::init::coin::{Coin, CoinError};
    use chain_core::tx::data::{address::ExtendedAddr, input::TxoPointer, output::TxOut};
    use chain_core::tx::witness::{redeem::EcdsaSignature, TxInWitness};
    use kvdb_memorydb::create;
    use secp256k1::{key::PublicKey, key::SecretKey, Message, Secp256k1, Signing};
    use serde_cbor::ser::to_vec_packed;
    use std::fmt::Debug;
    use std::mem;

    pub fn get_tx_witness<C: Signing>(
        secp: Secp256k1<C>,
        tx: &Tx,
        secret_key: &SecretKey,
    ) -> TxInWitness {
        let message = Message::from_slice(&tx.id()).expect("32 bytes");
        let sig = secp.sign_recoverable(&message, &secret_key);
        let (v, ss) = sig.serialize_compact();
        let r = &ss[0..32];
        let s = &ss[32..64];
        let mut sign = EcdsaSignature::default();
        sign.v = v.to_i32() as u8;
        sign.r.copy_from_slice(r);
        sign.s.copy_from_slice(s);
        return TxInWitness::BasicRedeem(sign);
    }

    fn create_db() -> Arc<dyn KeyValueDB> {
        Arc::new(create(NUM_COLUMNS.unwrap()))
    }

    fn prepare_app_valid_tx(timelocked: bool) -> (Arc<dyn KeyValueDB>, TxAux, SecretKey) {
        let db = create_db();

        let mut tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let addr = ExtendedAddr::BasicRedeem(RedeemAddress::from(&public_key).0);

        let mut old_tx = Tx::new();

        if timelocked {
            old_tx.add_output(TxOut::new_with_timelock(
                addr.clone(),
                Coin::new(10).unwrap(),
                20,
            ));
        } else {
            old_tx.add_output(TxOut::new_with_timelock(
                addr.clone(),
                Coin::new(10).unwrap(),
                -20,
            ));
        }

        let old_tx_id = old_tx.id();
        let txp = TxoPointer::new(old_tx_id, 0);

        let mut inittx = db.transaction();
        inittx.put(COL_BODIES, &old_tx_id, &to_vec_packed(&old_tx).unwrap());

        inittx.put(
            COL_TX_META,
            &old_tx_id,
            &BitVec::from_elem(1, false).to_bytes(),
        );
        db.write(inittx).unwrap();
        tx.add_input(txp);
        tx.add_output(TxOut::new(addr, Coin::new(9).unwrap()));
        tx.add_output(TxOut::new(
            ExtendedAddr::BasicRedeem(RedeemAddress::default().0),
            Coin::new(1).unwrap(),
        ));

        let witness: Vec<TxInWitness> = vec![get_tx_witness(secp, &tx, &secret_key)];
        let txaux = TxAux::new(tx, std::convert::From::from(witness));
        (db, txaux, secret_key)
    }

    const DEFAULT_CHAIN_ID: u8 = 0;

    #[test]
    fn existing_utxo_input_tx_should_verify() {
        let (db, txaux, _) = prepare_app_valid_tx(false);
        let inputs = basic_verify_collect_inputs(&txaux, db);
        assert!(inputs.is_ok());
        let result = verify_with_storage(&txaux, inputs.unwrap(), DEFAULT_CHAIN_ID, 0);
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
    fn test_verify_fail() {
        let (db, txaux, secret_key) = prepare_app_valid_tx(false);
        let inputs = basic_verify_collect_inputs(&txaux, db.clone()).expect("valid inputs");
        // WrongChainHexId
        {
            let result = verify_with_storage(&txaux, inputs.clone(), DEFAULT_CHAIN_ID + 1, 0);
            expect_error(&result, EError::WrongChainHexId);
        }
        // NoInputs
        {
            let mut txaux = txaux.clone();
            txaux.tx.inputs.clear();
            let basic_result = basic_verify_collect_inputs(&txaux, db.clone());
            expect_error(&basic_result, Error::NoInputs);
            let result = verify_with_storage(&txaux, inputs.clone(), DEFAULT_CHAIN_ID, 0);
            expect_error(&result, EError::NoInputs);
        }
        // NoOutputs
        {
            let mut txaux = txaux.clone();
            txaux.tx.outputs.clear();
            let result = verify_with_storage(&txaux, inputs.clone(), DEFAULT_CHAIN_ID, 0);
            expect_error(&result, EError::NoOutputs);
        }
        // DuplicateInputs
        {
            let mut txaux = txaux.clone();
            let inp = txaux.tx.inputs[0].clone();
            txaux.tx.inputs.push(inp);
            let basic_result = basic_verify_collect_inputs(&txaux, db.clone());
            expect_error(&basic_result, Error::DuplicateInputs);
            let result = verify_with_storage(&txaux, inputs.clone(), DEFAULT_CHAIN_ID, 0);
            expect_error(&result, EError::DuplicateInputs);
        }
        // ZeroCoin
        {
            let mut txaux = txaux.clone();
            txaux.tx.outputs[0].value = Coin::zero();
            let result = verify_with_storage(&txaux, inputs.clone(), DEFAULT_CHAIN_ID, 0);
            expect_error(&result, EError::ZeroCoin);
        }
        // UnexpectedWitnesses
        {
            let mut txaux = txaux.clone();
            let wp = txaux.witness[0].clone();
            txaux.witness.push(wp);
            let result = verify_with_storage(&txaux, inputs.clone(), DEFAULT_CHAIN_ID, 0);
            expect_error(&result, EError::UnexpectedWitnesses);
        }
        // MissingWitnesses
        {
            let mut txaux = txaux.clone();
            txaux.witness.clear();
            let result = verify_with_storage(&txaux, inputs.clone(), DEFAULT_CHAIN_ID, 0);
            expect_error(&result, EError::MissingWitnesses);
        }
        // InvalidSum
        {
            let mut txaux = txaux.clone();
            txaux.tx.outputs[0].value = Coin::max();
            let outp = txaux.tx.outputs[0].clone();
            txaux.tx.outputs.push(outp);
            txaux.witness[0] = get_tx_witness(Secp256k1::new(), &txaux.tx, &secret_key);
            let result = verify_with_storage(&txaux, inputs.clone(), DEFAULT_CHAIN_ID, 0);
            expect_error(
                &result,
                EError::InvalidSum(CoinError::OutOfBound(*Coin::max())),
            );
        }
        // InputSpent
        {
            let mut inittx = db.transaction();
            inittx.put(
                COL_TX_META,
                &txaux.tx.inputs[0].id,
                &BitVec::from_elem(1, true).to_bytes(),
            );
            db.write(inittx).unwrap();

            let result = basic_verify_collect_inputs(&txaux, db.clone());
            expect_error(&result, Error::InputSpent);

            let mut reset = db.transaction();
            reset.put(
                COL_TX_META,
                &txaux.tx.inputs[0].id,
                &BitVec::from_elem(1, false).to_bytes(),
            );
            db.write(reset).unwrap();
        }
        // Invalid signature (WitnessVerificationFailed)
        {
            let mut txaux = txaux.clone();
            let secp = Secp256k1::new();
            txaux.witness[0] = get_tx_witness(
                secp.clone(),
                &txaux.tx,
                &SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order"),
            );
            let result = verify_with_storage(&txaux, inputs.clone(), DEFAULT_CHAIN_ID, 0);
            expect_error(&result, EError::WitnessVerificationFailed);
        }
        // InvalidInput
        {
            let basic_result = basic_verify_collect_inputs(&txaux, create_db());
            expect_error(&basic_result, Error::InvalidInput);
            let result = verify_with_storage(&txaux, vec![Tx::default()], DEFAULT_CHAIN_ID, 0);
            expect_error(&result, EError::InvalidInput);
        }
        // InputOutputDoNotMatch
        {
            let mut txaux = txaux.clone();
            txaux.tx.outputs[0].value = (txaux.tx.outputs[0].value + Coin::unit()).unwrap();
            txaux.witness[0] = get_tx_witness(Secp256k1::new(), &txaux.tx, &secret_key);
            let result = verify_with_storage(&txaux, inputs.clone(), DEFAULT_CHAIN_ID, 0);
            expect_error(&result, EError::InputOutputDoNotMatch);
        }
        // OutputInTimelock
        {
            let (db, txaux, _) = prepare_app_valid_tx(true);
            let inputs = basic_verify_collect_inputs(&txaux, db).expect("valid inputs");
            let result = verify_with_storage(&txaux, inputs, DEFAULT_CHAIN_ID, 0);
            expect_error(&result, EError::OutputInTimelock);
        }
    }

}
