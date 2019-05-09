use crate::storage::{COL_BODIES, COL_TX_META};
use bit_vec::BitVec;
use chain_core::common::Timespec;
use chain_core::init::coin::{Coin, CoinError};
use chain_core::tx::fee::Fee;
use chain_core::tx::{data::Tx, TxAux};
use kvdb::{DBTransaction, KeyValueDB};
use rlp::{Decodable, Rlp};
use secp256k1;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::{fmt, io};

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
        }
    }
}

/// Given a db and a DB transaction, it will go through TX inputs and mark them as spent
/// in the TX_META storage.
pub fn spend_utxos(tx: &Tx, db: Arc<dyn KeyValueDB>, dbtx: &mut DBTransaction) {
    let mut updated_txs = BTreeMap::new();
    for txin in tx.inputs.iter() {
        updated_txs
            .entry(txin.id)
            .or_insert_with(|| {
                BitVec::from_bytes(&db.get(COL_TX_META, &txin.id[..]).unwrap().unwrap())
            })
            .set(txin.index, true);
    }
    for (txid, bv) in &updated_txs {
        dbtx.put(COL_TX_META, txid.as_bytes(), &bv.to_bytes());
    }
}

/// Given a db and a DB transaction, it will go through TX inputs and mark them as spent
/// in the TX_META storage and it will create a new entry for TX in TX_META with all outputs marked as unspent.
pub fn update_utxos_commit(tx: &Tx, db: Arc<dyn KeyValueDB>, dbtx: &mut DBTransaction) {
    spend_utxos(tx, db, dbtx);
    dbtx.put(
        COL_TX_META,
        tx.id().as_bytes(),
        &BitVec::from_elem(tx.outputs.len(), false).to_bytes(),
    );
}

/// External information needed for TX validation
#[derive(Clone, Copy)]
pub struct ChainInfo {
    pub min_fee_computed: Fee,
    pub chain_hex_id: u8,
    pub previous_block_time: Timespec,
}

/// Checks TX against the current DB and returns an `Error` if something fails.
/// If OK, returns the paid fee.
/// TODO: when more address/sigs available, check Redeem addresses are never in outputs?
pub fn verify(txaux: &TxAux, extra_info: ChainInfo, db: Arc<dyn KeyValueDB>) -> Result<Fee, Error> {
    let paid_fee = match txaux {
        TxAux::TransferTx(maintx, witness) => {
            // TODO: check other attributes?
            // check that chain IDs match
            if extra_info.chain_hex_id != maintx.attributes.chain_hex_id {
                return Err(Error::WrongChainHexId);
            }
            // check that there are inputs
            if maintx.inputs.is_empty() {
                return Err(Error::NoInputs);
            }

            // check that there are outputs
            if maintx.outputs.is_empty() {
                return Err(Error::NoOutputs);
            }

            // check that there are no duplicate inputs
            let mut inputs = BTreeSet::new();
            if !maintx.inputs.iter().all(|x| inputs.insert(x)) {
                return Err(Error::DuplicateInputs);
            }

            // check that all outputs have a non-zero amount
            if !maintx.outputs.iter().all(|x| x.value > Coin::zero()) {
                return Err(Error::ZeroCoin);
            }

            // Note: we don't need to check against MAX_COIN because Coin's
            // constructor should already do it.

            // TODO: check address attributes?

            // verify transaction witnesses
            if maintx.inputs.len() < witness.len() {
                return Err(Error::UnexpectedWitnesses);
            }

            if maintx.inputs.len() > witness.len() {
                return Err(Error::MissingWitnesses);
            }

            let mut incoins = Coin::zero();

            // verify that txids of inputs correspond to the owner/signer
            // and it'd check they are not spent
            for (txin, in_witness) in maintx.inputs.iter().zip(witness.iter()) {
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
                        let tx = Tx::decode(&Rlp::new(
                            &db.get(COL_BODIES, &txin.id[..]).unwrap().unwrap(),
                        ))
                        .unwrap();
                        if txin.index >= tx.outputs.len() {
                            return Err(Error::InvalidInput);
                        }
                        let txout = &tx.outputs[txin.index];
                        if let Some(valid_from) = &txout.valid_from {
                            if *valid_from > extra_info.previous_block_time {
                                return Err(Error::OutputInTimelock);
                            }
                        }

                        let wv = in_witness.verify_tx_address(&maintx, &txout.address);
                        if wv.is_err() {
                            return Err(Error::EcdsaCrypto(wv.unwrap_err()));
                        }
                        let sum = incoins + txout.value;
                        if sum.is_err() {
                            return Err(Error::InvalidSum(sum.unwrap_err()));
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
            // check sum(input amounts) >= sum(output amounts) + minimum fee
            // TODO: should the fee be fixed / validation would reject TX if it pays more than the below minimum?
            let min_fee: Coin = extra_info.min_fee_computed.to_coin();

            let outsum = maintx.get_output_total().and_then(|x| x + min_fee);
            if outsum.is_err() {
                return Err(Error::InvalidSum(outsum.unwrap_err()));
            }
            let outcoins = outsum.unwrap();
            if incoins < outcoins {
                return Err(Error::InputOutputDoNotMatch);
            }
            (incoins - outcoins).and_then(|x| x + min_fee).unwrap()
        }
    };
    Ok(Fee::new(paid_fee))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::storage::{COL_TX_META, NUM_COLUMNS};
    use chain_core::init::address::RedeemAddress;
    use chain_core::tx::data::{address::ExtendedAddr, input::TxoPointer, output::TxOut};
    use chain_core::tx::fee::FeeAlgorithm;
    use chain_core::tx::fee::{LinearFee, Milli};
    use chain_core::tx::witness::{TxInWitness, TxWitness};
    use kvdb_memorydb::create;
    use rlp::Encodable;
    use secp256k1::{key::PublicKey, key::SecretKey, Message, Secp256k1, Signing};
    use std::fmt::Debug;
    use std::mem;

    pub fn get_tx_witness<C: Signing>(
        secp: Secp256k1<C>,
        tx: &Tx,
        secret_key: &SecretKey,
    ) -> TxInWitness {
        let message = Message::from_slice(tx.id().as_bytes()).expect("32 bytes");
        let sig = secp.sign_recoverable(&message, &secret_key);
        return TxInWitness::BasicRedeem(sig);
    }

    fn create_db() -> Arc<dyn KeyValueDB> {
        Arc::new(create(NUM_COLUMNS.unwrap()))
    }

    fn prepare_app_valid_tx(
        timelocked: bool,
    ) -> (Arc<dyn KeyValueDB>, TxAux, Tx, TxWitness, SecretKey) {
        let db = create_db();

        let mut tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let addr = ExtendedAddr::BasicRedeem(RedeemAddress::from(&public_key));
        let mut old_tx = Tx::new();

        if timelocked {
            old_tx.add_output(TxOut::new_with_timelock(
                addr.clone(),
                Coin::one(),
                20.into(),
            ));
        } else {
            old_tx.add_output(TxOut::new_with_timelock(
                addr.clone(),
                Coin::one(),
                (-20).into(),
            ));
        }

        let old_tx_id = old_tx.id();
        let txp = TxoPointer::new(old_tx_id, 0);

        let mut inittx = db.transaction();
        inittx.put(COL_BODIES, &old_tx_id.as_bytes(), &old_tx.rlp_bytes());

        inittx.put(
            COL_TX_META,
            &old_tx_id.as_bytes(),
            &BitVec::from_elem(1, false).to_bytes(),
        );
        db.write(inittx).unwrap();
        tx.add_input(txp);
        tx.add_output(TxOut::new(addr, Coin::new(9).unwrap()));
        let sk2 = SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order");
        let pk2 = PublicKey::from_secret_key(&secp, &sk2);
        tx.add_output(TxOut::new(
            ExtendedAddr::BasicRedeem(RedeemAddress::from(&pk2)),
            Coin::new(1).unwrap(),
        ));

        let witness: Vec<TxInWitness> = vec![get_tx_witness(secp, &tx, &secret_key)];
        let txaux = TxAux::new(tx.clone(), witness.clone().into());
        (db, txaux, tx.clone(), witness.into(), secret_key)
    }

    const DEFAULT_CHAIN_ID: u8 = 0;

    #[test]
    fn existing_utxo_input_tx_should_verify() {
        let (db, txaux, _, _, _) = prepare_app_valid_tx(false);
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0.into(),
        };
        let result = verify(&txaux, extra_info, db);
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
        let (db, txaux, tx, witness, secret_key) = prepare_app_valid_tx(false);
        let extra_info = ChainInfo {
            min_fee_computed: LinearFee::new(Milli::new(1, 1), Milli::new(1, 1))
                .calculate_for_txaux(&txaux)
                .expect("invalid fee policy"),
            chain_hex_id: DEFAULT_CHAIN_ID,
            previous_block_time: 0.into(),
        };
        // WrongChainHexId
        {
            let mut extra_info = extra_info.clone();
            extra_info.chain_hex_id = DEFAULT_CHAIN_ID + 1;
            let result = verify(&txaux, extra_info, db.clone());
            expect_error(&result, Error::WrongChainHexId);
        }
        // NoInputs
        {
            let mut tx = tx.clone();
            tx.inputs.clear();
            let txaux = TxAux::TransferTx(tx, witness.clone());
            let result = verify(&txaux, extra_info, db.clone());
            expect_error(&result, Error::NoInputs);
        }
        // NoOutputs
        {
            let mut tx = tx.clone();
            tx.outputs.clear();
            let txaux = TxAux::TransferTx(tx, witness.clone());
            let result = verify(&txaux, extra_info, db.clone());
            expect_error(&result, Error::NoOutputs);
        }
        // DuplicateInputs
        {
            let mut tx = tx.clone();
            let inp = tx.inputs[0].clone();
            tx.inputs.push(inp);
            let txaux = TxAux::TransferTx(tx, witness.clone());
            let result = verify(&txaux, extra_info, db.clone());
            expect_error(&result, Error::DuplicateInputs);
        }
        // ZeroCoin
        {
            let mut tx = tx.clone();
            tx.outputs[0].value = Coin::zero();
            let txaux = TxAux::TransferTx(tx, witness.clone());
            let result = verify(&txaux, extra_info, db.clone());
            expect_error(&result, Error::ZeroCoin);
        }
        // UnexpectedWitnesses
        {
            let mut witness = witness.clone();
            let wp = witness[0].clone();
            witness.push(wp);
            let txaux = TxAux::TransferTx(tx.clone(), witness);
            let result = verify(&txaux, extra_info, db.clone());
            expect_error(&result, Error::UnexpectedWitnesses);
        }
        // MissingWitnesses
        {
            let txaux = TxAux::TransferTx(tx.clone(), vec![].into());
            let result = verify(&txaux, extra_info, db.clone());
            expect_error(&result, Error::MissingWitnesses);
        }
        // InvalidSum
        {
            let mut tx = tx.clone();
            tx.outputs[0].value = Coin::max();
            let outp = tx.outputs[0].clone();
            tx.outputs.push(outp);
            let mut witness = witness.clone();
            witness[0] = get_tx_witness(Secp256k1::new(), &tx, &secret_key);
            let txaux = TxAux::TransferTx(tx, witness);
            let result = verify(&txaux, extra_info, db.clone());
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
                &tx.inputs[0].id.as_bytes(),
                &BitVec::from_elem(1, true).to_bytes(),
            );
            db.write(inittx).unwrap();

            let result = verify(&txaux, extra_info, db.clone());
            expect_error(&result, Error::InputSpent);

            let mut reset = db.transaction();
            reset.put(
                COL_TX_META,
                &tx.inputs[0].id.as_bytes(),
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
                &tx,
                &SecretKey::from_slice(&[0x11; 32]).expect("32 bytes, within curve order"),
            );
            let txaux = TxAux::TransferTx(tx.clone(), witness);
            let result = verify(&txaux, extra_info, db.clone());
            expect_error(
                &result,
                Error::EcdsaCrypto(secp256k1::Error::InvalidPublicKey),
            );
        }
        // InvalidInput
        {
            let result = verify(&txaux, extra_info, create_db());
            expect_error(&result, Error::InvalidInput);
        }
        // InputOutputDoNotMatch
        {
            let mut tx = tx.clone();
            let mut witness = witness.clone();

            tx.outputs[0].value = (tx.outputs[0].value + Coin::one()).unwrap();
            witness[0] = get_tx_witness(Secp256k1::new(), &tx, &secret_key);
            let txaux = TxAux::TransferTx(tx, witness);
            let result = verify(&txaux, extra_info, db.clone());
            expect_error(&result, Error::InputOutputDoNotMatch);
        }
        // OutputInTimelock
        {
            let (db, txaux, _, _, _) = prepare_app_valid_tx(true);
            let result = verify(&txaux, extra_info, db.clone());
            expect_error(&result, Error::OutputInTimelock);
        }
    }

}
