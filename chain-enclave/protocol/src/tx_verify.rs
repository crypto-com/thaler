use crate::Error;
use chain_core::common::Timespec;
use chain_core::init::address::{keccak256, to_arr, RedeemAddressRaw};
use chain_core::init::coin::Coin;
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::{txid_hash, Tx};
use chain_core::tx::witness::{tree::MerklePath, TxInWitness};
use chain_core::tx::TxAux;
use libsecp256k1::{
    curve::Scalar,
    recover,
    schnorr::{schnorr_verify, SchnorrSignature},
    util::COMPRESSED_PUBLIC_KEY_SIZE,
    verify, Message, PublicKey, PublicKeyFormat, RecoveryId, Signature,
};
use std::collections::BTreeSet;

#[inline]
fn get_recovery_id(rid: u8) -> Result<RecoveryId, Error> {
    match RecoveryId::parse(rid) {
        Ok(r) => Ok(r),
        Err(_) => Err(Error::WitnessVerificationFailed),
    }
}

#[inline]
fn recover_pk(message: &Message, sign: &Signature, ri: RecoveryId) -> Result<PublicKey, Error> {
    match recover(message, sign, &ri) {
        Ok(r) => Ok(r),
        Err(_) => Err(Error::WitnessVerificationFailed),
    }
}

#[inline]
fn parse_pk(pk_vec: &[u8]) -> Result<PublicKey, Error> {
    match PublicKey::parse_slice(pk_vec, Some(PublicKeyFormat::Compressed)) {
        Ok(r) => Ok(r),
        Err(_) => Err(Error::WitnessVerificationFailed),
    }
}

#[inline]
fn to_address(pk: &PublicKey) -> RedeemAddressRaw {
    let hash = keccak256(&pk.serialize()[1..]);
    to_arr(&hash[12..])
}

/// verify a given extended address is associated to the witness
/// and the signature against the given transation `Tx`
/// TODO: capture possible errors in enum?
///
pub fn verify_tx_address(
    witness: &TxInWitness,
    tx: &Tx,
    address: &ExtendedAddr,
) -> Result<(), Error> {
    let message = Message::parse(&tx.id());
    match (witness, address) {
        (TxInWitness::BasicRedeem(sig), ExtendedAddr::BasicRedeem(addr)) => {
            let mut r = Scalar::default();
            let _ = r.set_b32(&sig.r);
            let mut s = Scalar::default();
            let _ = s.set_b32(&sig.s);
            let sign = Signature { r, s };
            let ri = get_recovery_id(sig.v)?;
            let pk = recover_pk(&message, &sign, ri)?;
            let expected_addr = to_address(&pk);
            // TODO: constant time eq?
            if *addr != expected_addr || !verify(&message, &sign, &pk) {
                Err(Error::WitnessVerificationFailed)
            } else {
                Ok(())
            }
        }
        (TxInWitness::TreeSig(pk, sig, ops), ExtendedAddr::OrTree(roothash)) => {
            let mut pk_vec = Vec::with_capacity(COMPRESSED_PUBLIC_KEY_SIZE);
            pk_vec.push(pk.0);
            pk_vec.extend(&pk.1);
            let mut pk_hash = txid_hash(&pk_vec);
            // TODO: blake2 tree hashing?
            for op in ops.iter() {
                let mut bs = vec![1u8];
                match op {
                    (MerklePath::LFound, data) => {
                        bs.extend(&pk_hash[..]);
                        bs.extend(&data[..]);
                        pk_hash = txid_hash(&bs);
                    }
                    (MerklePath::RFound, data) => {
                        bs.extend(&data[..]);
                        bs.extend(&pk_hash[..]);
                        pk_hash = txid_hash(&bs);
                    }
                }
            }
            let dpk = parse_pk(&pk_vec)?;
            let mut r = Scalar::default();
            let _ = r.set_b32(&sig.0);
            let mut s = Scalar::default();
            let _ = s.set_b32(&sig.1);
            let dsig = SchnorrSignature { r, s };
            // TODO: constant time eq?
            // TODO: migrate to upstream secp256k1 when Schnorr is available
            if pk_hash != *roothash || !schnorr_verify(&message, &dsig, &dpk) {
                Err(Error::WitnessVerificationFailed)
            } else {
                Ok(())
            }
        }
        (_, _) => Err(Error::WitnessVerificationFailed),
    }
}

fn verify_in_place(txaux: &TxAux, chain_hex_id: u8) -> Result<Coin, Error> {
    // TODO: check other attributes?
    // check that chain IDs match
    if chain_hex_id != txaux.tx.attributes.chain_hex_id {
        return Err(Error::WrongChainHexId);
    }
    // check that there are inputs
    if txaux.tx.inputs.is_empty() {
        return Err(Error::NoInputs);
    }

    // check that there are outputs
    if txaux.tx.outputs.is_empty() {
        return Err(Error::NoOutputs);
    }

    // check that there are no duplicate inputs
    let mut inputs = BTreeSet::new();
    if !txaux.tx.inputs.iter().all(|x| inputs.insert(x)) {
        return Err(Error::DuplicateInputs);
    }

    // check that all outputs have a non-zero amount
    if !txaux.tx.outputs.iter().all(|x| x.value > Coin::zero()) {
        return Err(Error::ZeroCoin);
    }

    // Note: we don't need to check against MAX_COIN because Coin's
    // constructor should already do it.

    // TODO: check address attributes?

    // verify transaction witnesses
    if txaux.tx.inputs.len() < txaux.witness.len() {
        return Err(Error::UnexpectedWitnesses);
    }

    if txaux.tx.inputs.len() > txaux.witness.len() {
        return Err(Error::MissingWitnesses);
    }
    let outsum = txaux.tx.get_output_total();
    if outsum.is_err() {
        return Err(Error::InvalidSum(outsum.unwrap_err()));
    }
    Ok(outsum.unwrap())
}

/// Checks TX against the current DB and returns an `Error` if something fails.
/// TODO: check Redeem addresses are never in outputs?
pub fn verify_with_storage(
    txaux: &TxAux,
    inputs: Vec<Tx>,
    chain_hex_id: u8,
    block_time: Timespec,
) -> Result<(), Error> {
    let outcoins = verify_in_place(txaux, chain_hex_id)?;
    let mut incoins = Coin::zero();

    // verify that txids of inputs correspond to the owner/signer
    // and it'd check they are not spent
    for (tx, (txin, in_witness)) in inputs
        .iter()
        .zip(txaux.tx.inputs.iter().zip(txaux.witness.iter()))
    {
        if tx.id() != txin.id || txin.index >= tx.outputs.len() {
            return Err(Error::InvalidInput);
        }
        let txout = &tx.outputs[txin.index];
        match txout.valid_from {
            Some(valid_from) if valid_from > block_time => {
                return Err(Error::OutputInTimelock);
            }
            _ => {}
        }

        verify_tx_address(&in_witness, &txaux.tx, &txout.address)?;

        let sum = incoins + txout.value;
        if sum.is_err() {
            return Err(Error::InvalidSum(sum.unwrap_err()));
        } else {
            incoins = sum.unwrap();
        }
    }
    // check sum(input amounts) == sum(output amounts)
    // TODO: do we allow "burn"? i.e. sum(input amounts) >= sum(output amounts)
    if incoins != outcoins {
        return Err(Error::InputOutputDoNotMatch);
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use chain_core::common::merkle::MerkleTree;
    use chain_core::common::HASH_SIZE_256;
    use chain_core::init::address::RedeemAddress;
    use chain_core::tx::data::txid_hash;
    use chain_core::tx::witness::redeem::EcdsaSignature;
    use chain_core::tx::witness::tree::{pk_to_raw, sig_to_raw, MerklePath, ProofOp};
    use secp256k1::{
        key::pubkey_combine,
        key::PublicKey,
        key::SecretKey,
        musig::{MuSigSession, MuSigSessionID},
        schnorrsig::{schnorr_sign, SchnorrSignature},
        Message, Secp256k1, Signing, Verification,
    };

    pub fn get_ecdsa_witness<C: Signing>(
        secp: &Secp256k1<C>,
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

    fn sign_single_schnorr<C: Signing>(
        secp: &Secp256k1<C>,
        msg: &Message,
        secret_key: &SecretKey,
    ) -> SchnorrSignature {
        schnorr_sign(secp, msg, secret_key).0
    }

    fn get_single_tx_witness<C: Signing>(
        secp: Secp256k1<C>,
        tx: &Tx,
        secret_key: &SecretKey,
    ) -> (TxInWitness, [u8; HASH_SIZE_256]) {
        let message = Message::from_slice(&tx.id()).expect("32 bytes");
        let sig = sign_single_schnorr(&secp, &message, &secret_key);
        let pk = PublicKey::from_secret_key(&secp, &secret_key);

        let pk_hash = txid_hash(&pk.serialize());
        let merkle = MerkleTree::new(&vec![pk_hash]);

        return (
            TxInWitness::TreeSig(pk_to_raw(pk), sig_to_raw(sig), vec![]),
            merkle.get_root_hash(),
        );
    }

    fn get_2_of_2_sig<C: Signing + Verification>(
        secp: &Secp256k1<C>,
        tx: &Tx,
        secret_key1: SecretKey,
        secret_key2: SecretKey,
    ) -> (SchnorrSignature, PublicKey, PublicKey) {
        let message = Message::from_slice(&tx.id()).expect("32 bytes");
        let pk1 = PublicKey::from_secret_key(&secp, &secret_key1);
        let pk2 = PublicKey::from_secret_key(&secp, &secret_key2);
        let session_id1 = MuSigSessionID::from_slice(&[0x01; 32]).expect("32 bytes");
        let session_id2 = MuSigSessionID::from_slice(&[0x02; 32]).expect("32 bytes");
        let (pk, pk_hash) = pubkey_combine(secp, &vec![pk1, pk2]).expect("combined pk");
        let mut session1 = MuSigSession::new(
            secp,
            session_id1,
            &message,
            &pk,
            &pk_hash,
            2,
            0,
            &secret_key1,
        )
        .expect("session 1");
        let mut session2 = MuSigSession::new(
            secp,
            session_id2,
            &message,
            &pk,
            &pk_hash,
            2,
            1,
            &secret_key2,
        )
        .expect("session 2");
        session1.set_nonce_commitment(session2.get_my_nonce_commitment(), 1);
        session2.set_nonce_commitment(session1.get_my_nonce_commitment(), 0);
        let nonces = vec![
            session1.get_public_nonce().unwrap(),
            session2.get_public_nonce().unwrap(),
        ];
        for i in 0..nonces.len() {
            let nonce = nonces[i];
            session1.set_nonce(i, nonce).expect("nonce in session1");
            session2.set_nonce(i, nonce).expect("nonce in session2");
        }
        session1.combine_nonces().expect("combined nonces session1");
        session2.combine_nonces().expect("combined nonces session2");
        let partial_sigs = vec![
            session1.partial_sign().expect("partial signature 1"),
            session2.partial_sign().expect("partial signature 2"),
        ];
        let sig = session1
            .partial_sig_combine(&partial_sigs)
            .expect("combined signature");
        return (sig, pk1, pk2);
    }

    fn get_2_of_2_tx_witness<C: Signing + Verification>(
        secp: Secp256k1<C>,
        tx: &Tx,
        secret_key1: SecretKey,
        secret_key2: SecretKey,
    ) -> (TxInWitness, [u8; HASH_SIZE_256]) {
        let (sig, pk1, pk2) = get_2_of_2_sig(&secp, tx, secret_key1, secret_key2);

        let pk = pubkey_combine(&secp, &vec![pk1, pk2]).unwrap().0;
        let pk_hash = txid_hash(&pk.serialize());
        let merkle = MerkleTree::new(&vec![pk_hash]);

        return (
            TxInWitness::TreeSig(pk_to_raw(pk), sig_to_raw(sig), vec![]),
            merkle.get_root_hash(),
        );
    }

    fn get_2_of_3_tx_witness<C: Signing + Verification>(
        secp: Secp256k1<C>,
        tx: &Tx,
        secret_key1: SecretKey,
        secret_key2: SecretKey,
        secret_key3: SecretKey,
    ) -> (TxInWitness, [u8; HASH_SIZE_256]) {
        let pk1 = PublicKey::from_secret_key(&secp, &secret_key1);
        let pk2 = PublicKey::from_secret_key(&secp, &secret_key2);
        let pk3 = PublicKey::from_secret_key(&secp, &secret_key3);
        let pkc1 = pubkey_combine(&secp, &vec![pk1, pk2]).unwrap().0;
        let pkc2 = pubkey_combine(&secp, &vec![pk1, pk3]).unwrap().0;
        let pkc3 = pubkey_combine(&secp, &vec![pk2, pk3]).unwrap().0;
        let pk_hashes: Vec<[u8; 32]> = vec![pkc1, pkc2, pkc3]
            .iter()
            .map(|x| txid_hash(&x.serialize()))
            .collect();
        let merkle = MerkleTree::new(&pk_hashes);

        let path: Vec<ProofOp> = vec![
            (MerklePath::LFound, pk_hashes[1]),
            (MerklePath::LFound, pk_hashes[2]),
        ];

        let (sig, _, _) = get_2_of_2_sig(&secp, tx, secret_key1, secret_key2);

        return (
            TxInWitness::TreeSig(pk_to_raw(pkc1), sig_to_raw(sig), path),
            merkle.get_root_hash(),
        );
    }

    #[test]
    fn mismatched_signed_tx_should_fail() {
        let tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let expected_addr1 = ExtendedAddr::OrTree([0x00; 32]);
        let witness1 = get_ecdsa_witness(&secp, &tx, &secret_key);
        assert!(verify_tx_address(&witness1, &tx, &expected_addr1).is_err());
        let expected_addr2 = ExtendedAddr::BasicRedeem(RedeemAddress::from(&public_key).0);
        let (witness2, _) = get_single_tx_witness(secp, &tx, &secret_key);
        assert!(verify_tx_address(&witness2, &tx, &expected_addr2).is_err());
    }

    #[test]
    fn signed_tx_should_verify() {
        let tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let expected_addr = ExtendedAddr::BasicRedeem(RedeemAddress::from(&public_key).0);
        let witness = get_ecdsa_witness(&secp, &tx, &secret_key);
        assert!(verify_tx_address(&witness, &tx, &expected_addr).is_ok());
    }

    #[test]
    fn schnorr_signed_tx_should_verify() {
        let tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let (witness, addr) = get_single_tx_witness(secp, &tx, &secret_key);
        let expected_addr = ExtendedAddr::OrTree(addr);
        let r = verify_tx_address(&witness, &tx, &expected_addr);
        assert!(r.is_ok());
    }

    #[test]
    fn agg_schnorr_signed_tx_should_verify() {
        let tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key1 = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let secret_key2 = SecretKey::from_slice(&[0xde; 32]).expect("32 bytes, within curve order");
        let (witness, addr) = get_2_of_2_tx_witness(secp, &tx, secret_key1, secret_key2);
        let expected_addr = ExtendedAddr::OrTree(addr);
        assert!(verify_tx_address(&witness, &tx, &expected_addr).is_ok());
    }

    #[test]
    fn tree_agg_schnorr_signed_tx_should_verify() {
        let tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key1 = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let secret_key2 = SecretKey::from_slice(&[0xde; 32]).expect("32 bytes, within curve order");
        let secret_key3 = SecretKey::from_slice(&[0xef; 32]).expect("32 bytes, within curve order");
        let (witness, addr) =
            get_2_of_3_tx_witness(secp, &tx, secret_key1, secret_key2, secret_key3);
        let expected_addr = ExtendedAddr::OrTree(addr);
        assert!(verify_tx_address(&witness, &tx, &expected_addr).is_ok());
    }

    #[test]
    fn wrong_basic_address_should_fail() {
        let tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");

        let witness = get_ecdsa_witness(&secp, &tx, &secret_key);
        let wrong_addr = ExtendedAddr::BasicRedeem(RedeemAddress::default().0);
        assert!(verify_tx_address(&witness, &tx, &wrong_addr).is_err());
    }

    #[test]
    fn wrongly_basic_signed_tx_should_fail() {
        let tx = Tx::new();
        let sign = EcdsaSignature::default();
        let witness = TxInWitness::BasicRedeem(sign);
        let addr = ExtendedAddr::BasicRedeem(RedeemAddress::default().0);
        assert!(verify_tx_address(&witness, &tx, &addr).is_err());
    }

}
