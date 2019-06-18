use chain_core::init::address::RedeemAddress;
use chain_core::state::account::{StakedStateAddress, StakedStateOpWitness};
use chain_core::tx::data::address::ExtendedAddr;
use chain_core::tx::data::TxId;
use chain_core::tx::witness::TxInWitness;
use secp256k1::{schnorrsig::schnorr_verify, Message, PublicKey, Secp256k1};

/// verify a given extended address is associated to the witness
/// and the signature against the given transation `Tx`
/// TODO: capture possible errors in enum?
///
pub fn verify_tx_address(
    witness: &TxInWitness,
    txid: &TxId,
    address: &ExtendedAddr,
) -> Result<(), secp256k1::Error> {
    let secp = Secp256k1::verification_only();
    let message = Message::from_slice(&txid[..])?;

    match (witness, address) {
        (TxInWitness::BasicRedeem(sig), ExtendedAddr::BasicRedeem(addr)) => {
            let pk = secp.recover(&message, &sig)?;
            let expected_addr = RedeemAddress::from(&pk);
            // TODO: constant time eq?
            if *addr != expected_addr {
                Err(secp256k1::Error::InvalidPublicKey)
            } else {
                secp.verify(&message, &sig.to_standard(), &pk)
            }
        }
        (TxInWitness::TreeSig(sig, proof), ExtendedAddr::OrTree(root_hash)) => {
            if !proof.verify(root_hash) {
                Err(secp256k1::Error::InvalidPublicKey)
            } else {
                schnorr_verify(
                    &secp,
                    &message,
                    &sig,
                    &PublicKey::from_slice(proof.value().as_bytes())?,
                )
            }
        }
        (_, _) => Err(secp256k1::Error::InvalidSignature),
    }
}

/// verify the signature against the given transation `Tx`
/// and recovers the address from it
///
pub fn verify_tx_recover_address(
    witness: &StakedStateOpWitness,
    txid: &TxId,
) -> Result<StakedStateAddress, secp256k1::Error> {
    match witness {
        StakedStateOpWitness::BasicRedeem(sig) => {
            let secp = Secp256k1::verification_only();
            let message = Message::from_slice(txid)?;
            let pk = secp.recover(&message, &sig)?;
            secp.verify(&message, &sig.to_standard(), &pk)?;
            Ok(StakedStateAddress::BasicRedeem(RedeemAddress::from(&pk)))
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use chain_core::common::{MerkleTree, H256};
    use chain_core::tx::data::Tx;
    use chain_core::tx::witness::{tree::RawPubkey, TxInWitness, TxWitness};
    use chain_core::tx::TransactionId;
    use parity_codec::{Decode, Encode};
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
        return TxInWitness::BasicRedeem(sig);
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
    ) -> (TxInWitness, H256) {
        let message = Message::from_slice(&tx.id()).expect("32 bytes");
        let sig = sign_single_schnorr(&secp, &message, &secret_key);
        let pk = PublicKey::from_secret_key(&secp, &secret_key);
        let raw_pk = RawPubkey::from(pk.serialize());

        let public_keys = vec![raw_pk];

        let merkle = MerkleTree::new(public_keys.clone());

        return (
            TxInWitness::TreeSig(sig, merkle.generate_proof(public_keys[0].clone()).unwrap()),
            merkle.root_hash(),
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
        let (pk, pk_hash) =
            pubkey_combine(secp, &vec![pk1.clone(), pk2.clone()]).expect("combined pk");
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
            let nonce = &nonces[i];
            session1
                .set_nonce(i, nonce.clone())
                .expect("nonce in session1");
            session2
                .set_nonce(i, nonce.clone())
                .expect("nonce in session2");
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
    ) -> (TxInWitness, H256) {
        let (sig, pk1, pk2) = get_2_of_2_sig(&secp, tx, secret_key1, secret_key2);

        let pk = pubkey_combine(&secp, &vec![pk1, pk2]).unwrap().0;
        let raw_pk = RawPubkey::from(pk.serialize());
        let public_keys = vec![raw_pk];

        let merkle = MerkleTree::new(public_keys.clone());

        return (
            TxInWitness::TreeSig(sig, merkle.generate_proof(public_keys[0].clone()).unwrap()),
            merkle.root_hash(),
        );
    }

    fn get_2_of_3_tx_witness<C: Signing + Verification>(
        secp: Secp256k1<C>,
        tx: &Tx,
        secret_key1: SecretKey,
        secret_key2: SecretKey,
        secret_key3: SecretKey,
    ) -> (TxInWitness, H256) {
        let pk1 = PublicKey::from_secret_key(&secp, &secret_key1);
        let pk2 = PublicKey::from_secret_key(&secp, &secret_key2);
        let pk3 = PublicKey::from_secret_key(&secp, &secret_key3);

        let pkc1 = pubkey_combine(&secp, &vec![pk1.clone(), pk2.clone()])
            .unwrap()
            .0;
        let pkc2 = pubkey_combine(&secp, &vec![pk1.clone(), pk3.clone()])
            .unwrap()
            .0;
        let pkc3 = pubkey_combine(&secp, &vec![pk2.clone(), pk3.clone()])
            .unwrap()
            .0;

        let public_keys: Vec<RawPubkey> = vec![pkc1, pkc2, pkc3]
            .iter()
            .map(|x| RawPubkey::from(x.serialize()))
            .collect();

        let merkle = MerkleTree::new(public_keys.clone());
        let proof = merkle.generate_proof(public_keys[0].clone()).unwrap();

        let (sig, _, _) = get_2_of_2_sig(&secp, tx, secret_key1, secret_key2);

        return (TxInWitness::TreeSig(sig, proof), merkle.root_hash());
    }

    #[test]
    fn mismatched_signed_tx_should_fail() {
        let tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let expected_addr1 = ExtendedAddr::OrTree([0x00; 32].into());
        let witness1 = get_ecdsa_witness(&secp, &tx, &secret_key);
        assert!(verify_tx_address(&witness1, &tx.id(), &expected_addr1).is_err());
        let expected_addr2 = ExtendedAddr::BasicRedeem(RedeemAddress::from(&public_key));
        let (witness2, _) = get_single_tx_witness(secp, &tx, &secret_key);
        assert!(verify_tx_address(&witness2, &tx.id(), &expected_addr2).is_err());
    }

    #[test]
    fn same_pk_recovered() {
        let tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let witness: TxWitness = vec![get_ecdsa_witness(&secp, &tx, &secret_key)].into();
        let mut encoded = witness.encode();
        let mut data: &[u8] = encoded.as_mut();
        let decoded = TxWitness::decode(&mut data).expect("decode tx witness");
        match &decoded[0] {
            TxInWitness::BasicRedeem(sig) => {
                let message = Message::from_slice(&tx.id()).expect("32 bytes");
                let pk = secp.recover(&message, &sig).unwrap();
                assert_eq!(pk, public_key);
            }
            _ => {
                assert!(false);
            }
        }
    }

    #[test]
    fn signed_tx_should_verify() {
        let tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let expected_addr = ExtendedAddr::BasicRedeem(RedeemAddress::from(&public_key));
        let witness = get_ecdsa_witness(&secp, &tx, &secret_key);
        assert!(verify_tx_address(&witness, &tx.id(), &expected_addr).is_ok());
    }

    #[test]
    fn schnorr_signed_tx_should_verify() {
        let tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let (witness, addr) = get_single_tx_witness(secp, &tx, &secret_key);
        let expected_addr = ExtendedAddr::OrTree(addr);
        let r = verify_tx_address(&witness, &tx.id(), &expected_addr);
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
        assert!(verify_tx_address(&witness, &tx.id(), &expected_addr).is_ok());
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
        assert!(verify_tx_address(&witness, &tx.id(), &expected_addr).is_ok());
    }

    #[test]
    fn wrong_basic_address_should_fail() {
        let tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");

        let witness = get_ecdsa_witness(&secp, &tx, &secret_key);
        let wrong_addr = ExtendedAddr::BasicRedeem(RedeemAddress::default());
        assert!(verify_tx_address(&witness, &tx.id(), &wrong_addr).is_err());
    }

    #[test]
    fn wrongly_basic_signed_tx_should_fail() {
        let tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let message = Message::from_slice(&[0xaa; 32]).expect("32 bytes");
        let sign = secp.sign_recoverable(&message, &secret_key);
        let witness = TxInWitness::BasicRedeem(sign);
        let addr = ExtendedAddr::BasicRedeem(RedeemAddress::default());
        assert!(verify_tx_address(&witness, &tx.id(), &addr).is_err());
    }

}
