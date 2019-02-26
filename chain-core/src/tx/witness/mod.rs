/// Witness for the initial "redeem" (ECDSA with PK recovery)
pub mod redeem;
/// Witness for Merklized Abstract Syntax Trees (MAST) + Schnorr
pub mod tree;

use common::TypeInfo;
use init::address::RedeemAddress;
use secp256k1::{
    self, constants::PUBLIC_KEY_SIZE, key::PublicKey, schnorrsig::schnorr_verify,
    schnorrsig::SchnorrSignature, Message, RecoverableSignature, RecoveryId, Secp256k1,
};
use serde::de::{Deserialize, Deserializer, EnumAccess, Error, VariantAccess, Visitor};
use serde::ser::{Serialize, Serializer};
use std::fmt;
use tx::data::address::ExtendedAddr;
use tx::data::{txid_hash, Tx};
use tx::witness::{
    redeem::EcdsaSignature,
    tree::{MerklePath, ProofOp, RawPubkey, RawSignature},
};

/// A transaction witness is a vector of input witnesses
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct TxWitness(Vec<TxInWitness>);

impl TypeInfo for TxWitness {
    #[inline]
    fn type_name() -> &'static str {
        "TxWitness"
    }
}

impl Serialize for TxWitness {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_newtype_struct(TxWitness::type_name(), &self.0)
    }
}

impl<'de> Deserialize<'de> for TxWitness {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TxWitnessVisitor;

        impl<'de> Visitor<'de> for TxWitnessVisitor {
            type Value = TxWitness;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("TX witness")
            }

            #[inline]
            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                let address_bytes = <Vec<TxInWitness>>::deserialize(deserializer);
                address_bytes.map(TxWitness)
            }
        }

        deserializer.deserialize_newtype_struct(TxWitness::type_name(), TxWitnessVisitor)
    }
}

impl TxWitness {
    /// creates an empty witness (for testing/tools)
    pub fn new() -> Self {
        TxWitness::default()
    }
}
impl From<Vec<TxInWitness>> for TxWitness {
    fn from(v: Vec<TxInWitness>) -> Self {
        TxWitness(v)
    }
}
impl ::std::iter::FromIterator<TxInWitness> for TxWitness {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = TxInWitness>,
    {
        TxWitness(Vec::from_iter(iter))
    }
}
impl ::std::ops::Deref for TxWitness {
    type Target = Vec<TxInWitness>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ::std::ops::DerefMut for TxWitness {
    fn deref_mut(&mut self) -> &mut Vec<TxInWitness> {
        &mut self.0
    }
}

// normally should be some structure: e.g. indicate a type of signature
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TxInWitness {
    BasicRedeem(EcdsaSignature),
    TreeSig(RawPubkey, RawSignature, Vec<ProofOp>),
}

impl fmt::Display for TxInWitness {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TypeInfo for TxInWitness {
    #[inline]
    fn type_name() -> &'static str {
        "TxInWitness"
    }
}

impl Serialize for TxInWitness {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            TxInWitness::BasicRedeem(ref sig) => serializer.serialize_newtype_variant(
                TxInWitness::type_name(),
                0,
                "BasicRedeem",
                sig,
            ),
            TxInWitness::TreeSig(pk, sig, ops) => serializer.serialize_newtype_variant(
                TxInWitness::type_name(),
                1,
                "TreeSig",
                &(pk, sig, ops),
            ),
        }
    }
}

impl<'de> Deserialize<'de> for TxInWitness {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TxInWitnessVisitor;
        impl<'de> Visitor<'de> for TxInWitnessVisitor {
            type Value = TxInWitness;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("transaction input witness")
            }

            #[inline]
            fn visit_enum<A>(self, deserializer: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                match deserializer.variant::<u64>() {
                    Ok((0, v)) => VariantAccess::newtype_variant::<EcdsaSignature>(v)
                        .map(TxInWitness::BasicRedeem),
                    Ok((1, v)) => {
                        VariantAccess::newtype_variant::<(RawPubkey, RawSignature, Vec<ProofOp>)>(v)
                            .map(|(pk, sig, ops)| TxInWitness::TreeSig(pk, sig, ops))
                    }
                    Ok((i, _)) => Err(A::Error::unknown_variant(
                        &i.to_string(),
                        &["BasicRedeem", "TreeSig"],
                    )),
                    Err(e) => Err(e),
                }
            }
        }

        deserializer.deserialize_enum(
            TxInWitness::type_name(),
            &["BasicRedeem", "TreeSig"],
            TxInWitnessVisitor,
        )
    }
}

impl TxInWitness {
    /// verify a given extended address is associated to the witness
    /// and the signature against the given transation `Tx`
    /// TODO: capture possible errors in enum
    ///
    pub fn verify_tx_address(
        &self,
        tx: &Tx,
        address: &ExtendedAddr,
    ) -> Result<(), secp256k1::Error> {
        let secp = Secp256k1::verification_only();
        let message = Message::from_slice(&tx.id())?;
        match (&self, address) {
            (TxInWitness::BasicRedeem(sig), ExtendedAddr::BasicRedeem(addr)) => {
                let mut sign = Vec::new();
                sign.extend(&sig.r);
                sign.extend(&sig.s);
                let ri = RecoveryId::from_i32(i32::from(sig.v))?;
                let rk = RecoverableSignature::from_compact(&sign, ri)?;
                let pk = secp.recover(&message, &rk)?;
                let expected_addr = RedeemAddress::from(&pk).0;
                // TODO: constant time eq?
                if *addr != expected_addr {
                    Err(secp256k1::Error::InvalidPublicKey)
                } else {
                    secp.verify(&message, &rk.to_standard(), &pk)
                }
            }
            (TxInWitness::TreeSig(pk, sig, ops), ExtendedAddr::OrTree(roothash)) => {
                let mut pk_vec = Vec::with_capacity(PUBLIC_KEY_SIZE);
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
                // TODO: constant time eq?
                if pk_hash != *roothash {
                    Err(secp256k1::Error::InvalidPublicKey)
                // TODO: migrate to upstream secp256k1 when Schnorr is available
                } else {
                    let dpk = PublicKey::from_slice(&pk_vec)?;
                    let mut sig_vec = Vec::from(&sig.0[..]);
                    sig_vec.extend(&sig.1);
                    let dsig = SchnorrSignature::from_default(&sig_vec)?;
                    schnorr_verify(&secp, &message, &dsig, &dpk)
                }
            }
            (_, _) => Err(secp256k1::Error::InvalidSignature),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use common::merkle::MerkleTree;
    use common::HASH_SIZE_256;
    use secp256k1::{
        key::pubkey_combine,
        key::PublicKey,
        key::SecretKey,
        musig::{MuSigSession, MuSigSessionID},
        schnorrsig::{schnorr_sign, SchnorrSignature},
        Message, Secp256k1, Signing, Verification,
    };
    use tx::data::txid_hash;
    use tx::witness::tree::{pk_to_raw, sig_to_raw, MerklePath};

    pub fn get_ecdsa_witness<C: Signing>(
        secp: &Secp256k1<C>,
        tx: &Tx,
        secret_key: SecretKey,
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
        secret_key: SecretKey,
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
        let witness1 = get_ecdsa_witness(&secp, &tx, secret_key);
        assert!(witness1.verify_tx_address(&tx, &expected_addr1).is_err());
        let expected_addr2 = ExtendedAddr::BasicRedeem(RedeemAddress::from(&public_key).0);
        let (witness2, _) = get_single_tx_witness(secp, &tx, secret_key);
        assert!(witness2.verify_tx_address(&tx, &expected_addr2).is_err());
    }

    #[test]
    fn signed_tx_should_verify() {
        let tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let expected_addr = ExtendedAddr::BasicRedeem(RedeemAddress::from(&public_key).0);
        let witness = get_ecdsa_witness(&secp, &tx, secret_key);
        assert!(witness.verify_tx_address(&tx, &expected_addr).is_ok());
    }

    #[test]
    fn schnorr_signed_tx_should_verify() {
        let tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let (witness, addr) = get_single_tx_witness(secp, &tx, secret_key);
        let expected_addr = ExtendedAddr::OrTree(addr);
        let r = witness.verify_tx_address(&tx, &expected_addr);
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
        assert!(witness.verify_tx_address(&tx, &expected_addr).is_ok());
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
        assert!(witness.verify_tx_address(&tx, &expected_addr).is_ok());
    }

    #[test]
    fn wrong_basic_address_should_fail() {
        let tx = Tx::new();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");

        let witness = get_ecdsa_witness(&secp, &tx, secret_key);
        let wrong_addr = ExtendedAddr::BasicRedeem(RedeemAddress::default().0);
        assert!(witness.verify_tx_address(&tx, &wrong_addr).is_err());
    }

    #[test]
    fn wrongly_basic_signed_tx_should_fail() {
        let tx = Tx::new();
        let sign = EcdsaSignature::default();
        let witness = TxInWitness::BasicRedeem(sign);
        let addr = ExtendedAddr::BasicRedeem(RedeemAddress::default().0);
        assert!(witness.verify_tx_address(&tx, &addr).is_err());
    }

}
