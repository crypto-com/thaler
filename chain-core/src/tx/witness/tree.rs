use crate::common::HASH_SIZE_256;
use secp256k1::constants::{COMPACT_SIGNATURE_SIZE, PUBLIC_KEY_SIZE};
use secp256k1::{key::PublicKey, schnorrsig::SchnorrSignature};
use serde::de::{Deserialize, Deserializer, Error, Visitor};
use serde::ser::{Serialize, Serializer};
use std::fmt;

/// wrappers, as Rust/serde has impls for up to 32-byte arrays
/// an alternative is to use `[serde-big-array](https://crates.io/crates/serde-big-array)`
/// TODO: revisit when transaction format is more stabilized
/// TODO: custom serializers + eq etc. impls
pub type RawPubkey = (u8, [u8; PUBLIC_KEY_SIZE - 1]);
/// TODO: custom serializers + eq etc. impls
pub type RawSignature = (
    [u8; COMPACT_SIGNATURE_SIZE / 2],
    [u8; COMPACT_SIGNATURE_SIZE / 2],
);

/// conversion for custom wrappers
pub fn pk_to_raw(pk: PublicKey) -> RawPubkey {
    let compressed = &pk.serialize();
    let mut r = [0; 32];
    r.copy_from_slice(&compressed[1..PUBLIC_KEY_SIZE]);
    (compressed[0], r)
}

/// conversion for custom wrappers
pub fn sig_to_raw(sig: SchnorrSignature) -> RawSignature {
    let compressed = &sig.serialize_default();
    let mut r1 = [0; 32];
    r1.copy_from_slice(&compressed[..COMPACT_SIGNATURE_SIZE / 2]);
    let mut r2 = [0; 32];
    r2.copy_from_slice(&compressed[COMPACT_SIGNATURE_SIZE / 2..]);
    (r1, r2)
}

/// Encodes whether a left or right branch was taken
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MerklePath {
    LFound = 1,
    RFound = 2,
}

/// Contains the path taken + the other branch's hash
pub type ProofOp = (MerklePath, [u8; HASH_SIZE_256]);

impl Serialize for MerklePath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bool(*self == MerklePath::LFound)
    }
}

impl<'de> Deserialize<'de> for MerklePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MerklePathVisitor;
        impl<'de> Visitor<'de> for MerklePathVisitor {
            type Value = MerklePath;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("merkle path type")
            }

            #[inline]
            fn visit_bool<E: Error>(self, v: bool) -> Result<Self::Value, E> {
                if v {
                    Ok(MerklePath::LFound)
                } else {
                    Ok(MerklePath::RFound)
                }
            }
        }

        deserializer.deserialize_bool(MerklePathVisitor)
    }
}
