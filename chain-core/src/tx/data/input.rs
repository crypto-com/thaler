use std::fmt;

use parity_scale_codec::{Decode, Encode, Error, Input, Output};
#[cfg(not(feature = "mesalock_sgx"))]
use serde::de::{
    self,
    value::{Error as ValueError, StrDeserializer},
    IntoDeserializer,
};
#[cfg(not(feature = "mesalock_sgx"))]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::tx::data::TxId;

/// the type for transaction output size or index
pub type TxoSize = u16;

/// Structure used for addressing a specific output of a transaction
/// built from a TxId (hash of the tx) and the offset in the outputs of this
/// transaction.
#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone)]
#[cfg_attr(not(feature = "mesalock_sgx"), derive(Serialize, Deserialize))]
pub struct TxoPointer {
    /// the previous transaction identifier
    #[cfg_attr(
        not(feature = "mesalock_sgx"),
        serde(serialize_with = "serialize_transaction_id")
    )]
    #[cfg_attr(
        not(feature = "mesalock_sgx"),
        serde(deserialize_with = "deserialize_transaction_id")
    )]
    pub id: TxId,
    /// the output index in the previous transaction
    pub index: TxoSize,
}

impl Encode for TxoPointer {
    fn encode_to<EncOut: Output>(&self, dest: &mut EncOut) {
        dest.push(&self.id);
        dest.push(&self.index);
    }

    fn size_hint(&self) -> usize {
        self.id.size_hint() + self.index.size_hint()
    }
}

impl Decode for TxoPointer {
    fn decode<DecIn: Input>(input: &mut DecIn) -> Result<Self, Error> {
        let txid = TxId::decode(input)?;
        let index = TxoSize::decode(input)?;
        Ok(TxoPointer { id: txid, index })
    }
}

#[cfg(not(feature = "mesalock_sgx"))]
fn serialize_transaction_id<S>(
    transaction_id: &TxId,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(transaction_id))
}

#[cfg(not(feature = "mesalock_sgx"))]
fn deserialize_transaction_id<'de, D>(deserializer: D) -> std::result::Result<TxId, D::Error>
where
    D: Deserializer<'de>,
{
    struct StrVisitor;

    impl<'de> de::Visitor<'de> for StrVisitor {
        type Value = TxId;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("transaction id in hexadecimal string")
        }

        #[inline]
        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            let transaction_id_vec =
                hex::decode(value).map_err(|err| de::Error::custom(err.to_string()))?;
            if transaction_id_vec.len() != 32 {
                return Err(de::Error::custom(format!(
                    "Invalid transaction id length: {}",
                    transaction_id_vec.len()
                )));
            }

            let mut transaction_id = [0; 32];
            transaction_id.copy_from_slice(&transaction_id_vec);

            Ok(transaction_id)
        }
    }

    deserializer.deserialize_str(StrVisitor)
}

impl fmt::Display for TxoPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}@{}", self.id, self.index)
    }
}

impl TxoPointer {
    /// Constructs a new TX input (mainly for testing/tools).
    pub fn new(id: TxId, index: usize) -> Self {
        TxoPointer {
            id,
            index: index as TxoSize,
        }
    }
}

/// converts transaction ID from hex string?
#[cfg(not(feature = "mesalock_sgx"))]
pub fn str2txid<S: AsRef<str>>(s: S) -> Result<TxId, ValueError> {
    let deserializer: StrDeserializer<ValueError> = s.as_ref().into_deserializer();
    deserialize_transaction_id(deserializer)
}
