/// Transaction internal structure
pub mod data;
/// Witness structures (e.g. signatures) for transactions
pub mod witness;

use self::data::Tx;
use self::witness::TxWitness;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::fmt;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TxAux {
    /// Tx with the vector of witnesses
    TransferTx(Tx, TxWitness),
}

impl TxAux {
    /// creates a new Tx with a vector of witnesses (mainly for testing/tools)
    pub fn new(tx: Tx, witness: TxWitness) -> Self {
        TxAux::TransferTx(tx, witness)
    }
}

impl fmt::Display for TxAux {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxAux::TransferTx(tx, witness) => {
                writeln!(f, "Tx:\n{}", tx)?;
                writeln!(f, "witnesses: {:?}\n", witness)
            }
        }
    }
}

impl Encodable for TxAux {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            TxAux::TransferTx(tx, witness) => {
                s.begin_list(3).append(&0u8).append(tx).append(witness);
            }
        }
    }
}

impl Decodable for TxAux {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        // TODO: this item count will be a range once there are more TX types
        if rlp.item_count()? != 3 {
            return Err(DecoderError::Custom(
                "Cannot decode a transaction auxiliary structure",
            ));
        }
        let type_tag: u8 = rlp.val_at(0)?;
        match type_tag {
            0 => {
                let tx: Tx = rlp.val_at(1)?;
                let witness = rlp.val_at(2)?;
                Ok(TxAux::TransferTx(tx, witness))
            }
            _ => Err(DecoderError::Custom("Unknown transaction type")),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::init::coin::Coin;
    use crate::tx::data::access::{TxAccess, TxAccessPolicy};
    use crate::tx::data::address::ExtendedAddr;
    use crate::tx::data::input::TxoPointer;
    use crate::tx::data::output::TxOut;
    use crate::tx::witness::{
        tree::{MerklePath, ProofOp},
        TxInWitness,
    };
    use secp256k1::{schnorrsig::schnorr_sign, Message, PublicKey, Secp256k1, SecretKey};

    // TODO: rewrite as quickcheck prop
    #[test]
    fn encode_decode() {
        // not a valid transaction, only to test enconding-decoding
        let mut tx = Tx::new();
        tx.add_input(TxoPointer::new([0x00; 32].into(), 0));
        tx.add_input(TxoPointer::new([0x01; 32].into(), 1));
        tx.add_output(TxOut::new(
            ExtendedAddr::BasicRedeem([0xaa; 20].into()),
            Coin::unit(),
        ));
        tx.add_output(TxOut::new(
            ExtendedAddr::OrTree([0xbb; 32].into()),
            Coin::unit(),
        ));
        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[0xcc; 32][..]).expect("secret key");
        let sk2 = SecretKey::from_slice(&[0xdd; 32][..]).expect("secret key");
        tx.attributes.allowed_view.push(TxAccessPolicy::new(
            PublicKey::from_secret_key(&secp, &sk1),
            TxAccess::AllData,
        ));
        tx.attributes.allowed_view.push(TxAccessPolicy::new(
            PublicKey::from_secret_key(&secp, &sk2),
            TxAccess::Output(0),
        ));
        let msg = Message::from_slice(&tx.id().as_bytes()).expect("msg");
        let w1 = TxInWitness::BasicRedeem(secp.sign_recoverable(&msg, &sk1));
        let w2 = TxInWitness::TreeSig(
            PublicKey::from_secret_key(&secp, &sk1),
            schnorr_sign(&secp, &msg, &sk1).0,
            vec![
                ProofOp(MerklePath::LFound, [0xaa; 32].into()),
                ProofOp(MerklePath::RFound, [0xbb; 32].into()),
            ],
        );
        let txa = TxAux::TransferTx(tx, vec![w1, w2].into());
        let encoded = txa.rlp_bytes();
        let rlp = Rlp::new(&encoded);
        let decoded = TxAux::decode(&rlp).expect("decode tx aux");
        assert_eq!(txa, decoded);
    }
}
