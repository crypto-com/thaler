/// Transaction internal structure
pub mod data;
/// Transaction fee calculation
pub mod fee;
/// Witness structures (e.g. signatures) for transactions
pub mod witness;

use std::fmt;

use parity_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use self::data::Tx;
use self::witness::TxWitness;
use crate::state::account::{AccountOpWitness, DepositBondTx, UnbondTx, WithdrawUnbondedTx};
use crate::tx::data::{txid_hash, TxId};

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, Encode, Decode)]
/// TODO: custom Encode/Decode when data structures are finalized (for backwards/forwards compatibility, encoders/decoders should be able to work with old formats)
pub enum TxAux {
    /// normal value transfer Tx with the vector of witnesses
    TransferTx(Tx, TxWitness),
    /// Tx "spends" utxos to be deposited as bonded stake in an account (witnesses as in transfer)
    DepositStakeTx(DepositBondTx, TxWitness),
    /// Tx that modifies account state -- moves some bonded stake into unbonded (witness for account)
    UnbondStakeTx(UnbondTx, AccountOpWitness),
    /// Tx that "creates" utxos out of account state; withdraws unbonded stake (witness for account)
    WithdrawUnbondedStakeTx(WithdrawUnbondedTx, AccountOpWitness),
}

pub trait TransactionId: Encode {
    /// retrieves a TX ID (currently blake2s(scale_codec_bytes(tx)))
    fn id(&self) -> TxId {
        txid_hash(&self.encode())
    }
}

impl TxAux {
    /// creates a new Tx with a vector of witnesses (mainly for testing/tools)
    pub fn new(tx: Tx, witness: TxWitness) -> Self {
        TxAux::TransferTx(tx, witness)
    }

    /// retrieves a TX ID (currently blake2s(scale_codec_bytes(tx)))
    pub fn tx_id(&self) -> TxId {
        match self {
            TxAux::TransferTx(tx, _) => tx.id(),
            TxAux::DepositStakeTx(tx, _) => tx.id(),
            TxAux::UnbondStakeTx(tx, _) => tx.id(),
            TxAux::WithdrawUnbondedStakeTx(tx, _) => tx.id(),
        }
    }
}

fn display_tx_witness<T: fmt::Display, W: fmt::Debug>(
    f: &mut fmt::Formatter<'_>,
    tx: T,
    witness: W,
) -> fmt::Result {
    writeln!(f, "Tx:\n{}", tx)?;
    writeln!(f, "witnesses: {:?}\n", witness)
}

impl fmt::Display for TxAux {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxAux::TransferTx(tx, witness) => display_tx_witness(f, tx, witness),
            TxAux::DepositStakeTx(tx, witness) => display_tx_witness(f, tx, witness),
            TxAux::UnbondStakeTx(tx, witness) => display_tx_witness(f, tx, witness),
            TxAux::WithdrawUnbondedStakeTx(tx, witness) => display_tx_witness(f, tx, witness),
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
    use parity_codec::{Decode, Encode};
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
        let msg = Message::from_slice(&tx.id()).expect("msg");
        let w1 = TxInWitness::BasicRedeem(secp.sign_recoverable(&msg, &sk1));
        let w2 = TxInWitness::TreeSig(
            PublicKey::from_secret_key(&secp, &sk1),
            schnorr_sign(&secp, &msg, &sk1).0,
            vec![
                ProofOp(MerklePath::LFound, [0xaa; 32].into()),
                ProofOp(MerklePath::RFound, [0xbb; 32].into()),
            ],
        );
        assert_eq!(tx.id(), tx.id());
        let txa = TxAux::TransferTx(tx, vec![w1, w2].into());
        let mut encoded: Vec<u8> = txa.encode();
        let mut data: &[u8] = encoded.as_mut();
        let decoded = TxAux::decode(&mut data).expect("decode tx aux");
        assert_eq!(txa, decoded);
    }
}
