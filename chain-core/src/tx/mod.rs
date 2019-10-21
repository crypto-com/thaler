use std::prelude::v1::Vec;

/// Transaction internal structure
pub mod data;
/// Transaction fee calculation
pub mod fee;
/// Witness structures (e.g. signatures) for transactions
pub mod witness;

#[cfg(feature = "hex")]
use std::fmt;

use parity_scale_codec::{Decode, Encode, Error, Input};

use self::data::Tx;
use self::witness::TxWitness;
use crate::state::account::{
    DepositBondTx, StakedStateOpWitness, UnbondTx, UnjailTx, WithdrawUnbondedTx,
};
use crate::state::tendermint::BlockHeight;
use crate::tx::data::{txid_hash, TxId};
use aead::Payload;
use data::input::{TxoIndex, TxoPointer};
use data::output::TxOut;

const TX_AUX_SIZE: usize = 1024 * 60; // 60 KB

/// wrapper around transactions with outputs
#[derive(Encode, Decode, Clone)]
pub enum TxWithOutputs {
    /// normal transfer
    Transfer(Tx),
    /// withdrawing unbonded amount from a staked state
    StakeWithdraw(WithdrawUnbondedTx),
}

impl TxWithOutputs {
    /// returns the particular transaction type's outputs
    pub fn outputs(&self) -> &[TxOut] {
        match self {
            TxWithOutputs::Transfer(tx) => &tx.outputs,
            TxWithOutputs::StakeWithdraw(tx) => &tx.outputs,
        }
    }

    /// returns the particular transaction type's id (currently blake2s_hash(SCALE-encoded tx))
    pub fn id(&self) -> TxId {
        match self {
            TxWithOutputs::Transfer(tx) => tx.id(),
            TxWithOutputs::StakeWithdraw(tx) => tx.id(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
/// Plain transaction parts "visible" inside enclaves
pub enum PlainTxAux {
    /// both private; normal value transfer Tx with the vector of witnesses
    TransferTx(Tx, TxWitness),
    /// only the witness, as only "input" data are private
    DepositStakeTx(TxWitness),
    /// only the TX data / new outputs are private
    WithdrawUnbondedStakeTx(WithdrawUnbondedTx),
}

impl PlainTxAux {
    /// creates a new Tx with a vector of witnesses (mainly for testing/tools)
    pub fn new(tx: Tx, witness: TxWitness) -> Self {
        PlainTxAux::TransferTx(tx, witness)
    }
}

#[cfg(feature = "hex")]
impl fmt::Display for PlainTxAux {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlainTxAux::TransferTx(tx, witness) => display_tx_witness(f, tx, witness),
            PlainTxAux::DepositStakeTx(witness) => writeln!(f, "witness: {:?}\n", witness),
            PlainTxAux::WithdrawUnbondedStakeTx(tx) => writeln!(f, "Tx:\n{}", tx),
        }
    }
}

/// plqin TX payload to be obfuscated
pub struct TxToObfuscate {
    pub txpayload: Vec<u8>,
    pub txid: TxId,
}

impl TxToObfuscate {
    pub fn from(tx: PlainTxAux, txid: TxId) -> Option<Self> {
        match &tx {
            PlainTxAux::TransferTx(itx, _) => {
                if itx.id() == txid {
                    Some(TxToObfuscate {
                        txpayload: tx.encode(),
                        txid,
                    })
                } else {
                    None
                }
            }
            PlainTxAux::DepositStakeTx(_) => Some(TxToObfuscate {
                txpayload: tx.encode(),
                txid,
            }),
            PlainTxAux::WithdrawUnbondedStakeTx(itx) => {
                if itx.id() == txid {
                    Some(TxToObfuscate {
                        txpayload: tx.encode(),
                        txid,
                    })
                } else {
                    None
                }
            }
        }
    }
}

impl<'tx> Into<Payload<'tx, 'tx>> for &'tx TxToObfuscate {
    fn into(self) -> Payload<'tx, 'tx> {
        Payload {
            msg: &self.txpayload,
            aad: &self.txid,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
/// obfuscated TX payload
pub struct TxObfuscated {
    pub key_from: BlockHeight,
    pub init_vector: [u8; 12],
    pub txpayload: Vec<u8>,
    pub txid: TxId,
}

impl<'tx> Into<Payload<'tx, 'tx>> for &'tx TxObfuscated {
    fn into(self) -> Payload<'tx, 'tx> {
        Payload {
            msg: &self.txpayload,
            aad: &self.txid,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
/// transactions with parts that are only viewable inside TEE
pub enum TxEnclaveAux {
    /// normal value transfer Tx with the vector of witnesses
    TransferTx {
        inputs: Vec<TxoPointer>,
        no_of_outputs: TxoIndex,
        payload: TxObfuscated,
    },
    /// Tx "spends" utxos to be deposited as bonded stake in an account (witnesses as in transfer)
    DepositStakeTx {
        tx: DepositBondTx,
        payload: TxObfuscated,
    },
    /// Tx that "creates" utxos out of account state; withdraws unbonded stake (witness for account)
    WithdrawUnbondedStakeTx {
        no_of_outputs: TxoIndex,
        witness: StakedStateOpWitness,
        payload: TxObfuscated,
    },
}

impl TxEnclaveAux {
    /// retrieves a TX ID (currently blake2s(scale_codec_bytes(tx)))
    pub fn tx_id(&self) -> TxId {
        match self {
            TxEnclaveAux::TransferTx {
                payload: TxObfuscated { txid, .. },
                ..
            } => *txid,
            TxEnclaveAux::DepositStakeTx { tx, .. } => tx.id(),
            TxEnclaveAux::WithdrawUnbondedStakeTx {
                payload: TxObfuscated { txid, .. },
                ..
            } => *txid,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Encode)]
/// TODO: custom Encode/Decode when data structures are finalized (for backwards/forwards compatibility, encoders/decoders should be able to work with old formats)
pub enum TxAux {
    /// transactions that need to be processed inside TEE
    EnclaveTx(TxEnclaveAux),
    /// Tx that modifies account state -- moves some bonded stake into unbonded (witness for account)
    UnbondStakeTx(UnbondTx, StakedStateOpWitness),
    /// Tx that unjails an account
    UnjailTx(UnjailTx, StakedStateOpWitness),
}

impl Decode for TxAux {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let size = input
            .remaining_len()?
            .ok_or_else(|| "Unable to calculate size of input")?;

        if size > TX_AUX_SIZE {
            return Err("Input too large".into());
        }

        match input.read_byte()? {
            0 => Ok(TxAux::EnclaveTx(TxEnclaveAux::decode(input)?)),
            1 => Ok(TxAux::UnbondStakeTx(
                UnbondTx::decode(input)?,
                StakedStateOpWitness::decode(input)?,
            )),
            2 => Ok(TxAux::UnjailTx(
                UnjailTx::decode(input)?,
                StakedStateOpWitness::decode(input)?,
            )),
            _ => Err("No such variant in enum TxAux".into()),
        }
    }
}

pub trait TransactionId: Encode {
    /// retrieves a TX ID (currently blake2s(scale_codec_bytes(tx)))
    fn id(&self) -> TxId {
        txid_hash(&self.encode())
    }
}

impl TxAux {
    /// retrieves a TX ID (currently blake2s(scale_codec_bytes(tx)))
    pub fn tx_id(&self) -> TxId {
        match self {
            TxAux::EnclaveTx(tx) => tx.tx_id(),
            TxAux::UnbondStakeTx(tx, _) => tx.id(),
            TxAux::UnjailTx(tx, _) => tx.id(),
        }
    }
}

#[cfg(feature = "hex")]
fn display_tx_witness<T: fmt::Display, W: fmt::Debug>(
    f: &mut fmt::Formatter<'_>,
    tx: T,
    witness: W,
) -> fmt::Result {
    writeln!(f, "Tx:\n{}", tx)?;
    writeln!(f, "witness: {:?}\n", witness)
}

#[cfg(feature = "hex")]
impl fmt::Display for TxAux {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxAux::EnclaveTx(TxEnclaveAux::TransferTx {
                payload: TxObfuscated { txid, .. },
                inputs,
                ..
            }) => {
                writeln!(f, "Transfer Tx id:\n{}", hex::encode(&txid[..]))?;
                writeln!(f, "tx inputs: {:?}\n", inputs)
            }
            TxAux::EnclaveTx(TxEnclaveAux::DepositStakeTx { tx, .. }) => writeln!(f, "Tx:\n{}", tx),
            TxAux::UnbondStakeTx(tx, witness) => display_tx_witness(f, tx, witness),
            TxAux::EnclaveTx(TxEnclaveAux::WithdrawUnbondedStakeTx {
                payload: TxObfuscated { txid, .. },
                witness,
                ..
            }) => {
                writeln!(
                    f,
                    "Withdraw Unbonded Stake Tx id:\n{}",
                    hex::encode(&txid[..])
                )?;
                writeln!(f, "witness: {:?}\n", witness)
            }
            TxAux::UnjailTx(tx, witness) => display_tx_witness(f, tx, witness),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::common::MerkleTree;
    use crate::init::coin::Coin;
    use crate::tx::data::access::{TxAccess, TxAccessPolicy};
    use crate::tx::data::address::ExtendedAddr;
    use crate::tx::data::input::TxoPointer;
    use crate::tx::data::output::TxOut;
    use crate::tx::witness::tree::RawPubkey;
    use crate::tx::witness::TxInWitness;
    use parity_scale_codec::{Decode, Encode};
    use secp256k1::{schnorrsig::schnorr_sign, Message, PublicKey, Secp256k1, SecretKey};

    // TODO: rewrite as quickcheck prop
    #[test]
    fn encode_decode() {
        // not a valid transaction, only to test enconding-decoding
        let mut tx = Tx::new();
        tx.add_input(TxoPointer::new([0x01; 32].into(), 1));
        tx.add_output(TxOut::new(
            ExtendedAddr::OrTree([0xbb; 32].into()),
            Coin::unit(),
        ));
        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[0xcc; 32][..]).expect("secret key");
        let pk1 = PublicKey::from_secret_key(&secp, &sk1);
        let raw_pk1 = RawPubkey::from(pk1.serialize());

        let raw_public_keys = vec![raw_pk1];

        tx.attributes
            .allowed_view
            .push(TxAccessPolicy::new(pk1.clone(), TxAccess::AllData));

        let msg = Message::from_slice(&tx.id()).expect("msg");

        let merkle = MerkleTree::new(raw_public_keys.clone());

        let w1 = TxInWitness::TreeSig(
            schnorr_sign(&secp, &msg, &sk1).0,
            merkle.generate_proof(raw_public_keys[0].clone()).unwrap(),
        );
        let txa = PlainTxAux::TransferTx(tx, vec![w1].into());
        let mut encoded: Vec<u8> = txa.encode();
        let mut data: &[u8] = encoded.as_mut();
        let decoded = PlainTxAux::decode(&mut data).expect("decode tx aux");
        assert_eq!(txa, decoded);
    }
}
