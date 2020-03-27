use crate::transaction_builder::WitnessedUTxO;
use chain_core::common::MerkleTree;
use chain_core::common::H256;
use chain_core::init::address::RedeemAddress;
use chain_core::state::account::{
    DepositBondTx, StakedStateAddress, StakedStateOpAttributes, StakedStateOpWitness,
    WithdrawUnbondedTx,
};
use chain_core::state::tendermint::BlockHeight;
use chain_core::tx::data::input::{TxoPointer, TxoSize};
use chain_core::tx::data::{Tx, TxId};
use chain_core::tx::witness::tree::RawXOnlyPubkey;
use chain_core::tx::witness::{TxInWitness, TxWitness};
use chain_core::tx::{PlainTxAux, TransactionId, TxAux, TxEnclaveAux, TxObfuscated};
use client_common::Result;
use parity_scale_codec::Encode;
use secp256k1::recovery::{RecoverableSignature, RecoveryId};
use secp256k1::schnorrsig::SchnorrSignature;

/// Default implementation of `Signer`
#[derive(Debug, Clone)]
pub struct DummySigner();

impl DummySigner {
    /// pad payload to the multiples of 128bits
    fn pad_payload(&self, plain_txaux: PlainTxAux) -> Vec<u8> {
        // https://tools.ietf.org/html/rfc8452
        vec![0; plain_txaux.encode().len() + 16]
    }

    /// Creates a mock merkletree
    fn mock_merkletree(
        &self,
        raw_pubkey: RawXOnlyPubkey,
        tree_length: usize,
    ) -> Result<MerkleTree<RawXOnlyPubkey>> {
        let tree = vec![raw_pubkey; tree_length];
        Ok(MerkleTree::new(tree))
    }

    /// Signs transaction with the mock key pair
    fn sign_tx(&self, total_pubkeys_len: usize) -> Result<TxInWitness> {
        let raw_pk = RawXOnlyPubkey::from([0_u8; 32] as H256);
        let merkle_tree = self.mock_merkletree(raw_pk.clone(), total_pubkeys_len)?;
        let proof = merkle_tree
            .generate_proof(raw_pk)
            .expect("generate proof error in mocked merkle tree");
        let mock_signature =
            SchnorrSignature::from_default(&[0_u8; 64]).expect("set mock signature failed");
        Ok(TxInWitness::TreeSig(mock_signature, proof))
    }

    /// Schnorr sign consecutive imaginary inputs of provided length
    pub fn schnorr_sign_inputs_len(&self, inputs: &[WitnessedUTxO]) -> Result<TxWitness> {
        Ok(inputs
            .iter()
            .map(|x| {
                self.sign_tx(x.threshold as usize)
                    .expect("would that ever fail? why this dummy has results?")
            })
            .collect::<Vec<TxInWitness>>()
            .into())
    }

    /// Mock the txaux for transactions
    pub fn mock_txaux_for_tx(&self, tx: Tx, witness: TxWitness) -> TxAux {
        let plain_payload = PlainTxAux::TransferTx(tx.clone(), witness);
        let padded_payload = self.pad_payload(plain_payload);
        // mock the enclave encrypted result
        let tx_enclave_aux = TxEnclaveAux::TransferTx {
            inputs: tx.inputs.clone(),
            no_of_outputs: tx.outputs.len() as TxoSize,
            payload: TxObfuscated {
                txid: [0; 32],
                key_from: BlockHeight::genesis(),
                init_vector: [0u8; 12],
                txpayload: padded_payload,
            },
        };
        TxAux::EnclaveTx(tx_enclave_aux)
    }

    /// Mock the txaux for deposit transactions
    pub fn mock_txaux_for_deposit(&self, inputs: &[WitnessedUTxO]) -> Result<TxAux> {
        let witness = self.schnorr_sign_inputs_len(inputs)?;
        let plain_payload = PlainTxAux::DepositStakeTx(witness);
        let padded_payload = self.pad_payload(plain_payload);
        let deposit_bond_tx = DepositBondTx {
            inputs: vec![TxoPointer {
                id: TxId::default(),
                index: TxoSize::default(),
            }],
            to_staked_account: StakedStateAddress::BasicRedeem(RedeemAddress::default()),
            attributes: StakedStateOpAttributes::default(),
        };
        let payload = TxObfuscated {
            txid: TxId::default(),
            key_from: BlockHeight::genesis(),
            init_vector: [0u8; 12],
            txpayload: padded_payload,
        };
        let tx_deposit_aux = TxEnclaveAux::DepositStakeTx {
            tx: deposit_bond_tx,
            payload,
        };
        Ok(TxAux::EnclaveTx(tx_deposit_aux))
    }

    /// Mock the txaux for withdraw transactions
    pub fn mock_txaux_for_withdraw(&self, tx: WithdrawUnbondedTx) -> TxAux {
        let ecdsa_signature =
            RecoverableSignature::from_compact(&[0; 64], RecoveryId::from_i32(1).unwrap()).unwrap();
        let witness = StakedStateOpWitness::new(ecdsa_signature);
        let no_of_outputs = tx.outputs.len() as TxoSize;
        let txid = tx.id();
        let plain = PlainTxAux::WithdrawUnbondedStakeTx(tx);
        let padded_plain = self.pad_payload(plain);
        TxAux::EnclaveTx(TxEnclaveAux::WithdrawUnbondedStakeTx {
            no_of_outputs,
            witness,
            payload: TxObfuscated {
                txid,
                key_from: BlockHeight::genesis(),
                init_vector: [0u8; 12],
                txpayload: padded_plain,
            },
        })
    }
}
