use crate::SelectedUnspentTransactions;
use chain_core::common::MerkleTree;
use chain_core::common::H264;
use chain_core::state::account::{StakedStateOpWitness, WithdrawUnbondedTx};
use chain_core::tx::data::input::TxoIndex;
use chain_core::tx::data::Tx;
use chain_core::tx::witness::tree::RawPubkey;
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
        let unit = 16_usize;
        let plain_payload_len = plain_txaux.encode().len();
        if plain_payload_len % unit == 0 {
            vec![0; plain_payload_len]
        } else {
            vec![0; plain_payload_len + unit - plain_payload_len % unit]
        }
    }

    /// Creates a mock merkletree
    fn mock_merkletree(
        &self,
        raw_pubkey: RawPubkey,
        tree_length: usize,
    ) -> Result<MerkleTree<RawPubkey>> {
        let tree = vec![raw_pubkey; tree_length];
        Ok(MerkleTree::new(tree))
    }

    /// Signs transaction with the mock key pair
    fn sign_tx(&self, total_pubkeys_len: usize) -> Result<TxInWitness> {
        let raw_pk = RawPubkey::from([0_u8; 33] as H264);
        let merkle_tree = self.mock_merkletree(raw_pk.clone(), total_pubkeys_len)?;
        let proof = merkle_tree
            .generate_proof(raw_pk)
            .expect("generate proof error in mocked merkle tree");
        let mock_signature =
            SchnorrSignature::from_default(&[0_u8; 64]).expect("set mock signature failed");
        Ok(TxInWitness::TreeSig(mock_signature, proof))
    }

    /// Signs the selected_unspent_transactions
    pub fn sign_txs(
        &self,
        total_pubkeys_len: usize,
        selected_unspent_transactions: &SelectedUnspentTransactions<'_>,
    ) -> Result<TxWitness> {
        selected_unspent_transactions
            .iter()
            .map(|_| self.sign_tx(total_pubkeys_len))
            .collect::<Result<Vec<TxInWitness>>>()
            .map(Into::into)
    }

    /// Mock the txaux for transactions
    pub fn mock_txaux_for_tx(&self, tx: Tx, witness: TxWitness) -> TxAux {
        let plain_payload = PlainTxAux::TransferTx(tx.clone(), witness);
        let padded_payload = self.pad_payload(plain_payload);
        // mock the enclave encrypted result
        let tx_enclave_aux = TxEnclaveAux::TransferTx {
            inputs: tx.inputs.clone(),
            no_of_outputs: tx.outputs.len() as TxoIndex,
            payload: TxObfuscated {
                txid: [0; 32],
                key_from: 0,
                init_vector: [0u8; 12],
                txpayload: padded_payload,
            },
        };
        TxAux::EnclaveTx(tx_enclave_aux)
    }

    /// Mock the txaux for withdraw transactions
    pub fn mock_txaux_for_withdraw(&self, tx: WithdrawUnbondedTx) -> TxAux {
        let ecdsa_signature =
            RecoverableSignature::from_compact(&[0; 64], RecoveryId::from_i32(1).unwrap()).unwrap();
        let witness = StakedStateOpWitness::new(ecdsa_signature);
        let no_of_outputs = tx.outputs.len() as TxoIndex;
        let txid = tx.id();
        let plain = PlainTxAux::WithdrawUnbondedStakeTx(tx);
        let padded_plain = self.pad_payload(plain);
        TxAux::EnclaveTx(TxEnclaveAux::WithdrawUnbondedStakeTx {
            no_of_outputs,
            witness,
            payload: TxObfuscated {
                txid,
                key_from: 0,
                init_vector: [0u8; 12],
                txpayload: padded_plain,
            },
        })
    }
}
