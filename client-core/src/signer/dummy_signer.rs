use crate::SelectedUnspentTransactions;
use chain_core::common::MerkleTree;
use chain_core::common::H264;
use chain_core::tx::witness::tree::RawPubkey;
use chain_core::tx::witness::{TxInWitness, TxWitness};
use client_common::Result;
use secp256k1::schnorrsig::SchnorrSignature;

/// Default implementation of `Signer`
#[derive(Debug, Clone)]
pub struct DummySigner {}

impl DummySigner {
    /// Creates a mock merkletree
    fn mock_merkletree(
        &self,
        raw_pubkey: RawPubkey,
        tree_length: usize,
    ) -> Result<MerkleTree<RawPubkey>> {
        let tree = vec![raw_pubkey; tree_length];
        Ok(MerkleTree::new(tree))
    }

    /// Signs with the mock key pair
    fn sign_inside(&self, total_pubkeys_len: usize) -> Result<TxInWitness> {
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
    pub fn sign(
        &self,
        total_pubkeys_len: usize,
        selected_unspent_transactions: &SelectedUnspentTransactions<'_>,
    ) -> Result<TxWitness> {
        selected_unspent_transactions
            .iter()
            .map(|_| self.sign_inside(total_pubkeys_len))
            .collect::<Result<Vec<TxInWitness>>>()
            .map(Into::into)
    }
}
