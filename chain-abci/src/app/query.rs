use super::ChainNodeApp;
use crate::storage::merkle::get_proof;
use crate::storage::*;
use abci::*;
use chain_core::common::merkle::MerkleTree;
use chain_core::common::HASH_SIZE_256;
use chain_core::tx::data::{txid_hash, TXID_HASH_ID};
use integer_encoding::VarInt;
use rlp::{Decodable, Rlp};

impl ChainNodeApp {
    /// Helper to find a key under a column in KV DB, or log an error (both stored in the response).
    fn lookup(&self, resp: &mut ResponseQuery, column: Option<u32>, key: &[u8], log_message: &str) {
        let v = self.storage.db.get(column, key);
        match v {
            Ok(Some(uv)) => {
                resp.value = uv.into_vec();
            }
            _ => {
                resp.log += log_message;
                resp.code = 1;
            }
        }
    }

    /// Generate generic ABCI ProofOp for the witness
    fn get_witness_proof_op(witness: &[u8]) -> ProofOp {
        let mut op = ProofOp::new();
        op.set_field_type("witness".into());
        op.set_key(TXID_HASH_ID.to_vec());
        op.set_data(txid_hash(witness).as_bytes().to_vec());
        op
    }

    /// Responds to query requests -- note that path is hex-encoded in the original request on the client side
    /// e.g. "store" == 0x73746f7265.
    pub fn query_handler(&self, _req: &RequestQuery) -> ResponseQuery {
        let mut resp = ResponseQuery::new();
        // TODO: auth / verification (when TXs are encrypted)
        match _req.path.as_ref() {
            "store" => {
                self.lookup(&mut resp, COL_BODIES, &_req.data[..], "tx not found");
                if _req.prove && resp.code == 0 {
                    let mwitness = self.storage.db.get(COL_WITNESS, &_req.data[..]);
                    match mwitness {
                        Ok(Some(witness)) => {
                            let last_height: i64 = self
                                .last_state
                                .as_ref()
                                .map_or(0, |x| x.last_block_height.into());
                            let height = if _req.height == 0 || _req.height > last_height {
                                last_height
                            } else {
                                _req.height
                            };
                            let app_hash = self
                                .storage
                                .db
                                .get(COL_APP_STATES, &i64::encode_var_vec(height))
                                .unwrap()
                                .unwrap();
                            let tree = MerkleTree::decode(&Rlp::new(
                                &self
                                    .storage
                                    .db
                                    .get(COL_MERKLE_PROOFS, &app_hash[..])
                                    .unwrap()
                                    .unwrap()[..],
                            ))
                            .expect("merkle tree");

                            let mut txid = [0u8; HASH_SIZE_256];
                            txid.copy_from_slice(&_req.data[..]);
                            let mut proofl = get_proof(&tree, &txid.into());
                            proofl.push(ChainNodeApp::get_witness_proof_op(&witness[..]));
                            let mut proof = Proof::new();
                            proof.set_ops(proofl.into());
                            resp.set_proof(proof);
                        }
                        _ => {
                            resp.log += "proof error: witness not found";
                            resp.code = 2;
                        }
                    }
                }
            }
            "meta" => {
                self.lookup(&mut resp, COL_TX_META, &_req.data[..], "tx not found");
            }
            "witness" => {
                self.lookup(&mut resp, COL_WITNESS, &_req.data[..], "tx not found");
            }
            "merkle" => {
                self.lookup(
                    &mut resp,
                    COL_MERKLE_PROOFS,
                    &_req.data[..],
                    "app state not found",
                );
            }
            _ => {
                resp.log += "invalid path";
                resp.code = 1;
            }
        }
        resp
    }
}
