use super::ChainNodeApp;
use crate::enclave_bridge::{mock::handle_enc_dec, EnclaveProxy};
use crate::storage::tx::get_account;
use crate::storage::*;
use abci::*;
use chain_core::common::{MerkleTree, Proof as MerkleProof, H256, HASH_SIZE_256};
use chain_core::state::account::StakedStateAddress;
use chain_core::state::ChainState;
use chain_core::tx::data::{txid_hash, TXID_HASH_ID};
use integer_encoding::VarInt;
use parity_scale_codec::{Decode, Encode};
use serde_json;
use std::convert::TryFrom;

/// Generate generic ABCI ProofOp for the witness
fn get_witness_proof_op(witness: &[u8]) -> ProofOp {
    let mut op = ProofOp::new();
    op.set_field_type("witness".into());
    op.set_key(TXID_HASH_ID.to_vec());
    op.set_data(txid_hash(witness).to_vec());
    op
}

impl<T: EnclaveProxy> ChainNodeApp<T> {
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

    /// Responds to query requests -- note that path is hex-encoded in the original request on the client side
    /// e.g. "store" == 0x73746f7265.
    pub fn query_handler(&self, _req: &RequestQuery) -> ResponseQuery {
        let mut resp = ResponseQuery::new();

        // "When Tendermint connects to a peer, it sends two queries to the ABCI application using the following paths, with no additional data:
        // * /p2p/filter/addr/<IP:PORT>, where <IP:PORT> denote the IP address and the port of the connection
        // * p2p/filter/id/<ID>, where <ID> is the peer node ID (ie. the pubkey.Address() for the peer's PubKey)
        // If either of these queries return a non-zero ABCI code, Tendermint will refuse to connect to the peer."
        if _req.path.starts_with("/p2p") || _req.path.starts_with("p2p") {
            // TODO: peer filtering
            return resp;
        }

        match _req.path.as_ref() {
            // FIXME: remove when no longer necessary
            "mockencrypt" => {
                handle_enc_dec(&_req, &mut resp, &self.storage);
            }
            // FIXME: remove when no longer necessary
            "mockdecrypt" => {
                handle_enc_dec(&_req, &mut resp, &self.storage);
            }
            "txquery" => match &self.tx_query_address {
                Some(addr) => {
                    resp.value = addr.clone().into_bytes();
                }
                None => {
                    resp.code = 1;
                    resp.log += "tx query address not set";
                }
            },
            "store" => {
                self.lookup(&mut resp, COL_BODIES, &_req.data[..], "tx not found");
                if _req.prove && resp.code == 0 {
                    let mwitness = self.storage.db.get(COL_WITNESS, &_req.data[..]);
                    match mwitness {
                        Ok(Some(witness)) => {
                            let last_height: i64 =
                                self.last_state.as_ref().map_or(0, |x| x.last_block_height);
                            let height = if _req.height == 0 || _req.height > last_height {
                                last_height
                            } else {
                                _req.height
                            };
                            let app_hash = self
                                .storage
                                .db
                                .get(COL_APP_HASHS, &i64::encode_var_vec(height))
                                .unwrap()
                                .unwrap();
                            let data = self
                                .storage
                                .db
                                .get(COL_MERKLE_PROOFS, &app_hash)
                                .unwrap()
                                .unwrap()
                                .to_vec();
                            let tree =
                                MerkleTree::decode(&mut data.as_slice()).expect("merkle tree");

                            let mut txid = [0u8; HASH_SIZE_256];
                            txid.copy_from_slice(&_req.data[..]);

                            // TODO: Change this in future to include individual ops?
                            let proof_ops = match tree.generate_proof(txid) {
                                None => vec![get_witness_proof_op(&witness[..])],
                                Some(merkle_proof) => vec![
                                    into_proof_op(tree.root_hash(), merkle_proof),
                                    get_witness_proof_op(&witness[..]),
                                ],
                            };

                            let mut proof = Proof::new();
                            proof.set_ops(proof_ops.into());
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
            "account" => {
                let account_address = StakedStateAddress::try_from(_req.data.as_slice());
                if let (Some(state), Ok(address)) = (&self.last_state, account_address) {
                    let account =
                        get_account(&address, &state.top_level.account_root, &self.accounts);
                    match account {
                        Ok(a) => {
                            resp.value = a.encode();
                            // TODO: inclusion proof
                        }
                        Err(e) => {
                            resp.log += format!("account lookup failed: {}", e).as_ref();
                            resp.code = 1;
                        }
                    }
                } else {
                    resp.log += "account lookup failed (either invalid address or node not correctly restored / initialized)";
                    resp.code = 3;
                }
            }
            "state" => {
                if self.tx_query_address.is_none() {
                    resp.code = 1;
                    resp.log += "tx query address not set";
                } else {
                    let value = self
                        .storage
                        .db
                        .get(COL_APP_STATES, &i64::encode_var_vec(_req.height));
                    match value {
                        Ok(Some(value)) => {
                            if let Ok(state) = ChainState::decode(&mut value.to_vec().as_slice()) {
                                resp.value =
                                    serde_json::to_string(&state).unwrap().as_bytes().to_owned();
                            } else {
                                resp.log += "state decode failed";
                                resp.code = 2;
                            }
                        }
                        _ => {
                            resp.log += "state not found";
                            resp.code = 2;
                        }
                    }
                }
            }
            _ => {
                resp.log += "invalid path";
                resp.code = 1;
            }
        }
        resp
    }
}

fn into_proof_op<T: Encode>(root_hash: H256, proof: MerkleProof<T>) -> ProofOp {
    let mut proof_op = ProofOp::new();

    proof_op.set_field_type("transaction".into());
    proof_op.set_key(root_hash.to_vec());
    proof_op.set_data(proof.encode());

    proof_op
}
