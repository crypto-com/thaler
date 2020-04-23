use std::convert::{TryFrom, TryInto};

use super::ChainNodeApp;
use crate::enclave_bridge::EnclaveProxy;
use abci::*;
use chain_core::common::{MerkleTree, Proof as MerkleProof, H256, HASH_SIZE_256};
use chain_core::state::account::StakedStateAddress;
use chain_core::state::tendermint::BlockHeight;
use chain_core::state::ChainState;
use chain_core::tx::data::{txid_hash, TXID_HASH_ID};
use chain_storage::jellyfish::get_with_proof;
use chain_storage::LookupItem;
use parity_scale_codec::{Decode, Encode};

/// Generate generic ABCI ProofOp for the witness
fn get_witness_proof_op(witness: &[u8]) -> ProofOp {
    let mut op = ProofOp::new();
    op.set_field_type("witness".into());
    op.set_key(TXID_HASH_ID.to_vec());
    op.set_data(txid_hash(witness).to_vec());
    op
}

fn get_key(resp: &mut ResponseQuery, data_key: &[u8]) -> Option<H256> {
    if data_key.len() != HASH_SIZE_256 {
        resp.log += "invalid txid or app hash length";
        resp.code = 4;
        None
    } else {
        let mut key = H256::default();
        key.copy_from_slice(&data_key[..]);
        Some(key)
    }
}

impl<T: EnclaveProxy> ChainNodeApp<T> {
    fn lookup_key(
        &self,
        resp: &mut ResponseQuery,
        item: LookupItem,
        key: &H256,
        log_message: &str,
    ) {
        let v = self.storage.lookup_item(item, &key);
        match v {
            Some(uv) => {
                resp.value = uv;
            }
            _ => {
                resp.log += log_message;
                resp.code = 1;
            }
        }
    }

    /// Helper to find a key under a column in KV DB, or log an error (both stored in the response).
    fn lookup(
        &self,
        resp: &mut ResponseQuery,
        item: LookupItem,
        data_key: &[u8],
        log_message: &str,
    ) -> Option<H256> {
        if let Some(key) = get_key(resp, data_key) {
            self.lookup_key(resp, item, &key, log_message);
            if resp.code == 0 {
                return Some(key);
            }
        }
        None
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
                let key = self.lookup(
                    &mut resp,
                    LookupItem::TxBody,
                    &_req.data[..],
                    "tx not found",
                );
                if let (Some(txid), true) = (key, _req.prove) {
                    let mwitness = self.storage.lookup_item(LookupItem::TxWitness, &txid);
                    if let Some(witness) = mwitness {
                        // Negative height default to 0
                        let req_height = _req
                            .height
                            .try_into()
                            .unwrap_or_else(|_| BlockHeight::genesis());
                        let last_height = self
                            .last_state
                            .as_ref()
                            .map_or(BlockHeight::genesis(), |x| x.last_block_height);
                        let height =
                            if req_height == BlockHeight::genesis() || req_height > last_height {
                                last_height
                            } else {
                                req_height
                            };
                        // note this should not crash if Tendermint delivers all blocks with height in order
                        // TODO: invariant / sanity check in rust-abci?
                        let app_hash = self.storage.get_historical_app_hash(height).unwrap();
                        let data = self
                            .storage
                            .lookup_item(LookupItem::TxsMerkle, &app_hash)
                            .unwrap();
                        let tree = MerkleTree::decode(&mut data.as_slice()).expect("merkle tree");

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
                    } else {
                        resp.log += "proof error: witness not found";
                        resp.code = 2;
                    }
                }
            }
            "meta" => {
                self.lookup(
                    &mut resp,
                    LookupItem::TxMetaSpent,
                    &_req.data[..],
                    "tx not found",
                );
            }
            "witness" => {
                self.lookup(
                    &mut resp,
                    LookupItem::TxWitness,
                    &_req.data[..],
                    "tx not found",
                );
            }
            "merkle" => {
                self.lookup(
                    &mut resp,
                    LookupItem::TxsMerkle,
                    &_req.data[..],
                    "app state not found",
                );
            }
            "account" => {
                let account_address = StakedStateAddress::try_from(_req.data.as_slice());
                if let (Some(state), Ok(address)) = (&self.last_state, account_address) {
                    let (account, _proof) =
                        get_with_proof(&self.storage, state.staking_version, &address);
                    match account {
                        Some(a) => {
                            resp.value = a.encode();
                            // TODO: inclusion proof
                        }
                        None => {
                            resp.log += "account lookup failed: account not exists";
                            resp.code = 1;
                        }
                    }
                } else {
                    resp.log += "account lookup failed (either invalid address or node not correctly restored / initialized)";
                    resp.code = 3;
                }
            }
            "staking" => {
                let height: BlockHeight = _req.height.try_into().expect("Invalid block height");
                let mversion = if height == BlockHeight::genesis() {
                    self.last_state.as_ref().map(|state| state.staking_version)
                } else {
                    self.storage.get_historical_staking_version(height)
                };
                let account_address = StakedStateAddress::try_from(_req.data.as_slice());
                if let (Some(version), Ok(address)) = (mversion, account_address) {
                    let (maccount, proof) = get_with_proof(&self.storage, version, &address);
                    resp.value = serde_json::to_string(&(
                        maccount,
                        if _req.prove { Some(proof) } else { None },
                    ))
                    .unwrap()
                    .into_bytes();
                } else {
                    resp.log += "account lookup failed (either invalid address or node not correctly restored / initialized)";
                    resp.code = 3;
                }
            }
            "state" => {
                if self.tx_query_address.is_none() {
                    resp.code = 1;
                    resp.log += "tx query address not set / state is not persisted";
                } else {
                    let value = self.storage.get_historical_state(
                        _req.height.try_into().expect("Invalid block height"),
                    );
                    match value {
                        Some(value) => {
                            if let Ok(state) = ChainState::decode(&mut value.to_vec().as_slice()) {
                                resp.value = serde_json::to_string(&state).unwrap().into_bytes();
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
            "council-nodes" => {
                let council_nodes = &self
                    .last_state
                    .as_ref()
                    .expect("Missing last_state: init chain was not called")
                    .staking_table
                    .list_council_nodes(&self.staking_getter_committed());

                resp.value = serde_json::to_string(&council_nodes)
                    .expect("Unable to serialize validator metadata into json")
                    .into_bytes();
            }
            "sealed" => {
                self.lookup(
                    &mut resp,
                    LookupItem::TxSealed,
                    &_req.data[..],
                    "sealed log not found",
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

fn into_proof_op<T: Encode>(root_hash: H256, proof: MerkleProof<T>) -> ProofOp {
    let mut proof_op = ProofOp::new();

    proof_op.set_field_type("transaction".into());
    proof_op.set_key(root_hash.to_vec());
    proof_op.set_data(proof.encode());

    proof_op
}
