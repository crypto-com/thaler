use abci::ProofOp;
use chain_core::common::merkle::{Hash256, MerkleNode, MerkleTree};
use chain_core::tx::data::TxId;

/// generates a Merkle path in generic TM proof ops
pub fn get_proof(tree: &MerkleTree, hash: &TxId) -> Vec<ProofOp> {
    let mut path = Vec::new();
    match tree {
        MerkleTree::Tree(_, node) => {
            let found = find_path(&node, &mut path, hash);
            if found {
                path.push(MerklePath::Root.to_proof_op(node.get_root_hash()));
            }
        }
        MerkleTree::Empty => {}
    }
    path
}

/// Match = found the TxId to be proven; L/RFound = found on the left / right branch
/// Root = reached the root / app_hash
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum MerklePath {
    Match = 0,
    LFound = 1,
    RFound = 2,
    Root = 3,
}

impl MerklePath {
    /// converts the internal MerklePath type into a generic TM proof op
    fn to_proof_op(self, t: &Hash256) -> ProofOp {
        let mut op = ProofOp::new();
        op.set_field_type("path".into());
        op.set_key(vec![self as u8]);
        op.set_data(t.to_vec());
        op
    }
}

/// searches a TX ID in the tree -- returns true if found
///
/// # Arguments
///
/// * `path` - a mutable vector of ProofOps, proof ops are added if a path was found
/// * `txid` - TX ID to look for
fn find_path(node: &MerkleNode, path: &mut Vec<ProofOp>, txid: &TxId) -> bool {
    match node {
        MerkleNode::Branch(_, l, r) => {
            let found_l = find_path(&l, path, txid);
            if found_l {
                path.push(MerklePath::LFound.to_proof_op(r.get_root_hash()));
                true
            } else {
                let found_r = find_path(&r, path, txid);
                if found_r {
                    path.push(MerklePath::RFound.to_proof_op(l.get_root_hash()));
                    true
                } else {
                    false
                }
            }
        }
        MerkleNode::Leaf(hash) if hash == txid => {
            path.push(MerklePath::Match.to_proof_op(hash));
            true
        }
        MerkleNode::Leaf(_) => false,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chain_core::common::HASH_SIZE_256;
    use chain_core::tx::data::txid_hash;
    use quickcheck::quickcheck;

    fn from_proof_op(op: &ProofOp) -> Option<MerklePath> {
        let key = op.key[0] as u8;
        if op.field_type == "path" && key < 4 {
            Some(unsafe { std::mem::transmute(key) })
        } else {
            None
        }
    }

    fn run_op(op: &ProofOp, prev_hash: &Hash256) -> Option<Hash256> {
        let path_op = from_proof_op(op);
        let mut bs = vec![1u8];
        match path_op {
            Some(MerklePath::LFound) => {
                bs.extend(prev_hash);
                bs.extend(&op.data[..]);
                Some(txid_hash(&bs))
            }
            Some(MerklePath::RFound) => {
                bs.extend(&op.data[..]);
                bs.extend(prev_hash);
                Some(txid_hash(&bs))
            }
            _ => None,
        }
    }

    fn verify(txid: &TxId, ops: &[ProofOp]) -> bool {
        if ops.len() < 2 {
            false
        } else {
            let op1 = &ops[0];
            let m1 = from_proof_op(op1);
            match m1 {
                Some(MerklePath::Match) => {
                    if op1.data[..] != txid[..] {
                        return false;
                    }
                }
                _ => {
                    return false;
                }
            }
            let mut ph = [0u8; HASH_SIZE_256];
            ph.copy_from_slice(&op1.data[..]);
            let mut prev_hash: Hash256 = ph.into();
            for i in 1..(ops.len() - 1) {
                prev_hash = run_op(&ops[i], &prev_hash).unwrap();
            }
            let lastop = &ops.last().unwrap();
            let last = from_proof_op(lastop);
            match last {
                Some(MerklePath::Root) => {
                    let mut e = [0u8; HASH_SIZE_256];
                    e.copy_from_slice(&lastop.data);
                    let expected: Hash256 = e.into();
                    expected == prev_hash
                }
                _ => false,
            }
        }
    }

    quickcheck! {
        fn can_verify_path_in_tree(v: Vec<Vec<u8>>, rv: Vec<u8>) -> bool {
            let txids: Vec<TxId> = v.iter().map(|x| txid_hash(x)).collect();
            let tree = MerkleTree::new(&txids);
            let random_txid = txid_hash(&rv);
            let path = get_proof(&tree, &random_txid);
            let verified = verify(&random_txid, &path);
            (txids.contains(&random_txid) && verified) || !verified
        }
    }
}
