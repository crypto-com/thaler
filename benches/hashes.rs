extern crate blake2;
extern crate chain_core;
extern crate digest;
extern crate sha3;
#[macro_use]
extern crate criterion;

use chain_core::common::hash256;
use chain_core::common::merkle::Hash256;
use chain_core::tx::data::TxId;

use blake2::Blake2s;
use criterion::{Criterion, Fun};
use digest::Digest;
use sha3::Sha3_256;
use std::iter;
use std::marker::PhantomData;

/// This generic enum was copy-pasted, because changing it in the original
/// is a bit of a pain because of the generic Serialization/Deserialization.
/// TODO: consider moving to merkle.rs when binary serialization is finalized and possibly custom (de-)serializers are written
pub enum GenericMerkleNode<D: Digest> {
    Branch(
        Hash256,
        Box<GenericMerkleNode<D>>,
        Box<GenericMerkleNode<D>>,
    ),
    Leaf(Hash256, PhantomData<D>),
}

impl<D: Digest> GenericMerkleNode<D> {
    fn make_tree(xs: &[TxId]) -> Self {
        if xs.is_empty() {
            panic!("make_tree applied to empty list")
        } else if xs.len() == 1 {
            GenericMerkleNode::Leaf(xs[0], PhantomData)
        } else {
            let i = xs.len().checked_next_power_of_two().unwrap() >> 1;
            let a = GenericMerkleNode::make_tree(&xs[0..i]);
            let b = GenericMerkleNode::make_tree(&xs[i..]);
            let mut bs = vec![1u8];
            bs.extend(a.get_root_hash().iter());
            bs.extend(b.get_root_hash().iter());
            GenericMerkleNode::Branch(hash256::<D>(&bs), Box::new(a), Box::new(b))
        }
    }

    fn get_root_hash(&self) -> &Hash256 {
        match self {
            GenericMerkleNode::Branch(hash, _, _) => hash,
            GenericMerkleNode::Leaf(hash, _) => hash,
        }
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let sha3 = Fun::new("sha3 merkle", |b, i| {
        b.iter(|| {
            let empty = hash256::<Sha3_256>(&vec![]);
            let txids: Vec<TxId> = iter::repeat(empty).take(*i).collect();
            GenericMerkleNode::<Sha3_256>::make_tree(&txids)
        })
    });

    let blake2s = Fun::new("blake2s merkle", |b, i| {
        b.iter(|| {
            let empty = hash256::<Blake2s>(&vec![]);
            let txids: Vec<TxId> = iter::repeat(empty).take(*i).collect();
            GenericMerkleNode::<Blake2s>::make_tree(&txids)
        })
    });

    let hashes = vec![sha3, blake2s];
    c.bench_functions("Merkle Hashes", hashes, 10000);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
