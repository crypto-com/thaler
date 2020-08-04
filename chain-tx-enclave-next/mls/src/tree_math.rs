//! draft-ietf-mls-protocol.md#tree-math-tree-math
//!
//! Left balanced complete binary tree, numbering the nodes in order, like:
//!
//! ```plain
//!                                              X
//!                      X
//!          X                       X                       X
//!    X           X           X           X           X
//! X     X     X     X     X     X     X     X     X     X     X
//! 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20
//! ```
//!
//! Insights:
//!
//! - Leaf nodes are even numbers, intermediate nodes are odd numbers, the size of the tree are always odd.
//! - The level of a node (counting from leaf to root) is the number of trailing one bits of the binary form of the number,
//!   leaf nodes have level zero.
//! - The parent nodes and direct child nodes are all like this:
//!   ```plain
//!      P01X
//!     /    \
//!   P00X  P10X
//!   ```
//!   - `P` is a shared prefix
//!   - `X` is a sequence of ones
//!
//!   So moving from parent to children or vice versa, is only about switching one or two bits.
//!
//! The left sub-tree of the root node is always complete, but the right part might not.
use parity_scale_codec::{Decode, Encode};
use rustls::internal::msgs::codec::{Codec, Reader};
use std::convert::{From, TryFrom};
use std::iter;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct LeafSize(pub u32);
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ParentSize(pub u32);
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeSize(pub u32);
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeType {
    Leaf(LeafSize),
    Parent(ParentSize),
}

impl Codec for LeafSize {
    #[inline]
    fn encode(&self, bytes: &mut Vec<u8>) {
        Codec::encode(&self.0, bytes)
    }

    #[inline]
    fn read(r: &mut Reader) -> Option<Self> {
        u32::read(r).map(Self)
    }
}

impl From<LeafSize> for NodeSize {
    #[inline]
    fn from(leaf: LeafSize) -> Self {
        NodeSize(leaf.0 * 2)
    }
}

impl From<ParentSize> for NodeSize {
    #[inline]
    fn from(p: ParentSize) -> Self {
        NodeSize(p.0 * 2 + 1)
    }
}

impl TryFrom<NodeSize> for LeafSize {
    type Error = ();

    #[inline]
    fn try_from(n: NodeSize) -> Result<Self, Self::Error> {
        match n.node_type() {
            NodeType::Leaf(index) => Ok(index),
            _ => Err(()),
        }
    }
}

impl TryFrom<NodeSize> for ParentSize {
    type Error = ();

    #[inline]
    fn try_from(n: NodeSize) -> Result<Self, Self::Error> {
        match n.node_type() {
            NodeType::Parent(index) => Ok(index),
            _ => Err(()),
        }
    }
}

impl LeafSize {
    pub fn sibling(self, leafs: LeafSize) -> Option<LeafSize> {
        NodeSize::from(self)
            .sibling(leafs)
            .map(|n| LeafSize::try_from(n).expect("leaf's sibling must be leaf"))
    }

    #[inline]
    pub fn node_index(self) -> usize {
        self.0 as usize * 2
    }
}

impl ParentSize {
    #[inline]
    pub fn node_index(self) -> usize {
        self.0 as usize * 2 + 1
    }

    /// The left child of an intermediate node.  Note that because the
    /// tree is left-balanced, there is no dependency on the size of the
    /// tree.
    #[inline]
    pub fn left(self) -> NodeSize {
        let x = self.0 * 2 + 1;
        let lvl = level(x);
        // 01x -> 00x
        NodeSize(x ^ (0b01 << (lvl - 1)))
    }

    /// The right child of an intermediate node.  Depends on the size of
    /// the tree because the straightforward calculation can take you
    /// beyond the edge of the tree.
    #[inline]
    pub fn right(self, leafs: LeafSize) -> NodeSize {
        let x = self.0 * 2 + 1;
        let lvl = level(x);
        let nodes = NodeSize::node_width(leafs);
        // 01x -> 10x
        let mut n = NodeSize(x ^ (0b11 << (lvl - 1)));
        while n >= nodes {
            // if `n` is leaf node, we'll have: `n = p + 1` and `p < nodes`,
            // since both `nodes` and `p` are odd, we'll have `n < nodes` too.
            // So `n` can't be leaf node here.
            let p = ParentSize::try_from(n).expect("won't be leaf child");
            n = p.left();
        }
        n
    }

    pub fn sibling(self, leafs: LeafSize) -> Option<ParentSize> {
        NodeSize::from(self)
            .sibling(leafs)
            .map(|n| ParentSize::try_from(n).expect("parent's sibling must be parent"))
    }

    pub fn level(self) -> u32 {
        level(self.0) + 1
    }

    /// Common ancestor of two leaves
    ///
    /// return None if leaf == right.
    pub fn common_ancestor(left: LeafSize, right: LeafSize) -> Option<Self> {
        let mut left = left.0;
        let mut right = right.0;
        let mut k = 1;
        while left != right {
            left >>= 1;
            right >>= 1;
            k += 1;
        }
        if k >= 2 {
            Some(ParentSize((left << (k - 1)) + (1 << (k - 2)) - 1))
        } else {
            None
        }
    }
}

impl NodeSize {
    #[inline]
    pub fn node_type(self) -> NodeType {
        if self.0 % 2 == 1 {
            NodeType::Parent(ParentSize((self.0 - 1) / 2))
        } else {
            NodeType::Leaf(LeafSize(self.0 / 2))
        }
    }

    #[inline]
    pub fn node_index(self) -> usize {
        self.0 as usize
    }

    /// The index of the root node of a tree with n nodes
    /// return None for zero leafs.
    ///
    /// ```
    /// use mls::tree_math::{LeafSize, NodeSize};
    /// assert_eq!(NodeSize::root(LeafSize(0)).0, 0);
    /// assert_eq!(NodeSize::root(LeafSize(1)).0, 0);
    /// assert_eq!(NodeSize::root(LeafSize(0b10001)).0, 0b011111);
    /// ```
    #[inline]
    pub fn root(leafs: LeafSize) -> Self {
        let nodes = NodeSize::node_width(leafs);
        let lvl = log2(nodes.0);
        NodeSize((1 << lvl) - 1)
    }

    #[inline]
    pub fn leafs_len(self) -> Option<LeafSize> {
        if self.0 % 2 == 0 {
            None
        } else {
            Some(LeafSize((self.0 + 1) / 2))
        }
    }

    /// The number of nodes needed to represent a tree with n leaves
    #[inline]
    pub fn node_width(leafs: LeafSize) -> NodeSize {
        if leafs.0 == 0 {
            NodeSize(0)
        } else {
            NodeSize(leafs.0 + leafs.0 - 1)
        }
    }

    /// The level of a node in the tree. Leaves are level 0, their parents are
    /// level 1, etc. If a node's children are at different levels, then its
    /// level is the max level of its children plus one.
    #[inline]
    pub fn level(self) -> u32 {
        level(self.0)
    }

    /// The parent of a node.  As with the right child calculation, have
    /// to walk back until the parent is within the range of the tree.
    ///
    /// ```
    /// use mls::tree_math::*;
    /// assert_eq!(NodeSize(0b10001).parent(LeafSize(11)), Some(ParentSize(0b1001)));
    /// assert_eq!(NodeSize(0b10001).parent(LeafSize(10)), Some(ParentSize(0b0111)));
    /// assert_eq!(NodeSize(0b01011).parent(LeafSize(7)), Some(ParentSize(0b0011)));
    /// ```
    #[inline]
    pub fn parent(self, leafs: LeafSize) -> Option<ParentSize> {
        let nodes = NodeSize::node_width(leafs);
        assert!(self < nodes);
        if self == NodeSize::root(leafs) {
            return None;
        }
        let mut p = parent_step(self.0);
        while p >= nodes.0 {
            p = parent_step(p);
        }
        Some(ParentSize((p - 1) / 2))
    }

    /// The direct path of a node, ordered from the root
    /// down, including the root, not including self
    ///
    /// Only root node returns empty vector
    #[inline]
    pub fn direct_path(self, leafs: LeafSize) -> Vec<ParentSize> {
        if let Some(p) = self.parent(leafs) {
            iter::successors(Some(p), |&p| NodeSize::from(p).parent(leafs)).collect()
        } else {
            Vec::new()
        }
    }

    /// The other child of the node's parent.  Root's sibling is itself.
    ///
    /// Only root node returns None
    pub fn sibling(self, leafs: LeafSize) -> Option<NodeSize> {
        let p = self.parent(leafs)?;
        if self < NodeSize::from(p) {
            Some(p.right(leafs))
        } else {
            Some(p.left())
        }
    }
}

/// The exponent of the largest power of 2 less than x. Equivalent to:
///  int(math.floor(math.log(x, 2)))
///
/// return the index of the leading one bit, if all zero, return None.
///
/// ```
/// use mls::tree_math::*;
/// assert_eq!(log2(0), 0);
/// assert_eq!(log2(1), 0);
/// assert_eq!(log2(0b100001), 5);
/// ```
pub fn log2(x: u32) -> u32 {
    // FIXME after leading_trailing_ones get stablized
    // let msb = std::mem::size_of::<NodeSize>() as u32 * 8 - x.leading_zeros();
    // msb.saturating_sub(1)
    if x == 0 {
        return 0;
    }

    let mut k = 0;
    while (x >> k) > 0 {
        k += 1
    }
    k - 1
}

pub fn level(x: u32) -> u32 {
    // FIXME after leading_trailing_ones get stablized
    // let n = x.trailing_ones();
    let mut k = 0;
    while ((x >> k) & 0x01) == 1 {
        k += 1;
    }
    k
}

/// The immediate parent of a node.  May be beyond the right edge of
/// the tree.
///
/// Turning 00X or 10X to 01X
/// where X is sequence of ones
///
/// ```
/// use mls::tree_math::*;
/// assert_eq!(parent_step(0b10011), 0b10111);
/// assert_eq!(parent_step(0b11011), 0b10111);
/// ```
pub fn parent_step(x: u32) -> u32 {
    let lvl = level(x);
    let mask = ((x >> (lvl + 1)) & 0x01) << (lvl + 1);
    (x | (1 << lvl)) ^ mask
}

#[cfg(test)]
mod test {
    use super::{log2, LeafSize, NodeSize, ParentSize};
    use std::convert::TryFrom;

    #[test]
    fn test_tree_math() {
        // Precomputed answers for the tree on eleven elements
        // adapted from https://github.com/cisco/go-mls/blob/master/tree-math_test.go
        let a_root = vec![
            0x00, 0x01, 0x03, 0x03, 0x07, 0x07, 0x07, 0x07, 0x0f, 0x0f, 0x0f,
        ];
        let a_log2 = vec![
            0x00, 0x00, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
            0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04,
        ];
        let a_level = vec![
            0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01,
            0x00, 0x04, 0x00, 0x01, 0x00, 0x02, 0x00,
        ];
        let a_left = vec![
            None,
            Some(0x00),
            None,
            Some(0x01),
            None,
            Some(0x04),
            None,
            Some(0x03),
            None,
            Some(0x08),
            None,
            Some(0x09),
            None,
            Some(0x0c),
            None,
            Some(0x07),
            None,
            Some(0x10),
            None,
            Some(0x11),
            None,
        ];
        let a_right = vec![
            None,
            Some(0x02),
            None,
            Some(0x05),
            None,
            Some(0x06),
            None,
            Some(0x0b),
            None,
            Some(0x0a),
            None,
            Some(0x0d),
            None,
            Some(0x0e),
            None,
            Some(0x13),
            None,
            Some(0x12),
            None,
            Some(0x14),
            None,
        ];
        let a_parent = vec![
            Some(0x01),
            Some(0x03),
            Some(0x01),
            Some(0x07),
            Some(0x05),
            Some(0x03),
            Some(0x05),
            Some(0x0f),
            Some(0x09),
            Some(0x0b),
            Some(0x09),
            Some(0x07),
            Some(0x0d),
            Some(0x0b),
            Some(0x0d),
            None,
            Some(0x11),
            Some(0x13),
            Some(0x11),
            Some(0x0f),
            Some(0x13),
        ];
        let a_sibling = vec![
            Some(0x02),
            Some(0x05),
            Some(0x00),
            Some(0x0b),
            Some(0x06),
            Some(0x01),
            Some(0x04),
            Some(0x13),
            Some(0x0a),
            Some(0x0d),
            Some(0x08),
            Some(0x03),
            Some(0x0e),
            Some(0x09),
            Some(0x0c),
            None,
            Some(0x12),
            Some(0x14),
            Some(0x10),
            Some(0x07),
            Some(0x11),
        ];
        let a_dirpath = [
            vec![0x01, 0x03, 0x07, 0x0f],
            vec![0x03, 0x07, 0x0f],
            vec![0x01, 0x03, 0x07, 0x0f],
            vec![0x07, 0x0f],
            vec![0x05, 0x03, 0x07, 0x0f],
            vec![0x03, 0x07, 0x0f],
            vec![0x05, 0x03, 0x07, 0x0f],
            vec![0x0f],
            vec![0x09, 0x0b, 0x07, 0x0f],
            vec![0x0b, 0x07, 0x0f],
            vec![0x09, 0x0b, 0x07, 0x0f],
            vec![0x07, 0x0f],
            vec![0x0d, 0x0b, 0x07, 0x0f],
            vec![0x0b, 0x07, 0x0f],
            vec![0x0d, 0x0b, 0x07, 0x0f],
            vec![],
            vec![0x11, 0x13, 0x0f],
            vec![0x13, 0x0f],
            vec![0x11, 0x13, 0x0f],
            vec![0x0f],
            vec![0x13, 0x0f],
        ];
        let a_n = 0x0b;
        for n in 1..a_n {
            assert_eq!(NodeSize::root(LeafSize(n)).0, a_root[n as usize - 1])
        }
        for i in 0x00..0x14 {
            let x = NodeSize(i);
            let leafs = LeafSize(a_n);
            assert_eq!(a_log2[i as usize], log2(i));
            assert_eq!(a_level[i as usize], x.level());
            assert_eq!(
                a_left[i as usize],
                ParentSize::try_from(x).ok().map(|p| p.left().0)
            );
            assert_eq!(
                a_right[i as usize],
                ParentSize::try_from(x).ok().map(|p| p.right(leafs).0)
            );
            assert_eq!(
                a_parent[i as usize],
                x.parent(leafs).map(|p| NodeSize::from(p).0)
            );
            assert_eq!(a_sibling[i as usize], x.sibling(leafs).map(|x| x.0));
            assert_eq!(
                a_dirpath[i as usize],
                x.direct_path(leafs)
                    .into_iter()
                    .map(|x| NodeSize::from(x).0)
                    .collect::<Vec<_>>()
            );
        }

        let a_ancestor = vec![
            vec![0x01, 0x03, 0x03, 0x07, 0x07, 0x07, 0x07, 0x0f, 0x0f, 0x0f],
            vec![0x03, 0x03, 0x07, 0x07, 0x07, 0x07, 0x0f, 0x0f, 0x0f],
            vec![0x05, 0x07, 0x07, 0x07, 0x07, 0x0f, 0x0f, 0x0f],
            vec![0x07, 0x07, 0x07, 0x07, 0x0f, 0x0f, 0x0f],
            vec![0x09, 0x0b, 0x0b, 0x0f, 0x0f, 0x0f],
            vec![0x0b, 0x0b, 0x0f, 0x0f, 0x0f],
            vec![0x0d, 0x0f, 0x0f, 0x0f],
            vec![0x0f, 0x0f, 0x0f],
            vec![0x11, 0x13],
            vec![0x13],
        ];
        for l in 0..a_n {
            for r in l + 1..a_n {
                assert_eq!(
                    a_ancestor[l as usize][(r - l - 1) as usize],
                    NodeSize::from(ParentSize::common_ancestor(LeafSize(l), LeafSize(r)).unwrap())
                        .0
                );
            }
        }
    }
}
