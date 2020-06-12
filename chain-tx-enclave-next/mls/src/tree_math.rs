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
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LeafSize(pub usize);

impl LeafSize {
    /// compute leaf size from node size
    pub fn from_nodes(nodes: NodeSize) -> Option<LeafSize> {
        if nodes.0 % 2 == 1 {
            Some(LeafSize((nodes.0 + 1) / 2))
        } else {
            None
        }
    }

    /// convert node index to leaf index
    #[inline]
    pub fn from_node_index(node_index: NodeSize) -> Option<LeafSize> {
        if node_index.0 % 2 == 0 {
            Some(LeafSize(node_index.0 / 2))
        } else {
            None
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeSize(pub usize);

impl NodeSize {
    /// The number of nodes needed to represent a tree with n leaves
    #[inline]
    pub fn node_width(n: LeafSize) -> NodeSize {
        if n.0 == 0 {
            NodeSize(0)
        } else {
            NodeSize(n.0 + n.0 - 1)
        }
    }

    /// convert leaf index to node index
    #[inline]
    pub fn from_leaf_index(leaf_index: LeafSize) -> NodeSize {
        NodeSize(leaf_index.0 * 2)
    }

    /// The level of a node in the tree. Leaves are level 0, their parents are
    /// level 1, etc. If a node's children are at different levels, then its
    /// level is the max level of its children plus one.
    #[inline]
    pub fn level(self) -> u32 {
        let x = self.0;
        // FIXME after leading_trailing_ones get stablized
        // let n = x.trailing_ones();
        let mut k = 0;
        while ((x >> k) & 0x01) == 1 {
            k += 1;
        }
        k
    }

    /// The left child of an intermediate node.  Note that because the
    /// tree is left-balanced, there is no dependency on the size of the
    /// tree.
    #[inline]
    pub fn left(self) -> Option<NodeSize> {
        let lvl = self.level();
        if lvl == 0 {
            None
        } else {
            let x = lvl - 1;
            // 01x -> 00x
            Some(NodeSize(self.0 ^ (0b01 << x)))
        }
    }

    /// The right child of an intermediate node.  Depends on the size of
    /// the tree because the straightforward calculation can take you
    /// beyond the edge of the tree.
    #[inline]
    pub fn right(self, leafs: LeafSize) -> Option<NodeSize> {
        let lvl = self.level();
        if lvl == 0 {
            None
        } else {
            let nodes = NodeSize::node_width(leafs);
            // 01x -> 10x
            let mut r = NodeSize(self.0 ^ (0b11 << (lvl - 1)));
            while r >= nodes {
                r = r.left()?;
            }
            Some(r)
        }
    }

    /// The exponent of the largest power of 2 less than x. Equivalent to:
    ///  int(math.floor(math.log(x, 2)))
    ///
    /// return the index of the leading one bit, if all zero, return None.
    ///
    /// ```
    /// use mls::tree_math::*;
    /// assert_eq!(NodeSize(0).log2(), 0);
    /// assert_eq!(NodeSize(1).log2(), 0);
    /// assert_eq!(NodeSize(0b100001).log2(), 5);
    /// ```
    #[inline]
    pub fn log2(self: NodeSize) -> u32 {
        // FIXME after leading_trailing_ones get stablized
        // let msb = std::mem::size_of::<NodeSize>() as u32 * 8 - x.leading_zeros();
        // msb.saturating_sub(1)
        let x = self.0;
        if x == 0 {
            return 0;
        }

        let mut k = 0;
        while (x >> k) > 0 {
            k += 1
        }
        k - 1
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
    pub fn root(leafs: LeafSize) -> NodeSize {
        let nodes = NodeSize::node_width(leafs);
        let lvl = nodes.log2();
        NodeSize((1 << lvl) - 1)
    }

    /// The immediate parent of a node.  May be beyond the right edge of
    /// the tree.
    ///
    /// Turning 00X or 10X to 01X
    /// where X is sequence of ones
    ///
    /// ```
    /// use mls::tree_math::*;
    /// assert_eq!(NodeSize(0b10011).parent_step().0, 0b10111);
    /// assert_eq!(NodeSize(0b11011).parent_step().0, 0b10111);
    /// ```
    #[inline]
    pub fn parent_step(self) -> NodeSize {
        let lvl = self.level();
        let x = self.0;
        let mask = ((x >> (lvl + 1)) & 0x01) << (lvl + 1);
        NodeSize((x | (1 << lvl)) ^ mask)
    }

    /// The parent of a node.  As with the right child calculation, have
    /// to walk back until the parent is within the range of the tree.
    ///
    /// ```
    /// use mls::tree_math::*;
    /// assert_eq!(NodeSize(0b10001).parent(LeafSize(11)), Some(NodeSize(0b10011)));
    /// assert_eq!(NodeSize(0b10001).parent(LeafSize(10)), Some(NodeSize(0b01111)));
    /// assert_eq!(NodeSize(0b01011).parent(LeafSize(7)), Some(NodeSize(0b00111)));
    /// ```
    #[inline]
    pub fn parent(self, leafs: LeafSize) -> Option<NodeSize> {
        let nodes = NodeSize::node_width(leafs);
        assert!(self < nodes);
        if self == NodeSize::root(leafs) {
            return None;
        }
        let mut p = self.parent_step();
        while p >= nodes {
            p = p.parent_step();
        }
        Some(p)
    }

    /// The direct path of a node, ordered from the root
    /// down, including the root, not including self
    ///
    /// Only root node returns empty vector
    #[inline]
    pub fn direct_path(self, leafs: LeafSize) -> Vec<NodeSize> {
        let root = NodeSize::root(leafs);
        let mut d = Vec::new();
        let mut p = self;
        while p != root {
            // no panic: only root node returns `None`, p is not root node because of the while
            // condition.
            p = p.parent(leafs).unwrap();
            d.push(p);
        }
        d
    }

    /// The other child of the node's parent.  Root's sibling is itself.
    ///
    /// Only root node returns None
    pub fn sibling(self, leafs: LeafSize) -> Option<NodeSize> {
        if let Some(p) = self.parent(leafs) {
            if self < p {
                p.right(leafs)
            } else {
                // impossible they are equal
                assert!(self > p);
                p.left()
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::{LeafSize, NodeSize};

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
            assert_eq!(NodeSize::root(LeafSize(n)).0, a_root[n - 1])
        }
        for i in 0x00..0x14 {
            let x = NodeSize(i);
            assert_eq!(a_log2[i], x.log2());
            assert_eq!(a_level[i], x.level());
            assert_eq!(a_left[i], x.left().map(|x| x.0));
            assert_eq!(a_right[i], x.right(LeafSize(a_n)).map(|x| x.0));
            assert_eq!(a_parent[i], x.parent(LeafSize(a_n)).map(|x| x.0));
            assert_eq!(a_sibling[i], x.sibling(LeafSize(a_n)).map(|x| x.0));
            assert_eq!(
                a_dirpath[i],
                x.direct_path(LeafSize(a_n))
                    .into_iter()
                    .map(|x| x.0)
                    .collect::<Vec<_>>()
            );
        }
    }
}
