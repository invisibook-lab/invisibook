//! Client-side note commitment tree.
//!
//! `Frontier` is the O(depth) incremental state (what the chain also keeps):
//! enough to append leaves and produce the current root. `NoteTree` keeps
//! every leaf so the wallet can produce Merkle paths for its own notes.
//!
//! Conventions (pinned by `spec/golden.json`):
//! - interior node = `P2(left, right)`;
//! - path bit `i` = bit `i` of the leaf index, little-endian (bit 0 nearest
//!   the leaf); bit 0 means "I am the left child at this level", so the
//!   sibling goes on the right — circomlib `DualMux` order.

use ark_bn254::Fr;
use zk::wallet::poseidon2;

use crate::note::{TREE_DEPTH, empty_roots};

/// O(depth) incremental frontier: append-only, yields the root after every
/// append. Mirrors Go `chain/core/pool.go`'s frontier byte-for-byte.
#[derive(Debug, Clone)]
pub struct Frontier {
    /// `filled[level]` = root of the completed left sibling subtree at
    /// `level`, for the subtree the next leaf will extend.
    filled: [Fr; TREE_DEPTH],
    size: u64,
    root: Fr,
    empty: [Fr; TREE_DEPTH + 1],
}

impl Default for Frontier {
    fn default() -> Self {
        Self::new()
    }
}

impl Frontier {
    /// An empty tree; `root()` equals `EMPTY_ROOTS[TREE_DEPTH]`.
    pub fn new() -> Self {
        let empty = empty_roots();
        Frontier {
            filled: [empty[0]; TREE_DEPTH],
            size: 0,
            root: empty[TREE_DEPTH],
            empty,
        }
    }

    /// Number of leaves appended so far.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Current root over all appended leaves (empty-padded to full depth).
    pub fn root(&self) -> Fr {
        self.root
    }

    /// Append a leaf; returns its leaf index. Panics when the tree is full
    /// (2^TREE_DEPTH leaves) — callers must reject inserts before that.
    pub fn append(&mut self, leaf: Fr) -> u64 {
        assert!(
            self.size < 1u64 << TREE_DEPTH,
            "note tree is full ({} leaves)",
            self.size
        );
        let index = self.size;
        let mut cur = leaf;
        for level in 0..TREE_DEPTH {
            if (index >> level) & 1 == 0 {
                // Left child: remember it for the future right sibling and
                // pad the right side with the empty subtree for now.
                self.filled[level] = cur;
                cur = poseidon2(cur, self.empty[level]);
            } else {
                cur = poseidon2(self.filled[level], cur);
            }
        }
        self.size += 1;
        self.root = cur;
        index
    }
}

/// Full client-side tree: all leaves, so any leaf's Merkle path can be
/// produced. The wallet rebuilds it from the chain's `GetNotes` range read.
#[derive(Debug, Clone, Default)]
pub struct NoteTree {
    leaves: Vec<Fr>,
}

impl NoteTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Append a leaf, returning its index.
    pub fn append(&mut self, leaf: Fr) -> u64 {
        assert!(
            (self.leaves.len() as u64) < 1u64 << TREE_DEPTH,
            "note tree is full"
        );
        self.leaves.push(leaf);
        self.leaves.len() as u64 - 1
    }

    /// Root over the current leaves (empty-padded to full depth).
    pub fn root(&self) -> Fr {
        let empty = empty_roots();
        let mut level: Vec<Fr> = self.leaves.clone();
        for d in 0..TREE_DEPTH {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                let left = pair[0];
                let right = if pair.len() == 2 { pair[1] } else { empty[d] };
                next.push(poseidon2(left, right));
            }
            if next.is_empty() {
                next.push(empty[d + 1]);
            }
            level = next;
        }
        level[0]
    }

    /// Merkle path of `leaf_index`: `(siblings, index_bits)` with the
    /// conventions in the module docs. `leaf_index` must be < `len()`.
    pub fn path(&self, leaf_index: u64) -> ([Fr; TREE_DEPTH], [bool; TREE_DEPTH]) {
        assert!(leaf_index < self.len(), "leaf index out of range");
        let empty = empty_roots();
        let mut siblings = [empty[0]; TREE_DEPTH];
        let mut bits = [false; TREE_DEPTH];
        let mut level: Vec<Fr> = self.leaves.clone();
        let mut pos = leaf_index as usize;
        for d in 0..TREE_DEPTH {
            let is_right = pos & 1 == 1;
            bits[d] = is_right;
            let sib_pos = if is_right { pos - 1 } else { pos + 1 };
            siblings[d] = if sib_pos < level.len() {
                level[sib_pos]
            } else {
                empty[d]
            };
            // Build the next level.
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                let left = pair[0];
                let right = if pair.len() == 2 { pair[1] } else { empty[d] };
                next.push(poseidon2(left, right));
            }
            if next.is_empty() {
                next.push(empty[d + 1]);
            }
            level = next;
            pos >>= 1;
        }
        (siblings, bits)
    }

    /// Recompute a root from a leaf and its path — the check the circuit
    /// performs; exposed for tests and recovery flows.
    pub fn root_from_path(leaf: Fr, siblings: &[Fr; TREE_DEPTH], bits: &[bool; TREE_DEPTH]) -> Fr {
        let mut cur = leaf;
        for d in 0..TREE_DEPTH {
            cur = if bits[d] {
                poseidon2(siblings[d], cur)
            } else {
                poseidon2(cur, siblings[d])
            };
        }
        cur
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::{asset_id, fr_from_be_bytes, note_commit, note_fr_to_hex, npk_from_sk};
    use serde_json::Value;

    fn golden() -> Value {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/golden.json"
        ))
        .expect("spec/golden.json must exist");
        serde_json::from_str(&raw).expect("golden.json must parse")
    }

    fn golden_leaves() -> [Fr; 3] {
        let sk1 = fr_from_be_bytes(&[0x42; 32]);
        let sk2 = fr_from_be_bytes(&[0x43; 32]);
        let eth = asset_id("ETH").unwrap();
        let usdt = asset_id("USDT").unwrap();
        [
            note_commit(npk_from_sk(sk1), eth, 7, fr_from_be_bytes(&[0x33; 32])),
            note_commit(
                npk_from_sk(sk2),
                usdt,
                1_000_000,
                fr_from_be_bytes(&[0x34; 32]),
            ),
            note_commit(npk_from_sk(sk1), eth, 5, fr_from_be_bytes(&[0x35; 32])),
        ]
    }

    #[test]
    fn golden_root_frontier_and_full_tree_agree() {
        let g = golden();
        let leaves = golden_leaves();

        let mut frontier = Frontier::new();
        let mut tree = NoteTree::new();
        for (i, l) in leaves.iter().enumerate() {
            assert_eq!(frontier.append(*l), i as u64);
            assert_eq!(tree.append(*l), i as u64);
        }
        let expected = g["root_after_3"].as_str().unwrap();
        assert_eq!(note_fr_to_hex(&frontier.root()), expected);
        assert_eq!(note_fr_to_hex(&tree.root()), expected);
    }

    #[test]
    fn golden_path_of_leaf1() {
        let g = golden();
        let leaves = golden_leaves();
        let mut tree = NoteTree::new();
        for l in leaves {
            tree.append(l);
        }
        let (siblings, bits) = tree.path(1);

        let want_path: Vec<String> = g["path_leaf1"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let want_bits: Vec<bool> = g["bits_leaf1"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_i64().unwrap() == 1)
            .collect();
        for d in 0..TREE_DEPTH {
            assert_eq!(note_fr_to_hex(&siblings[d]), want_path[d], "sibling {d}");
            assert_eq!(bits[d], want_bits[d], "bit {d}");
        }
        assert_eq!(
            note_fr_to_hex(&NoteTree::root_from_path(leaves[1], &siblings, &bits)),
            g["root_after_3"].as_str().unwrap()
        );
    }

    #[test]
    fn empty_tree_root_is_empty_root() {
        let g = golden();
        assert_eq!(
            note_fr_to_hex(&Frontier::new().root()),
            g["empty_root_20"].as_str().unwrap()
        );
        assert_eq!(
            note_fr_to_hex(&NoteTree::new().root()),
            g["empty_root_20"].as_str().unwrap()
        );
    }
}
