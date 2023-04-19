use crate::crypto::sha3_256;
use crate::primitives::transaction::Transaction;
use crate::utils::transaction_utils::construct_tx_hash;
use bincode::serialize;
use bytes::Bytes;
use std::cmp::min;
use std::vec::Vec;

pub struct MerkleTree {
    pub root: String,
    pub tree: Vec<Vec<String>>,
    pub depth: usize,
}

impl MerkleTree {
    pub fn new(transactions: &[String]) -> MerkleTree {
        let depth = (transactions.len() as f32).log2().ceil() as usize;
        let mut num_nodes = transactions.len();

        // + 2 because we need an extra space for metaroot hash
        let mut tree: Vec<Vec<String>> = Vec::with_capacity(depth + 2);
        tree.push(transactions.to_vec());

        if transactions.len() % 2 == 1 {
            let dup = transactions.last().unwrap().clone();
            tree[0].push(dup);
        }

        // Build hash tree up to root
        for level in 0..depth {
            let next_nodes = num_nodes / 2;
            let mut parent_hashes = Vec::with_capacity(next_nodes);

            for j in 0..next_nodes {
                let left_child_index = j * 2;
                let right_child_index = min(left_child_index + 1, num_nodes - 1);

                let left_child = tree[level][left_child_index].clone();
                let right_child = tree[level][right_child_index].clone();

                let parent_hash = hash_node(&left_child, &right_child);
                parent_hashes.push(parent_hash);
            }

            tree.push(parent_hashes);
            num_nodes = next_nodes;
        }

        MerkleTree {
            root: tree[depth][0].clone(),
            tree,
            depth: depth + 1,
        }
    }

    /// Adds the coinbase transaction and metaroot to the merkle tree
    ///
    /// ### Arguments
    ///
    /// * `coinbase` - Coinbase transaction to add
    fn add_coinbase(&mut self, coinbase: &Transaction) {
        let coinbase_hash = construct_tx_hash(coinbase);
        self.tree[self.depth].push(coinbase_hash);

        let metaroot = hash_node(&self.tree[self.depth][0], &self.tree[self.depth][1]);
        self.tree.push(vec![metaroot]);
    }
}

/// Hashes two nodes as strings together using SHA3-256
///
/// ### Arguments
///
/// * `left` - Left node to hash
/// * `right` - Right node to hash
fn hash_node(left: &str, right: &str) -> String {
    let concat = Bytes::from(serialize(&vec![left, right]).unwrap());
    hex::encode(sha3_256::digest(&concat))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_tx() -> String {
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            version: 0,
            druid_info: None,
        };

        construct_tx_hash(&tx)
    }

    #[test]
    fn should_construct_valid_merkle_tree() {
        let txs = [create_tx(), create_tx(), create_tx(), create_tx()];
        let mt = MerkleTree::new(&txs);

        println!("{:?}", mt.tree);

        assert_eq!(mt.depth, 3);
        assert_eq!(mt.tree.len(), 3);
        assert_eq!(mt.tree[0].len(), 4);
        assert_eq!(mt.tree[1].len(), 2);
        assert_eq!(mt.tree[2].len(), 1);
        assert_eq!(
            mt.root,
            "e00dd9bb3ae6602667f78469ea594c9ed0b70847b94c5ec76247e6f3868c4669".to_string()
        );
    }
}
