use crate::constants::LEAF_NODE_LIMIT;
use crate::crypto::sha3_256;
use crate::primitives::transaction::Transaction;
use crate::utils::transaction_utils::construct_tx_hash;
use bincode::serialize;
use bytes::Bytes;
use std::cmp::min;
use std::vec::Vec;

#[derive(Debug)]
pub struct MerkleTree {
    pub root: String,
    pub tree: Vec<Vec<String>>,
    pub depth: usize,
}

impl MerkleTree {
    pub fn new(transactions: &[String]) -> MerkleTree {
        let full_tx = grow_to_square(transactions);
        let depth = (full_tx.len() as f32).log2().ceil() as usize;
        let mut num_nodes = full_tx.len();

        // + 2 because we need an extra space for metaroot hash
        let mut tree: Vec<Vec<String>> = Vec::with_capacity(depth + 2);
        tree.push(full_tx);

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

    /// Gets the audit path of a transaction in the merkle tree
    ///
    /// ### Arguments
    ///
    /// * `tx_hash` - Hash of the transaction to get the audit path of
    pub fn get_audit_path(&self, tx_hash: &str) -> Vec<String> {
        let index = self.get_index_of_tx(tx_hash);

        if let Some(mut index) = index {
            let mut audit_path = Vec::new();
            let mut next_hash = tx_hash.to_string();

            for level in 0..self.depth {
                let left_child_index = if index % 2 == 1 { index - 1 } else { index };
                let right_child_index = min(left_child_index + 1, self.tree[level].len() - 1);

                let left_child = self.tree[level][left_child_index].clone();
                let right_child = self.tree[level][right_child_index].clone();

                if left_child == next_hash {
                    audit_path.push(left_child.clone());
                } else if right_child == next_hash {
                    audit_path.push(right_child.clone());
                }

                index = index / 2;
                next_hash = hash_node(&left_child, &right_child);
            }

            return audit_path;
        }

        vec![]
    }

    /// Gets the index of a transaction in the merkle tree leaf nodes
    ///
    /// NOTE: Iteration will be slow if the tree is large. Benchmarking is needed to
    /// discover what "large" means. For large trees, switch to depth first search
    ///
    /// ### Arguments
    ///
    /// * `tx_hash` - Hash of the transaction to get the index of
    fn get_index_of_tx(&self, tx_hash: &str) -> Option<usize> {
        if self.tree[0].len() < LEAF_NODE_LIMIT {
            return self.tree[0].iter().position(|x| x == tx_hash);
        }

        let mut index = 0;

        // Perform depth first search to find the index
        for level in 0..self.depth {
            let left_child_index = index * 2;
            let right_child_index = min(left_child_index + 1, self.tree[level].len() - 1);

            let left_child = self.tree[level][left_child_index].clone();
            let right_child = self.tree[level][right_child_index].clone();

            if left_child == tx_hash {
                return Some(left_child_index);
            } else if right_child == tx_hash {
                return Some(right_child_index);
            }

            index = index * 2;
        }

        None
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

/// Duplicates the last transaction in the list until the number of transactions is a power of 2
///
/// ### Arguments
///
/// * `txs` - List of transactions to grow
fn grow_to_square(txs: &[String]) -> Vec<String> {
    let mut txs = txs.to_vec();
    let mut num_txs = txs.len();

    if num_txs != 0 && !is_power_of_2(num_txs as u32) {
        let total = next_power_of_two(num_txs);

        while num_txs < total {
            let last_tx = txs.last().unwrap().clone();
            txs.push(last_tx);
            num_txs += 1;
        }
    }

    txs
}

/// Checks if a number is a power of 2
///
/// ### Arguments
///
/// * `n` - Number to check
fn is_power_of_2(n: u32) -> bool {
    (n != 0) && (n & (n - 1) == 0)
}

/// Gets the next power of 2
///
/// ### Arguments
///
/// * `n` - Number to get the next power of 2 of
fn next_power_of_two(n: usize) -> usize {
    let mut m = n - 1;
    m |= m >> 1;
    m |= m >> 2;
    m |= m >> 4;
    m |= m >> 8;
    m |= m >> 16;
    m + 1
}

/*---- TESTS ----*/

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    fn create_tx() -> String {
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            version: 0,
            druid_info: None,
        };

        construct_tx_hash(&tx)
    }

    fn create_random_hash() -> String {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes[..]);

        hex::encode(bytes)
    }

    #[test]
    fn should_construct_valid_merkle_tree() {
        let txs = [create_tx(), create_tx(), create_tx(), create_tx()];
        let mt = MerkleTree::new(&txs);

        assert_eq!(mt.depth, 3);
        assert_eq!(mt.tree.len(), mt.depth);
        assert_eq!(mt.tree[0].len(), 4);
        assert_eq!(mt.tree[1].len(), 2);
        assert_eq!(mt.tree[2].len(), 1);
        assert_eq!(
            mt.root,
            "e00dd9bb3ae6602667f78469ea594c9ed0b70847b94c5ec76247e6f3868c4669".to_string()
        );
    }

    #[test]
    fn should_get_valid_audit_path() {
        let txs = [
            create_random_hash(),
            create_random_hash(),
            create_random_hash(),
            create_random_hash(),
            create_random_hash(),
        ];
        let mt = MerkleTree::new(&txs);

        let audit_path = mt.get_audit_path(&txs[1]);

        let s_entry = hash_node(&txs[0], &txs[1]);
        let s_entry_pair = hash_node(&txs[2], &txs[3]);
        let t_entry = hash_node(&s_entry, &s_entry_pair);

        assert_eq!(audit_path.len(), 4);
        assert_eq!(audit_path[0], txs[1]);
        assert_eq!(audit_path[1], s_entry);
        assert_eq!(audit_path[2], t_entry);
    }
}
