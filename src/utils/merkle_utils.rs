use crate::crypto::sha3_256;
use crate::primitives::transaction::Transaction;
use crate::utils::transaction_utils::construct_tx_hash;
use bincode::serialize;
use bytes::Bytes;
use rayon::prelude::*;
use std::cmp::min;
use std::vec::Vec;

/// Hashes a list of transactions in parallel. This will duplicate the last transaction hash if the
/// number of transactions is odd.
///
/// ### Arguments
///
/// * `transactions` - List of transactions to hash
fn hash_transactions(transactions: &[Transaction]) -> Vec<String> {
    let mut hashes: Vec<String> = transactions
        .par_iter()
        .map(|tx| construct_tx_hash(tx))
        .collect();

    if transactions.len() % 2 == 1 {
        let dup = hashes.last().unwrap().clone();
        hashes.push(dup);
    }

    hashes
}

/// Constructs a Merkle tree from a list of transactions and the coinbase transaction
///
/// ### Arguments
///
/// * `transactions` - List of transactions to hash
/// * `coinbase` - Coinbase transaction to add
pub fn build_hash_tree(transactions: &[Transaction], coinbase: &Transaction) -> Vec<Vec<String>> {
    let depth = (transactions.len() as f32).log2().ceil() as usize;
    let mut num_nodes = transactions.len();

    // + 2 because we need an extra space for metaroot hash
    let mut tree = Vec::with_capacity(depth + 2);
    tree.push(hash_transactions(transactions));

    // Build hash tree up to root
    for i in 0..depth {
        let next_nodes = num_nodes / 2;
        let mut parent_hashes = Vec::with_capacity(next_nodes);

        for j in 0..next_nodes {
            let left_child_index = j * 2;
            let right_child_index = min(left_child_index + 1, num_nodes - 1);

            let left_child = tree[i][left_child_index].clone();
            let right_child = tree[i][right_child_index].clone();

            let parent_hash = hash_node(&left_child, &right_child);
            parent_hashes.push(parent_hash);
        }

        tree.push(parent_hashes);
        num_nodes = next_nodes;
    }

    // Add coinbase and metaroot
    add_coinbase_and_metaroot(&mut tree, coinbase, depth);

    tree
}

/// Adds the coinbase transaction and metaroot to the merkle tree
///
/// ### Arguments
///
/// * `tree` - Merkle tree to add coinbase and metaroot to
/// * `coinbase` - Coinbase transaction to add
/// * `depth` - Depth of the merkle tree
fn add_coinbase_and_metaroot(tree: &mut Vec<Vec<String>>, coinbase: &Transaction, depth: usize) {
    let coinbase_hash = construct_tx_hash(coinbase);
    tree[depth].push(coinbase_hash);

    let metaroot = hash_node(&tree[depth][0], &tree[depth][1]);
    tree.push(vec![metaroot]);
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

    fn create_tx() -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![],
            version: 0,
            druid_info: None,
        }
    }

    #[test]
    fn should_construct_valid_merkle_tree() {
        let txs = vec![create_tx(), create_tx(), create_tx(), create_tx()];
        let tree = build_hash_tree(&txs, &create_tx());

        assert_eq!(tree.len(), 4);
        assert_eq!(tree[0].len(), 4);
        assert_eq!(tree[1].len(), 2);
        assert_eq!(tree[2].len(), 2); // + 1 for coinbase
        assert_eq!(tree[3].len(), 1); // metaroot
    }
}
