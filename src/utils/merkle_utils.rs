use crate::crypto::sha3_256;
use crate::primitives::transaction::Transaction;
use crate::utils::transaction_utils::construct_tx_hash;
use bincode::serialize;
use bytes::Bytes;
use std::cmp::min;
use std::vec::Vec;

pub fn build_hash_tree(transactions: Vec<Transaction>, coinbase: Transaction) -> Vec<Vec<String>> {
    // Instantiate empty list for leaf nodes.
    // Note: In the Rust implementation, the size of the array will be determined from the fixed block size.
    let mut tree: Vec<Vec<String>> = vec![Vec::new()];

    // Hash transactions to create leaf nodes.
    for tx in &transactions {
        tree[0].push(construct_tx_hash(tx));
    }

    // If number of transactions is odd, then duplicate last transaction hash.
    if tree[0].len() % 2 == 1 {
        let dup = tree[0].last().unwrap().clone();
        tree[0].push(dup);
    }

    // Calculate Merkle tree depth (root level = 0)
    let d = ((tree[0].len() as f64).log2().ceil()) as usize;

    // Build hash tree up to root
    for i in 1..d {
        // Append new row to tree
        tree.push(Vec::new());

        // Determine size of layer directly below current layer and ensure that
        // the size of the current layer is an even number.
        let cur_layer = tree[i - 1].len() + tree[i - 1].len() % 2;

        for j in 0..cur_layer {
            if j % 2 == 1 {
                let left_child = tree[i - 1][j - 1].clone();
                let right_child = tree[i - 1][min(j + 1, cur_layer - 1)].clone();
                tree[i].push(hash_node(&left_child, &right_child));
            }
        }

        // If number of transactions is odd, duplicate last transaction hash
        if tree[i].len() % 2 == 1 {
            let dup = tree[i].last().unwrap().clone();
            tree[i].push(dup);
        }
    }

    // Compute Merkle tree root
    let left_child = tree[d - 1][0].clone();
    let right_child = tree[d - 1][1].clone();
    let merkle_root_hash = hash_node(&left_child, &right_child);

    // Hash coinbase transaction
    let coinbase_hash = construct_tx_hash(&coinbase);

    // Calculate the "meta root" hash
    let meta_root_hash = hash_node(&merkle_root_hash, &coinbase_hash);

    // Insert coinbase hash at same level as the transaction tree root hash
    tree[d].push(coinbase_hash.clone());

    // Add an additional level to the tree which includes only the meta root hash
    tree.push(vec![meta_root_hash]);

    tree.reverse();
    tree
}

fn hash_node(left: &str, right: &str) -> String {
    let concat = Bytes::from(serialize(&vec![left, right]).unwrap());
    hex::encode(sha3_256::digest(&concat))
}
