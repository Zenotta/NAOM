#![allow(unused)]
use crate::constants::{MAX_BLOCK_SIZE, NETWORK_VERSION};
use crate::crypto::sha3_256::{self, Sha3_256};
use crate::crypto::sign_ed25519::PublicKey;
use crate::primitives::asset::Asset;
use crate::primitives::transaction::{Transaction, TxIn, TxOut};
use crate::utils::merkle_utils::MerkleTree;
use bincode::{deserialize, serialize};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

/// Block header, which contains a smaller footprint view of the block.
/// Hash records are assumed to be 256 bit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub bits: usize,
    pub nonce_and_mining_tx_hash: (Vec<u8>, String),
    pub b_num: u64,
    pub seed_value: Vec<u8>, // for commercial
    pub previous_hash: Option<String>,
    pub txs_merkle_root_and_hash: (String, String),
}

impl Default for BlockHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockHeader {
    /// Creates a new BlockHeader
    pub fn new() -> BlockHeader {
        BlockHeader {
            version: NETWORK_VERSION,
            bits: 0,
            nonce_and_mining_tx_hash: Default::default(),
            b_num: 0,
            seed_value: Vec::new(),
            previous_hash: None,
            txs_merkle_root_and_hash: Default::default(),
        }
    }

    /// Checks whether a BlockHeader is empty
    pub fn is_null(&self) -> bool {
        self.bits == 0
    }
}

/// A block, a collection of transactions for processing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<String>,
}

impl Default for Block {
    fn default() -> Self {
        Self::new()
    }
}

impl Block {
    /// Creates a new instance of a block
    pub fn new() -> Block {
        Block {
            header: BlockHeader::new(),
            transactions: Vec::new(),
        }
    }

    /// Sets the internal number of bits based on length
    pub fn set_bits(&mut self) {
        let bytes = Bytes::from(serialize(&self).unwrap());
        self.header.bits = bytes.len();
    }

    /// Checks whether a block has hit its maximum size
    pub fn is_full(&self) -> bool {
        let bytes = Bytes::from(serialize(&self).unwrap());
        bytes.len() >= MAX_BLOCK_SIZE
    }

    /// Get the merkle root for the current set of transactions
    pub async fn set_txs_merkle_root_and_hash(&mut self) {
        let merkle_tree = MerkleTree::new(&self.transactions);
        let txs_hash = build_hex_txs_hash(&self.transactions);

        self.header.txs_merkle_root_and_hash = (merkle_tree.root, txs_hash);
    }
}

/*---- FUNCTIONS ----*/

/// Converts a dynamic array into a static 32 bit
///
/// ### Arguments
///
/// * `bytes`   - Bytes to cast
pub fn from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

/// Generates a random transaction hash for testing
pub fn gen_random_hash() -> String {
    let rand_2: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    hex::encode(sha3_256::digest(rand_2.as_bytes()))
}

/// Builds hex encoded sha3 hash of the passed transactions
///
/// ### Arguments
///
/// * `transactions`    - Transactions to construct a merkle tree for
pub fn build_hex_txs_hash(transactions: &[String]) -> String {
    let txs = serialize(transactions).unwrap();
    hex::encode(sha3_256::digest(&txs))
}
