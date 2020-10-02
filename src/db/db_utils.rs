use std::mem;
use rocksdb::DB;
use rayon::prelude::*;
use bincode::deserialize;
use std::sync::{Arc, Mutex};
use crate::constants::{DB_PATH, DB_PATH_TEST};
use crate::primitives::block::Block;
use crate::primitives::transaction::Transaction;

/// Finds all matching transactions for a given DRUID
/// 
/// ### Arguments
/// 
/// * `druid`   - DRUID to find transaction for
/// * `block`   - Block hash containing DRUID
pub fn find_all_matching_druids(druid: String, block: String) -> Vec<Transaction> {
    // TODO: Allow for network type change
    let open_path = format!("{}/{}", DB_PATH, DB_PATH_TEST);
    let final_txs = Arc::new(Mutex::new(Vec::new()));
    let db = DB::open_default(open_path.clone()).unwrap();
    let block = match db.get(block) {
        Ok(Some(value)) => deserialize::<Block>(&value).unwrap(),
        Ok(None) => panic!("Block not found in blockchain"),
        Err(e) => panic!("Error retrieving block: {:?}", e),
    };

    block.transactions.par_iter().for_each(|x| {
        let tx = match db.get(x) {
            Ok(Some(value)) => deserialize::<Transaction>(&value).unwrap(),
            Ok(None) => panic!("Transaction not found in blockchain"),
            Err(e) => panic!("Error retrieving transaction: {:?}", e),
        };

        if let Some(d) = &tx.druid {
            if d == &druid {
                final_txs.lock().unwrap().push(tx);
            }
        }
    });

    let guard = Arc::try_unwrap(final_txs).expect("Lock still has multiple owners");
    guard.into_inner().expect("Mutex cannot be locked")
}