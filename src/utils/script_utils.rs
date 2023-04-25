#![allow(unused)]
use crate::constants::*;
use crate::crypto::sha3_256;
use crate::crypto::sign_ed25519::{
    self as sign, PublicKey, Signature, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN,
};
use crate::primitives::asset::{Asset, AssetValues, ReceiptAsset, TokenAmount};
use crate::primitives::druid::DruidExpectation;
use crate::primitives::transaction::*;
use crate::script::interface_ops::*;
use crate::script::lang::{ConditionStack, Script, Stack};
use crate::script::{OpCodes, StackEntry};
use crate::utils::error_utils::*;
use crate::utils::transaction_utils::{
    construct_address, construct_tx_in_signable_asset_hash, construct_tx_in_signable_hash,
};
use bincode::serialize;
use bytes::Bytes;
use hex::encode;
use std::collections::{BTreeMap, BTreeSet};
use std::thread::current;
use tracing::{debug, error, info, trace};

use super::transaction_utils::construct_p2sh_address;

/// Verifies that all incoming transactions are allowed to be spent. Returns false if a single
/// transaction doesn't verify
///
/// TODO: Currently assumes p2pkh and p2sh, abstract to all tx types
///
/// ### Arguments
///
/// * `tx`  - Transaction to verify
pub fn tx_is_valid<'a>(
    tx: &Transaction,
    is_in_utxo: impl Fn(&OutPoint) -> Option<&'a TxOut> + 'a,
) -> bool {
    let mut tx_ins_spent: AssetValues = Default::default();
    // TODO: Add support for `Data` asset variant
    // `Receipt` assets MUST have an a DRS value associated with them when they are getting on-spent
    if tx.outputs.iter().any(|out| {
        (out.value.is_receipt()
            && (out.value.get_drs_tx_hash().is_none() || out.value.get_metadata().is_some()))
    }) {
        error!("ON-SPENDING NEEDS EMPTY METADATA AND NON-EMPTY DRS SPECIFICATION");
        return false;
    }

    for tx_in in &tx.inputs {
        // Ensure the transaction is in the `UTXO` set
        let tx_out_point = tx_in.previous_out.as_ref().unwrap().clone();

        let tx_out = if let Some(tx_out) = is_in_utxo(&tx_out_point) {
            tx_out
        } else {
            error!("UTXO DOESN'T CONTAIN THIS TX");
            return false;
        };

        // At this point `TxIn` will be valid
        let tx_out_pk = tx_out.script_public_key.as_ref();
        let tx_out_hash = construct_tx_in_signable_hash(&tx_out_point);

        if let Some(pk) = tx_out_pk {
            // Check will need to include other signature types here
            if !tx_has_valid_p2pkh_sig(&tx_in.script_signature, &tx_out_hash, pk)
                && !tx_has_valid_p2sh_script(&tx_in.script_signature, pk)
            {
                return false;
            }
        } else {
            return false;
        }

        let asset = tx_out.value.clone().with_fixed_hash(&tx_out_point);
        tx_ins_spent.update_add(&asset);
    }

    tx_outs_are_valid(&tx.outputs, tx_ins_spent)
}

/// Verifies that the outgoing `TxOut`s are valid. Returns false if a single
/// transaction doesn't verify.
///
/// TODO: Abstract to data assets
///
/// ### Arguments
///
/// * `tx_outs` - `TxOut`s to verify
/// * `tx_ins_spent` - Total amount spendable from `TxIn`s
pub fn tx_outs_are_valid(tx_outs: &[TxOut], tx_ins_spent: AssetValues) -> bool {
    let mut tx_outs_spent: AssetValues = Default::default();

    for tx_out in tx_outs {
        // Addresses must have valid length
        if let Some(addr) = &tx_out.script_public_key {
            if !address_has_valid_length(addr) {
                trace!("Address has invalid length");
                return false;
            }
        }

        tx_outs_spent.update_add(&tx_out.value);
    }

    // Ensure that the `TxIn`s correlate with the `TxOut`s
    tx_outs_spent.is_equal(&tx_ins_spent)
}

/// Checks whether a create transaction has a valid input script
///
/// ### Arguments
///
/// * `script`      - Script to validate
/// * `asset`       - Asset to be created
pub fn tx_has_valid_create_script(script: &Script, asset: &Asset) -> bool {
    let mut it = script.stack.iter();
    let asset_hash = construct_tx_in_signable_asset_hash(asset);

    if let Asset::Receipt(r) = asset {
        if !receipt_has_valid_size(r) {
            trace!("Receipt metadata is too large");
            return false;
        }
    }

    if let (
        Some(StackEntry::Op(OpCodes::OP_CREATE)),
        Some(StackEntry::Num(_)),
        Some(StackEntry::Op(OpCodes::OP_DROP)),
        Some(StackEntry::Bytes(b)),
        Some(StackEntry::Signature(_)),
        Some(StackEntry::PubKey(_)),
        Some(StackEntry::Op(OpCodes::OP_CHECKSIG)),
        None,
    ) = (
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
    ) {
        if b == &asset_hash && script.interpret() {
            return true;
        }
    }

    trace!("Invalid script for create: {:?}", script.stack,);
    false
}

/// Checks whether a transaction to spend tokens in P2PKH has a valid signature
///
/// ### Arguments
///
/// * `script`          - Script to validate
/// * `outpoint_hash`   - Hash of the corresponding outpoint
/// * `tx_out_pub_key`  - Public key of the previous tx_out
fn tx_has_valid_p2pkh_sig(script: &Script, outpoint_hash: &str, tx_out_pub_key: &str) -> bool {
    let mut it = script.stack.iter();

    if let (
        Some(StackEntry::Bytes(b)),
        Some(StackEntry::Signature(_)),
        Some(StackEntry::PubKey(_)),
        Some(StackEntry::Op(OpCodes::OP_DUP)),
        Some(StackEntry::Op(
            OpCodes::OP_HASH256 | OpCodes::OP_HASH256_V0 | OpCodes::OP_HASH256_TEMP,
        )),
        Some(StackEntry::PubKeyHash(h)),
        Some(StackEntry::Op(OpCodes::OP_EQUALVERIFY)),
        Some(StackEntry::Op(OpCodes::OP_CHECKSIG)),
        None,
    ) = (
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
    ) {
        if h == tx_out_pub_key && b == outpoint_hash && script.interpret() {
            return true;
        }
    }

    trace!(
        "Invalid P2PKH script: {:?} tx_out_pub_key: {}",
        script.stack,
        tx_out_pub_key
    );

    false
}

/// Checks whether a transaction to spend tokens in P2SH has a valid hash and executing script
///
/// ### Arguments
///
/// * `script`          - Script to validate
/// * `address`         - Address of the P2SH transaction
pub fn tx_has_valid_p2sh_script(script: &Script, address: &str) -> bool {
    let p2sh_address = construct_p2sh_address(script);

    if p2sh_address == address {
        return script.interpret();
    }

    trace!(
        "Invalid P2SH script: {:?}, address: {}",
        script.stack,
        address
    );

    false
}

/// Checks that a receipt's metadata conforms to the network size constraint
///
/// ### Arguments
///
/// * `receipt` - Receipt to check
fn receipt_has_valid_size(receipt: &ReceiptAsset) -> bool {
    if let Some(metadata) = &receipt.metadata {
        return metadata.len() <= MAX_METADATA_BYTES;
    }
    true
}

/// Checks that an address has a valid length
///
/// ### Arguments
///
/// * `address` - Address to check
fn address_has_valid_length(address: &str) -> bool {
    address.len() == 32 || address.len() == 64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::RECEIPT_ACCEPT_VAL;
    use crate::primitives::asset::{Asset, DataAsset};
    use crate::primitives::druid::DdeValues;
    use crate::primitives::transaction::OutPoint;
    use crate::utils::test_utils::generate_tx_with_ins_and_outs_assets;
    use crate::utils::transaction_utils::*;

    /*---- CONSTANTS OPS ----*/

    #[test]
    /// Test OP_0
    fn test_0() {
        /// op_0([]) -> [0]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_0(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_1
    fn test_1() {
        /// op_1([]) -> [1]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_1(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_2
    fn test_2() {
        /// op_2([]) -> [2]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_2(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_3
    fn test_3() {
        /// op_3([]) -> [3]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(3)];
        op_3(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_4
    fn test_4() {
        /// op_4([]) -> [4]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(4)];
        op_4(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_5
    fn test_5() {
        /// op_5([]) -> [5]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(5)];
        op_5(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_6
    fn test_6() {
        /// op_6([]) -> [6]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(6)];
        op_6(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_7
    fn test_7() {
        /// op_7([]) -> [7]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(7)];
        op_7(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_8
    fn test_8() {
        /// op_8([]) -> [8]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(8)];
        op_8(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_9
    fn test_9() {
        /// op_9([]) -> [9]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(9)];
        op_9(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_10
    fn test_10() {
        /// op_10([]) -> [10]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(10)];
        op_10(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_11
    fn test_11() {
        /// op_11([]) -> [11]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(11)];
        op_11(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_12
    fn test_12() {
        /// op_12([]) -> [12]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(12)];
        op_12(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_13
    fn test_13() {
        /// op_13([]) -> [13]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(13)];
        op_13(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_14
    fn test_14() {
        /// op_14([]) -> [14]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(14)];
        op_14(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_15
    fn test_15() {
        /// op_15([]) -> [15]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(15)];
        op_15(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_16
    fn test_16() {
        /// op_16([]) -> [16]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(16)];
        op_16(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    /*---- FLOW CONTROL OPS ----*/

    #[test]
    /// Test OP_NOP
    fn test_nop() {
        /// op_nop([1]) -> [1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_nop(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_IF
    fn test_if() {
        /// op_if([1], {0,None}) -> [], {1,None}
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut cond_stack = ConditionStack::new();
        let mut v: Vec<StackEntry> = vec![];
        op_if(&mut stack, &mut cond_stack);
        assert_eq!(stack.main_stack, v);
        assert_eq!(cond_stack.size, 1);
        assert_eq!(cond_stack.first_false_pos, None);
        /// op_if([0], {0,None}) -> [], {1,0}
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        let mut cond_stack = ConditionStack::new();
        let mut v: Vec<StackEntry> = vec![];
        op_if(&mut stack, &mut cond_stack);
        assert_eq!(stack.main_stack, v);
        assert_eq!(cond_stack.size, 1);
        assert_eq!(cond_stack.first_false_pos, Some(0));
        /// op_if([1], {1,0}) -> [1], {2,0}
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut cond_stack = ConditionStack::new();
        cond_stack.size = 1;
        cond_stack.first_false_pos = Some(0);
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_if(&mut stack, &mut cond_stack);
        assert_eq!(stack.main_stack, v);
        assert_eq!(cond_stack.size, 2);
        assert_eq!(cond_stack.first_false_pos, Some(0));
        /// error item type
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(String::new()));
        let mut cond_stack = ConditionStack::new();
        let b = op_if(&mut stack, &mut cond_stack);
        assert!(!b);
        /// error num items
        let mut stack = Stack::new();
        let mut cond_stack = ConditionStack::new();
        let b = op_if(&mut stack, &mut cond_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_NOTIF
    fn test_notif() {
        /// op_notif([0], {0,None}) -> [], {1,None}
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        let mut cond_stack = ConditionStack::new();
        let mut v: Vec<StackEntry> = vec![];
        op_notif(&mut stack, &mut cond_stack);
        assert_eq!(stack.main_stack, v);
        assert_eq!(cond_stack.size, 1);
        assert_eq!(cond_stack.first_false_pos, None);
        /// op_notif([1], {0,None}) -> [], {1,0}
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut cond_stack = ConditionStack::new();
        let mut v: Vec<StackEntry> = vec![];
        op_notif(&mut stack, &mut cond_stack);
        assert_eq!(stack.main_stack, v);
        assert_eq!(cond_stack.size, 1);
        assert_eq!(cond_stack.first_false_pos, Some(0));
        /// op_notif([0], {1,0}) -> [0], {2,0}
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        let mut cond_stack = ConditionStack::new();
        cond_stack.size = 1;
        cond_stack.first_false_pos = Some(0);
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_notif(&mut stack, &mut cond_stack);
        assert_eq!(stack.main_stack, v);
        assert_eq!(cond_stack.size, 2);
        assert_eq!(cond_stack.first_false_pos, Some(0));
        /// error item type
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(String::new()));
        let mut cond_stack = ConditionStack::new();
        let b = op_notif(&mut stack, &mut cond_stack);
        assert!(!b);
        /// error num items
        let mut stack = Stack::new();
        let mut cond_stack = ConditionStack::new();
        let b = op_notif(&mut stack, &mut cond_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_ELSE
    fn test_else() {
        /// op_else({1,None}) -> {1,0}
        let mut cond_stack = ConditionStack::new();
        cond_stack.size = 1;
        cond_stack.first_false_pos = None;
        op_else(&mut cond_stack);
        assert_eq!(cond_stack.size, 1);
        assert_eq!(cond_stack.first_false_pos, Some(0));
        /// op_else({1,0}) -> {1,None}
        let mut cond_stack = ConditionStack::new();
        cond_stack.size = 1;
        cond_stack.first_false_pos = Some(0);
        op_else(&mut cond_stack);
        assert_eq!(cond_stack.size, 1);
        assert_eq!(cond_stack.first_false_pos, None);
        /// op_else({2,0}) -> {2,0}
        let mut cond_stack = ConditionStack::new();
        cond_stack.size = 2;
        cond_stack.first_false_pos = Some(0);
        op_else(&mut cond_stack);
        assert_eq!(cond_stack.size, 2);
        assert_eq!(cond_stack.first_false_pos, Some(0));
        /// empty condition stack
        let mut cond_stack = ConditionStack::new();
        let b = op_else(&mut cond_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_ENDIF
    fn test_endif() {
        /// op_endif({1,None}) -> {0,None}
        let mut cond_stack = ConditionStack::new();
        cond_stack.size = 1;
        cond_stack.first_false_pos = None;
        op_endif(&mut cond_stack);
        assert_eq!(cond_stack.size, 0);
        assert_eq!(cond_stack.first_false_pos, None);
        /// op_endif({1,0}) -> {0,None}
        let mut cond_stack = ConditionStack::new();
        cond_stack.size = 1;
        cond_stack.first_false_pos = Some(0);
        op_endif(&mut cond_stack);
        assert_eq!(cond_stack.size, 0);
        assert_eq!(cond_stack.first_false_pos, None);
        /// op_endif({2,0}) -> {1,0}
        let mut cond_stack = ConditionStack::new();
        cond_stack.size = 2;
        cond_stack.first_false_pos = Some(0);
        op_endif(&mut cond_stack);
        assert_eq!(cond_stack.size, 1);
        assert_eq!(cond_stack.first_false_pos, Some(0));
        /// empty condition stack
        let mut cond_stack = ConditionStack::new();
        let b = op_endif(&mut cond_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_VERIFY
    fn test_verify() {
        /// op_verify([1]) -> []
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![];
        op_verify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_verify([0]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        let b = op_verify(&mut stack);
        assert!(!b);
        /// op_verify([]) -> fail
        let mut stack = Stack::new();
        let b = op_verify(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_RETURN
    fn test_return() {
        /// op_return([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_return(&mut stack);
        assert!(!b);
        /// op_return([]) -> fail
        let mut stack = Stack::new();
        let b = op_return(&mut stack);
        assert!(!b)
    }

    /*---- STACK OPS ----*/

    #[test]
    /// Test OP_TOALTSTACK
    fn test_toaltstack() {
        /// op_toaltstack([1], []) -> [], [1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v1: Vec<StackEntry> = vec![];
        let mut v2: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_toaltstack(&mut stack);
        assert_eq!(stack.main_stack, v1);
        assert_eq!(stack.alt_stack, v2);
        /// op_toaltstack([], []) -> fail
        let mut stack = Stack::new();
        let b = op_toaltstack(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_FROMALTSTACK
    fn test_fromaltstack() {
        /// op_fromaltstack([], [1]) -> [1], []
        let mut stack = Stack::new();
        stack.alt_stack.push(StackEntry::Num(1));
        let mut v1: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let mut v2: Vec<StackEntry> = vec![];
        op_fromaltstack(&mut stack);
        assert_eq!(stack.main_stack, v1);
        assert_eq!(stack.alt_stack, v2);
        /// op_fromaltstack([], []) -> fail
        let mut stack = Stack::new();
        let b = op_fromaltstack(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_2DROP
    fn test_2drop() {
        /// op_2drop([1,2]) -> []
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        op_2drop(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_2drop([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_2drop(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_2DUP
    fn test_2dup() {
        /// op_2dup([1,2]) -> [1,2,1,2]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        op_2dup(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_2dup([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_2dup(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_3DUP
    fn test_3dup() {
        /// op_3dup([1,2,3]) -> [1,2,3,1,2,3]
        let mut stack = Stack::new();
        for i in 1..=3 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=3 {
            v.push(StackEntry::Num(i));
        }
        for i in 1..=3 {
            v.push(StackEntry::Num(i));
        }
        op_3dup(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_3dup([1,2]) -> fail
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_3dup(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_2OVER
    fn test_2over() {
        /// op_2over([1,2,3,4]) -> [1,2,3,4,1,2]
        let mut stack = Stack::new();
        for i in 1..=4 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        op_2over(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_2over([1,2,3]) -> fail
        let mut stack = Stack::new();
        for i in 1..=3 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_2over(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_2ROT
    fn test_2rot() {
        /// op_2rot([1,2,3,4,5,6]) -> [3,4,5,6,1,2]
        let mut stack = Stack::new();
        for i in 1..=6 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 3..=6 {
            v.push(StackEntry::Num(i));
        }
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        op_2rot(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_2rot([1,2,3,4,5]) -> fail
        let mut stack = Stack::new();
        for i in 1..=5 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_2rot(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_2SWAP
    fn test_2swap() {
        /// op_2swap([1,2,3,4]) -> [3,4,1,2]
        let mut stack = Stack::new();
        for i in 1..=4 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 3..=4 {
            v.push(StackEntry::Num(i));
        }
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        op_2swap(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_2swap([1,2,3]) -> fail
        let mut stack = Stack::new();
        for i in 1..=3 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_2swap(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_IFDUP
    fn test_ifdup() {
        /// op_ifdup([1]) -> [1,1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            v.push(StackEntry::Num(1));
        }
        op_ifdup(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_ifdup([0]) -> [0]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_ifdup(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_ifdup([]) -> fail
        let mut stack = Stack::new();
        let b = op_ifdup(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_DEPTH
    fn test_depth() {
        /// op_depth([1,1,1,1]) -> [1,1,1,1,4]
        let mut stack = Stack::new();
        for i in 1..=4 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            v.push(StackEntry::Num(1));
        }
        v.push(StackEntry::Num(4));
        op_depth(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_depth([]) -> [0]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_depth(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_DROP
    fn test_drop() {
        /// op_drop([1]) -> []
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let mut v: Vec<StackEntry> = vec![];
        op_drop(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_drop([]) -> fail
        let mut stack = Stack::new();
        let b = op_drop(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_DUP
    fn test_dup() {
        /// op_dup([1]) -> [1,1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            v.push(StackEntry::Num(1));
        }
        op_dup(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_dup([]) -> fail
        let mut stack = Stack::new();
        let b = op_dup(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_NIP
    fn test_nip() {
        /// op_nip([1,2]) -> [2]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_nip(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_nip([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_nip(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_OVER
    fn test_over() {
        /// op_over([1,2]) -> [1,2,1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_over(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_over([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_over(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_PICK
    fn test_pick() {
        /// op_pick([1,2,3,4,3]) -> [1,2,3,4,1]
        let mut stack = Stack::new();
        for i in 1..=4 {
            stack.push(StackEntry::Num(i));
        }
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_pick(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_pick([1,2,3,4,0]) -> [1,2,3,4,4]
        let mut stack = Stack::new();
        for i in 1..=4 {
            stack.push(StackEntry::Num(i));
        }
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(4));
        op_pick(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_pick([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_pick(&mut stack);
        assert!(!b);
        /// op_pick([1,"hello"]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Bytes("hello".to_string()));
        let b = op_pick(&mut stack);
        assert!(!b);
        /// op_pick([1,1]) -> fail
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_pick(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_ROLL
    fn test_roll() {
        /// op_roll([1,2,3,4,3]) -> [2,3,4,1]
        let mut stack = Stack::new();
        for i in 1..=4 {
            stack.push(StackEntry::Num(i));
        }
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![];
        for i in 2..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_roll(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_roll([1,2,3,4,0]) -> [1,2,3,4]
        let mut stack = Stack::new();
        for i in 1..=4 {
            stack.push(StackEntry::Num(i));
        }
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        op_roll(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_roll([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_roll(&mut stack);
        assert!(!b);
        /// op_roll([1,"hello"]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Bytes("hello".to_string()));
        let b = op_roll(&mut stack);
        assert!(!b);
        /// op_roll([1,1]) -> fail
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_roll(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_ROT
    fn test_rot() {
        /// op_rot([1,2,3]) -> [2,3,1]
        let mut stack = Stack::new();
        for i in 1..=3 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 2..=3 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_rot(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_rot([1,2]) -> fail
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_rot(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_SWAP
    fn test_swap() {
        /// op_swap([1,2]) -> [2,1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2), StackEntry::Num(1)];
        op_swap(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_swap([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_swap(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_TUCK
    fn test_tuck() {
        /// op_tuck([1,2]) -> [2,1,2]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        op_tuck(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_tuck([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_tuck(&mut stack);
        assert!(!b)
    }

    /*---- SPLICE OPS ----*/

    #[test]
    /// Test OP_CAT
    fn test_cat() {
        /// op_cat(["hello","world"]) -> ["helloworld"]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Bytes("world".to_string()));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("helloworld".to_string())];
        op_cat(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_cat(["hello",""]) -> ["hello"]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Bytes("".to_string()));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        op_cat(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_cat(["a","a"*MAX_SCRIPT_ITEM_SIZE]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("a".to_string()));
        let mut s = String::new();
        for i in 1..=MAX_SCRIPT_ITEM_SIZE {
            s.push('a');
        }
        stack.push(StackEntry::Bytes(s.to_string()));
        let b = op_cat(&mut stack);
        assert!(!b);
        /// op_cat(["hello"]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        let b = op_cat(&mut stack);
        assert!(!b);
        /// op_cat(["hello", 1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Num(1));
        let b = op_cat(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_SUBSTR
    fn test_substr() {
        /// op_substr(["hello",1,2]) -> ["el"]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("el".to_string())];
        op_substr(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_substr(["hello",0,0]) -> [""]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        for i in 1..=2 {
            stack.push(StackEntry::Num(0));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("".to_string())];
        op_substr(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_substr(["hello",0,5]) -> ["hello"]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Num(0));
        stack.push(StackEntry::Num(5));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        op_substr(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_substr(["hello",5,0]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Num(5));
        stack.push(StackEntry::Num(0));
        let b = op_substr(&mut stack);
        assert!(!b);
        /// op_substr(["hello",1,5]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(5));
        let b = op_substr(&mut stack);
        assert!(!b);
        /// op_substr(["hello",1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Num(1));
        let b = op_substr(&mut stack);
        assert!(!b);
        /// op_substr(["hello",1,usize::MAX]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(usize::MAX));
        let b = op_substr(&mut stack);
        assert!(!b);
        /// op_substr(["hello",1,""]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Bytes("".to_string()));
        let b = op_substr(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_LEFT
    fn test_left() {
        /// op_left(["hello",2]) -> ["he"]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Num(2));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("he".to_string())];
        op_left(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_left(["hello",0]) -> [""]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("".to_string())];
        op_left(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_left(["hello",5]) -> ["hello"]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Num(5));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        op_left(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_left(["hello",""]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Bytes("".to_string()));
        let b = op_left(&mut stack);
        assert!(!b);
        /// op_left(["hello"]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        let b = op_left(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_RIGHT
    fn test_right() {
        /// op_right(["hello",0]) -> ["hello"]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        op_right(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_right(["hello",2]) -> ["llo"]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Num(2));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("llo".to_string())];
        op_right(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_right(["hello",5]) -> [""]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Num(5));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("".to_string())];
        op_right(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_right(["hello",""]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        stack.push(StackEntry::Bytes("".to_string()));
        let b = op_right(&mut stack);
        assert!(!b);
        /// op_right(["hello"]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        let b = op_right(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_SIZE
    fn test_size() {
        /// op_size(["hello"]) -> ["hello",5]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".to_string()));
        let mut v: Vec<StackEntry> =
            vec![StackEntry::Bytes("hello".to_string()), StackEntry::Num(5)];
        op_size(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_size([""]) -> ["",0]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("".to_string()));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("".to_string()), StackEntry::Num(0)];
        op_size(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_size([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_size(&mut stack);
        assert!(!b);
        /// op_size([]) -> fail
        let mut stack = Stack::new();
        let b = op_size(&mut stack);
        assert!(!b)
    }

    /*---- BITWISE LOGIC OPS ----*/

    #[test]
    /// Test OP_INVERT
    fn test_invert() {
        /// op_invert([0]) -> [usize::MAX]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(usize::MAX)];
        op_invert(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_invert([]) -> fail
        let mut stack = Stack::new();
        let b = op_invert(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_AND
    fn test_and() {
        /// op_and([1,2]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_and(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_and([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_and(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_OR
    fn test_or() {
        /// op_or([1,2]) -> [3]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(3)];
        op_or(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_or([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_or(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_XOR
    fn test_xor() {
        /// op_xor([1,2]) -> [3]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(3)];
        op_xor(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_xor([1,1]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_xor(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_xor([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_xor(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_EQUAL
    fn test_equal() {
        /// op_equal(["hello","hello"]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Bytes("hello".to_string()));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_equal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_equal([1,2]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_equal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_equal([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_equal(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_EQUALVERIFY
    fn test_equalverify() {
        /// op_equalverify(["hello","hello"]) -> []
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Bytes("hello".to_string()));
        }
        let mut v: Vec<StackEntry> = vec![];
        op_equalverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_equalverify([1,2]) -> fail
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_equalverify(&mut stack);
        assert!(!b);
        /// op_equalverify([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_equalverify(&mut stack);
        assert!(!b)
    }

    /*---- ARITHMETIC OPS ----*/

    #[test]
    /// Test OP_1ADD
    fn test_1add() {
        /// op_1add([1]) -> [2]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_1add(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_1add([usize::MAX]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(usize::MAX));
        let b = op_1add(&mut stack);
        assert!(!b);
        /// op_1add([]) -> fail
        let mut stack = Stack::new();
        let b = op_1add(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_1SUB
    fn test_1sub() {
        /// op_1sub([1]) -> [0]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_1sub(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_1sub([0]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        let b = op_1sub(&mut stack);
        assert!(!b);
        /// op_1sub([]) -> fail
        let mut stack = Stack::new();
        let b = op_1sub(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_2MUL
    fn test_2mul() {
        /// op_2mul([1]) -> [2]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_2mul(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_2mul([usize::MAX]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(usize::MAX));
        let b = op_2mul(&mut stack);
        assert!(!b);
        /// op_2mul([]) -> fail
        let mut stack = Stack::new();
        let b = op_2mul(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_2DIV
    fn test_2div() {
        /// op_2div([1]) -> [0]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_2div(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_2div([]) -> fail
        let mut stack = Stack::new();
        let b = op_2div(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_NOT
    fn test_not() {
        /// op_not([0]) -> [1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_not(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_not([1]) -> [0]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_not(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_not([]) -> fail
        let mut stack = Stack::new();
        let b = op_not(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_0NOTEQUAL
    fn test_0notequal() {
        /// op_0notequal([1]) -> [1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_0notequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_0notequal([0]) -> [0]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_0notequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_0notequal([]) -> fail
        let mut stack = Stack::new();
        let b = op_0notequal(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_ADD
    fn test_add() {
        /// op_add([1,2]) -> [3]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(3)];
        op_add(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_add([1,usize::MAX]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(usize::MAX));
        let b = op_add(&mut stack);
        assert!(!b);
        /// op_add([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_add(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_SUB
    fn test_sub() {
        /// op_sub([1,0]) -> [1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_sub(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_sub([0,1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        stack.push(StackEntry::Num(1));
        let b = op_sub(&mut stack);
        assert!(!b);
        /// op_sub([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_sub(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_MUL
    fn test_mul() {
        /// op_mul([1,2]) -> [2]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_mul(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_mul([2,usize::MAX]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::Num(usize::MAX));
        let b = op_mul(&mut stack);
        assert!(!b);
        /// op_mul([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_mul(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_DIV
    fn test_div() {
        /// op_div([1,2]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_div(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_div([1,0]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(0));
        let b = op_div(&mut stack);
        assert!(!b);
        /// op_div([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_div(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_MOD
    fn test_mod() {
        /// op_mod([1,2]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_mod(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_mod([1,0]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(0));
        let b = op_mod(&mut stack);
        assert!(!b);
        /// op_mod([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_mod(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_LSHIFT
    fn test_lshift() {
        /// op_lshift([1,2]) -> [4]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(4)];
        op_lshift(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_lshift([1,64]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(64));
        let b = op_lshift(&mut stack);
        assert!(!b);
        /// op_lshift([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_lshift(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_RSHIFT
    fn test_rshift() {
        /// op_rshift([1,2]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_rshift(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_rshift([1,64]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(64));
        let b = op_rshift(&mut stack);
        assert!(!b);
        /// op_rshift([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_rshift(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_BOOLAND
    fn test_booland() {
        /// op_booland([1,2]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_booland(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_booland([0,1]) -> [0]
        let mut stack = Stack::new();
        for i in 0..=1 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_booland(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_booland([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_booland(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_BOOLOR
    fn test_boolor() {
        /// op_boolor([0,1]) -> [1]
        let mut stack = Stack::new();
        for i in 0..=1 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_boolor(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_boolor([0,0]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(0));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_boolor(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_boolor([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_boolor(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_NUMEQUAL
    fn test_numequal() {
        /// op_numequal([1,1]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_numequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_numequal([1,2]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_numequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_numequal([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_numequal(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_NUMEQUALVERIFY
    fn test_numequalverify() {
        /// op_numequalverify([1,1]) -> []
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![];
        op_numequalverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_numequalverify([1,2]) -> fail
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_numequalverify(&mut stack);
        assert!(!b);
        /// op_numequalverify([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_numequalverify(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_NUMNOTEQUAL
    fn test_numnotequal() {
        /// op_numnotequal([1,2]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_numnotequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_numnotequal([1,1]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_numnotequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_numnotequal([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_numnotequal(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_LESSTHAN
    fn test_lessthan() {
        /// op_lessthan([1,2]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_lessthan(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_lessthan([1,1]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_lessthan(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_lessthan([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_lessthan(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_GREATERTHAN
    fn test_greaterthan() {
        /// op_greaterthan([2,1]) -> [1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_greaterthan(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_greaterthan([1,1]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_greaterthan(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_greaterthan([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_greaterthan(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_LESSTHANOREQUAL
    fn test_lessthanorequal() {
        /// test_lessthanorequal([1,1]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_lessthanorequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_lessthanorequal([2,1]) -> [0]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_lessthanorequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_lessthanorequal([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_lessthanorequal(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_GREATERTHANOREQUAL
    fn test_greaterthanorequal() {
        /// op_greaterthanorequal([1,1]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_greaterthanorequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_greaterthanorequal([1,2]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_greaterthanorequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_greaterthanorequal([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_greaterthanorequal(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_MIN
    fn test_min() {
        /// op_min([1,2]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_min(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_min([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_min(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_MAX
    fn test_max() {
        /// op_max([1,2]) -> [2]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_max(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_max([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_max(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_WITHIN
    fn test_within() {
        /// op_within([2,1,3]) -> [1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_within(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_within([1,2,3]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=3 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_within(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_within([1,2]) -> fail
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_within(&mut stack);
        assert!(!b)
    }

    /*---- CRYPTO OPS ----*/

    #[test]
    /// Test OP_SHA3
    fn test_sha3() {
        /// op_sha3([sig]) -> [sha3_256(sig)]
        let (pk, sk) = sign::gen_keypair();
        let msg = hex::encode(vec![0, 0, 0]);
        let sig = sign::sign_detached(msg.as_bytes(), &sk);
        let h = hex::encode(sha3_256::digest(sig.as_ref()));
        let mut stack = Stack::new();
        stack.push(StackEntry::Signature(sig));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes(h)];
        op_sha3(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_sha3([pk]) -> [sha3_256(pk)]
        let h = hex::encode(sha3_256::digest(pk.as_ref()));
        let mut stack = Stack::new();
        stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes(h)];
        op_sha3(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_sha3(["hello"]) -> [sha3_256("hello")]
        let s = "hello".to_string();
        let h = hex::encode(sha3_256::digest(s.as_bytes()));
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(s));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes(h)];
        op_sha3(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_sha3([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_sha3(&mut stack);
        assert!(!b);
        /// op_sha3([]) -> fail
        let mut stack = Stack::new();
        let b = op_sha3(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_HASH256
    fn test_hash256() {
        /// op_hash256([pk]) -> [addr]
        let (pk, sk) = sign::gen_keypair();
        let mut stack = Stack::new();
        stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![StackEntry::PubKeyHash(construct_address(&pk))];
        op_hash256(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_hash256([]) -> fail
        let mut stack = Stack::new();
        let b = op_hash256(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_HASH256_V0
    fn test_hash256_v0() {
        /// op_hash256_v0([pk]) -> [addr_v0]
        let (pk, sk) = sign::gen_keypair();
        let mut stack = Stack::new();
        stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![StackEntry::PubKeyHash(construct_address_v0(&pk))];
        op_hash256_v0(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_hash256([]) -> fail
        let mut stack = Stack::new();
        let b = op_hash256_v0(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_HASH256_TEMP
    fn test_hash256_temp() {
        /// op_hash256_temp([pk]) -> [addr_temp]
        let (pk, sk) = sign::gen_keypair();
        let mut stack = Stack::new();
        stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![StackEntry::PubKeyHash(construct_address_temp(&pk))];
        op_hash256_temp(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_hash256([]) -> fail
        let mut stack = Stack::new();
        let b = op_hash256_temp(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_CHECKSIG
    fn test_checksig() {
        /// op_checksig([msg,sig,pk]) -> [1]
        let (pk, sk) = sign::gen_keypair();
        let msg = hex::encode(vec![0, 0, 0]);
        let sig = sign::sign_detached(msg.as_bytes(), &sk);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Signature(sig));
        stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_checksig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// wrong message
        /// op_checksig([msg',sig,pk]) -> [0]
        let msg = hex::encode(vec![0, 0, 1]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Signature(sig));
        stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_checksig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// wrong public key
        /// op_checksig([msg,sig,pk']) -> [0]
        let (pk, sk) = sign::gen_keypair();
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Signature(sig));
        stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_checksig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// no message
        /// op_checksig([sig,pk]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Signature(sig));
        stack.push(StackEntry::PubKey(pk));
        let b = op_checksig(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_CHECKSIGVERIFY
    fn test_checksigverify() {
        /// op_checksigverify([msg,sig,pk]) -> []
        let (pk, sk) = sign::gen_keypair();
        let msg = hex::encode(vec![0, 0, 0]);
        let sig = sign::sign_detached(msg.as_bytes(), &sk);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Signature(sig));
        stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![];
        op_checksigverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// wrong message
        /// op_checksigverify([msg',sig,pk]) -> fail
        let msg = hex::encode(vec![0, 0, 1]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Signature(sig));
        stack.push(StackEntry::PubKey(pk));
        let b = op_checksigverify(&mut stack);
        assert!(!b);
        /// wrong public key
        /// op_checksig([msg,sig,pk']) -> fail
        let (pk, sk) = sign::gen_keypair();
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Signature(sig));
        stack.push(StackEntry::PubKey(pk));
        let b = op_checksigverify(&mut stack);
        assert!(!b);
        /// no message
        /// op_checksigverify([sig,pk]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Signature(sig));
        stack.push(StackEntry::PubKey(pk));
        let b = op_checksigverify(&mut stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_CHECKMULTISIG
    fn test_checkmultisig() {
        /// 2-of-3 multisig
        /// op_checkmultisig([msg,sig1,sig2,2,pk1,pk2,pk3,3]) -> [1]
        let (pk1, sk1) = sign::gen_keypair();
        let (pk2, sk2) = sign::gen_keypair();
        let (pk3, sk3) = sign::gen_keypair();
        let msg = hex::encode(vec![0, 0, 0]);
        let sig1 = sign::sign_detached(msg.as_bytes(), &sk1);
        let sig2 = sign::sign_detached(msg.as_bytes(), &sk2);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Signature(sig2));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_checkmultisig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// 0-of-3 multisig
        /// op_checkmultisig([msg,0,pk1,pk2,pk3,3]) -> [1]
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Num(0));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_checkmultisig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// 0-of-0 multisig
        /// op_checkmultisig([msg,0,0]) -> [1]
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Num(0));
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_checkmultisig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// 1-of-1 multisig
        /// op_checkmultisig([msg,sig1,1,pk1,1]) -> [1]
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_checkmultisig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// ordering is not relevant
        /// op_checkmultisig([msg,sig3,sig1,2,pk2,pk3,pk1,3]) -> [1]
        let msg = hex::encode(vec![0, 0, 0]);
        let sig3 = sign::sign_detached(msg.as_bytes(), &sk3);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Signature(sig3));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_checkmultisig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// wrong message
        /// op_checkmultisig([msg',sig1,sig2,2,pk1,pk2,pk3,3]) -> [0]
        let msg = hex::encode(vec![0, 0, 1]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Signature(sig2));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_checkmultisig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// same signature twice
        /// op_checkmultisig([msg,sig1,sig1,2,pk1,pk2,pk3,3]) -> [0]
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_checkmultisig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// too many pubkeys
        /// op_checkmultisig([MAX_PUB_KEYS_PER_MULTISIG+1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(MAX_PUB_KEYS_PER_MULTISIG as usize + ONE));
        let b = op_checkmultisig(&mut stack);
        assert!(!b);
        /// not enough pubkeys
        /// op_checkmultisig([pk1,pk2,3]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisig(&mut stack);
        assert!(!b);
        /// too many signatures
        /// op_checkmultisig([4,pk1,pk2,pk3,3]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(4));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisig(&mut stack);
        assert!(!b);
        /// not enough signatures
        /// op_checkmultisig([sig1,2,pk1,pk2,pk3,3]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisig(&mut stack);
        assert!(!b);
        /// no message
        /// op_checkmultisig([sig1,sig2,2,pk1,pk2,pk3,3]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Signature(sig2));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisig(&mut stack);
        assert!(!b);
    }

    #[test]
    /// Test OP_CHECKMULTISIGVERIFY
    fn test_checkmultisigverify() {
        /// 2-of-3 multisig
        /// op_checkmultisigverify([msg,sig1,sig2,2,pk1,pk2,pk3,3]) -> []
        let (pk1, sk1) = sign::gen_keypair();
        let (pk2, sk2) = sign::gen_keypair();
        let (pk3, sk3) = sign::gen_keypair();
        let msg = hex::encode(vec![0, 0, 0]);
        let sig1 = sign::sign_detached(msg.as_bytes(), &sk1);
        let sig2 = sign::sign_detached(msg.as_bytes(), &sk2);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Signature(sig2));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![];
        op_checkmultisigverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// 0-of-3 multisig
        /// op_checkmultisigverify([msg,0,pk1,pk2,pk3,3]) -> []
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Num(0));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![];
        op_checkmultisigverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// 0-of-0 multisig
        /// op_checkmultisig([msg,0,0]) -> []
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Num(0));
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![];
        op_checkmultisigverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// 1-of-1 multisig
        /// op_checkmultisigverify([msg,sig1,1,pk1,1]) -> []
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![];
        op_checkmultisigverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// ordering is not relevant
        /// op_checkmultisigverify([msg,sig3,sig1,2,pk2,pk3,pk1,3]) -> []
        let msg = hex::encode(vec![0, 0, 0]);
        let sig3 = sign::sign_detached(msg.as_bytes(), &sk3);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Signature(sig3));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![];
        op_checkmultisigverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// wrong message
        /// op_checkmultisigverify([msg',sig1,sig2,2,pk1,pk2,pk3,3]) -> fail
        let msg = hex::encode(vec![0, 0, 1]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Signature(sig2));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisigverify(&mut stack);
        assert!(!b);
        /// same signature twice
        /// op_checkmultisigverify([msg,sig1,sig1,2,pk1,pk2,pk3,3]) -> fail
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(msg));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        op_checkmultisigverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// too many pubkeys
        /// op_checkmultisigverify([MAX_PUB_KEYS_PER_MULTISIG+1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(MAX_PUB_KEYS_PER_MULTISIG as usize + ONE));
        let b = op_checkmultisigverify(&mut stack);
        assert!(!b);
        /// not enough pubkeys
        /// op_checkmultisigverify([pk1,pk2,3]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisigverify(&mut stack);
        assert!(!b);
        /// too many signatures
        /// op_checkmultisigverify([4,pk1,pk2,pk3,3]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(4));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisigverify(&mut stack);
        assert!(!b);
        /// not enough signatures
        /// op_checkmultisigverify([sig1,2,pk1,pk2,pk3,3]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisigverify(&mut stack);
        assert!(!b);
        /// no message
        /// op_checkmultisigverify([sig1,sig2,2,pk1,pk2,pk3,3]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Signature(sig2));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisigverify(&mut stack);
        assert!(!b);
    }

    #[test]
    fn test_is_valid_script() {
        // empty script
        let v = vec![];
        let script = Script::from(v);
        assert!(script.is_valid());
        // script length <= 10000 bytes
        let v = vec![StackEntry::Bytes("a".repeat(500)); 20];
        let script = Script::from(v);
        assert!(script.is_valid());
        // script length > 10000 bytes
        let v = vec![StackEntry::Bytes("a".repeat(500)); 21];
        let script = Script::from(v);
        assert!(!script.is_valid());
        // # opcodes <= 201
        let v = vec![StackEntry::Op(OpCodes::OP_1); MAX_OPS_PER_SCRIPT as usize];
        let script = Script::from(v);
        assert!(script.is_valid());
        // # opcodes > 201
        let v = vec![StackEntry::Op(OpCodes::OP_1); (MAX_OPS_PER_SCRIPT + 1) as usize];
        let script = Script::from(v);
        assert!(!script.is_valid());
    }

    #[test]
    fn test_is_valid_stack() {
        // empty stack
        let v = vec![];
        let stack = Stack::from(v);
        assert!(stack.is_valid());
        // # items on interpreter stack <= 1000
        let v = vec![StackEntry::Num(1); MAX_STACK_SIZE as usize];
        let stack = Stack::from(v);
        assert!(stack.is_valid());
        // # items on interpreter stack > 1000
        let v = vec![StackEntry::Num(1); (MAX_STACK_SIZE + 1) as usize];
        let stack = Stack::from(v);
        assert!(!stack.is_valid());
    }

    #[test]
    fn test_interpret_script() {
        // empty script
        let v = vec![];
        let script = Script::from(v);
        assert!(script.interpret());
        // OP_0
        let v = vec![StackEntry::Op(OpCodes::OP_0)];
        let script = Script::from(v);
        assert!(!script.interpret());
        // OP_1
        let v = vec![StackEntry::Op(OpCodes::OP_1)];
        let script = Script::from(v);
        assert!(script.interpret());
        // OP_1 OP_2 OP_ADD OP_3 OP_EQUAL
        let v = vec![
            StackEntry::Op(OpCodes::OP_1),
            StackEntry::Op(OpCodes::OP_2),
            StackEntry::Op(OpCodes::OP_ADD),
            StackEntry::Op(OpCodes::OP_3),
            StackEntry::Op(OpCodes::OP_EQUAL),
        ];
        let script = Script::from(v);
        assert!(script.interpret());
        // script length <= 10000 bytes
        let v = vec![StackEntry::Bytes("a".repeat(500)); 20];
        let script = Script::from(v);
        assert!(script.interpret());
        // script length > 10000 bytes
        let v = vec![StackEntry::Bytes("a".repeat(500)); 21];
        let script = Script::from(v);
        assert!(!script.interpret());
        // # opcodes <= 201
        let v = vec![StackEntry::Op(OpCodes::OP_1); MAX_OPS_PER_SCRIPT as usize];
        let script = Script::from(v);
        assert!(script.interpret());
        // # opcodes > 201
        let v = vec![StackEntry::Op(OpCodes::OP_1); (MAX_OPS_PER_SCRIPT + 1) as usize];
        let script = Script::from(v);
        assert!(!script.interpret());
        // # items on interpreter stack <= 1000
        let v = vec![StackEntry::Num(1); MAX_STACK_SIZE as usize];
        let script = Script::from(v);
        assert!(script.interpret());
        // # items on interpreter stack > 1000
        let v = vec![StackEntry::Num(1); (MAX_STACK_SIZE + 1) as usize];
        let script = Script::from(v);
        assert!(!script.interpret());
    }

    #[test]
    fn test_conditionals() {
        // OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        let v = vec![
            StackEntry::Op(OpCodes::OP_1),
            StackEntry::Op(OpCodes::OP_IF),
            StackEntry::Op(OpCodes::OP_2),
            StackEntry::Op(OpCodes::OP_ELSE),
            StackEntry::Op(OpCodes::OP_3),
            StackEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::from(v);
        assert!(script.interpret());
        // OP_1 OP_IF OP_0 OP_ELSE OP_3 OP_ENDIF
        let v = vec![
            StackEntry::Op(OpCodes::OP_1),
            StackEntry::Op(OpCodes::OP_IF),
            StackEntry::Op(OpCodes::OP_0),
            StackEntry::Op(OpCodes::OP_ELSE),
            StackEntry::Op(OpCodes::OP_3),
            StackEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::from(v);
        assert!(!script.interpret());
        // OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        let v = vec![
            StackEntry::Op(OpCodes::OP_0),
            StackEntry::Op(OpCodes::OP_IF),
            StackEntry::Op(OpCodes::OP_2),
            StackEntry::Op(OpCodes::OP_ELSE),
            StackEntry::Op(OpCodes::OP_3),
            StackEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::from(v);
        assert!(script.interpret());
        // OP_0 OP_IF OP_2 OP_ELSE OP_0 OP_ENDIF
        let v = vec![
            StackEntry::Op(OpCodes::OP_0),
            StackEntry::Op(OpCodes::OP_IF),
            StackEntry::Op(OpCodes::OP_2),
            StackEntry::Op(OpCodes::OP_ELSE),
            StackEntry::Op(OpCodes::OP_0),
            StackEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::from(v);
        assert!(!script.interpret());
        // OP_0 OP_NOTIF OP_2 OP_ELSE OP_0 OP_ENDIF
        let v = vec![
            StackEntry::Op(OpCodes::OP_0),
            StackEntry::Op(OpCodes::OP_NOTIF),
            StackEntry::Op(OpCodes::OP_2),
            StackEntry::Op(OpCodes::OP_ELSE),
            StackEntry::Op(OpCodes::OP_0),
            StackEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::from(v);
        assert!(script.interpret());
        // OP_0 OP_IF OP_2 OP_ENDIF
        let v = vec![
            StackEntry::Op(OpCodes::OP_1),
            StackEntry::Op(OpCodes::OP_IF),
            StackEntry::Op(OpCodes::OP_0),
            StackEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::from(v);
        assert!(!script.interpret());
        // OP_1 OP_IF OP_2 OP_IF OP_3 OP_ELSE OP_0 OP_ENDIF OP_ENDIF
        let v = vec![
            StackEntry::Op(OpCodes::OP_1),
            StackEntry::Op(OpCodes::OP_IF),
            StackEntry::Op(OpCodes::OP_2),
            StackEntry::Op(OpCodes::OP_IF),
            StackEntry::Op(OpCodes::OP_3),
            StackEntry::Op(OpCodes::OP_ELSE),
            StackEntry::Op(OpCodes::OP_0),
            StackEntry::Op(OpCodes::OP_ENDIF),
            StackEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::from(v);
        assert!(script.interpret());
        // OP_1 OP_IF OP_0 OP_IF OP_3 OP_ELSE OP_0 OP_ENDIF OP_ENDIF
        let v = vec![
            StackEntry::Op(OpCodes::OP_1),
            StackEntry::Op(OpCodes::OP_IF),
            StackEntry::Op(OpCodes::OP_0),
            StackEntry::Op(OpCodes::OP_IF),
            StackEntry::Op(OpCodes::OP_3),
            StackEntry::Op(OpCodes::OP_ELSE),
            StackEntry::Op(OpCodes::OP_0),
            StackEntry::Op(OpCodes::OP_ENDIF),
            StackEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::from(v);
        assert!(!script.interpret());
        // OP_0 OP_IF OP_2 OP_IF OP_3 OP_ELSE OP_4 OP_ENDIF OP_ELSE OP_0 OP_ENDIF
        let v = vec![
            StackEntry::Op(OpCodes::OP_0),
            StackEntry::Op(OpCodes::OP_IF),
            StackEntry::Op(OpCodes::OP_2),
            StackEntry::Op(OpCodes::OP_IF),
            StackEntry::Op(OpCodes::OP_3),
            StackEntry::Op(OpCodes::OP_ELSE),
            StackEntry::Op(OpCodes::OP_4),
            StackEntry::Op(OpCodes::OP_ENDIF),
            StackEntry::Op(OpCodes::OP_ELSE),
            StackEntry::Op(OpCodes::OP_0),
            StackEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::from(v);
        assert!(!script.interpret());
        // OP_1 OP_IF OP_1
        let v = vec![
            StackEntry::Op(OpCodes::OP_1),
            StackEntry::Op(OpCodes::OP_IF),
            StackEntry::Op(OpCodes::OP_1),
        ];
        let script = Script::from(v);
        assert!(!script.interpret());
        // OP_1 OP_IF OP_1 OP_ELSE OP_3
        let v = vec![
            StackEntry::Op(OpCodes::OP_1),
            StackEntry::Op(OpCodes::OP_IF),
            StackEntry::Op(OpCodes::OP_1),
            StackEntry::Op(OpCodes::OP_ELSE),
            StackEntry::Op(OpCodes::OP_3),
        ];
        let script = Script::from(v);
        assert!(!script.interpret());
        // OP_2 OP_ELSE OP_3 OP_ENDIF
        let v = vec![
            StackEntry::Op(OpCodes::OP_2),
            StackEntry::Op(OpCodes::OP_ELSE),
            StackEntry::Op(OpCodes::OP_3),
            StackEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::from(v);
        assert!(!script.interpret());
        // OP_IF
        let v = vec![StackEntry::Op(OpCodes::OP_IF)];
        let script = Script::from(v);
        assert!(!script.interpret());
        // OP_NOTIF
        let v = vec![StackEntry::Op(OpCodes::OP_NOTIF)];
        let script = Script::from(v);
        assert!(!script.interpret());
        // OP_ELSE
        let v = vec![StackEntry::Op(OpCodes::OP_ELSE)];
        let script = Script::from(v);
        assert!(!script.interpret());
        // OP_ENDIF
        let v = vec![StackEntry::Op(OpCodes::OP_ENDIF)];
        let script = Script::from(v);
        assert!(!script.interpret());
    }

    /// Util function to create p2pkh TxIns
    fn create_multisig_tx_ins(tx_values: Vec<TxConstructor>, m: usize) -> Vec<TxIn> {
        let mut tx_ins = Vec::new();

        for entry in tx_values {
            let mut new_tx_in = TxIn::new();
            new_tx_in.script_signature = Script::multisig_validation(
                m,
                entry.pub_keys.len(),
                entry.previous_out.t_hash.clone(),
                entry.signatures,
                entry.pub_keys,
            );
            new_tx_in.previous_out = Some(entry.previous_out);

            tx_ins.push(new_tx_in);
        }

        tx_ins
    }

    /// Util function to create multisig member TxIns
    fn create_multisig_member_tx_ins(tx_values: Vec<TxConstructor>) -> Vec<TxIn> {
        let mut tx_ins = Vec::new();

        for entry in tx_values {
            let mut new_tx_in = TxIn::new();
            new_tx_in.script_signature = Script::member_multisig(
                entry.previous_out.t_hash.clone(),
                entry.pub_keys[0],
                entry.signatures[0],
            );
            new_tx_in.previous_out = Some(entry.previous_out);

            tx_ins.push(new_tx_in);
        }

        tx_ins
    }

    #[test]
    /// Checks that a correct create script is validated as such
    fn test_pass_create_script_valid() {
        let asset = Asset::receipt(1, None, None);
        let asset_hash = construct_tx_in_signable_asset_hash(&asset);
        let (pk, sk) = sign::gen_keypair();
        let signature = sign::sign_detached(asset_hash.as_bytes(), &sk);

        let script = Script::new_create_asset(0, asset_hash, signature, pk);
        assert!(tx_has_valid_create_script(&script, &asset));
    }

    #[test]
    /// Checks that metadata is validated correctly if too large
    fn test_fail_create_receipt_script_invalid() {
        let metadata = String::from_utf8_lossy(&[0; MAX_METADATA_BYTES + 1]).to_string();
        let asset = Asset::receipt(1, None, Some(metadata));
        let asset_hash = construct_tx_in_signable_asset_hash(&asset);
        let (pk, sk) = sign::gen_keypair();
        let signature = sign::sign_detached(asset_hash.as_bytes(), &sk);

        let script = Script::new_create_asset(0, asset_hash, signature, pk);
        assert!(!tx_has_valid_create_script(&script, &asset));
    }

    #[test]
    /// Checks whether addresses are validated correctly
    fn test_validate_addresses_correctly() {
        let (pk, _) = sign::gen_keypair();
        let address = construct_address(&pk);

        assert!(address_has_valid_length(&address));
        assert!(address_has_valid_length(&hex::encode([0; 32])));
        assert!(!address_has_valid_length(&hex::encode([0; 64])));
    }

    #[test]
    /// Checks that correct member multisig scripts are validated as such
    fn test_pass_member_multisig_valid() {
        test_pass_member_multisig_valid_common(None);
    }

    #[test]
    /// Checks that correct member multisig scripts are validated as such
    fn test_pass_member_multisig_valid_v0() {
        test_pass_member_multisig_valid_common(Some(NETWORK_VERSION_V0));
    }

    #[test]
    /// Checks that correct member multisig scripts are validated as such
    fn test_pass_member_multisig_valid_temp() {
        test_pass_member_multisig_valid_common(Some(NETWORK_VERSION_TEMP));
    }

    fn test_pass_member_multisig_valid_common(address_version: Option<u64>) {
        let (pk, sk) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let signature = sign::sign_detached(t_hash.as_bytes(), &sk);

        let tx_const = TxConstructor {
            previous_out: OutPoint::new(t_hash, 0),
            signatures: vec![signature],
            pub_keys: vec![pk],
            address_version,
        };

        let tx_ins = create_multisig_member_tx_ins(vec![tx_const]);

        assert!(&tx_ins[0].clone().script_signature.interpret());
    }

    #[test]
    /// Checks that incorrect member multisig scripts are validated as such
    fn test_fail_member_multisig_invalid() {
        test_fail_member_multisig_invalid_common(None);
    }

    #[test]
    /// Checks that incorrect member multisig scripts are validated as such
    fn test_fail_member_multisig_invalid_v0() {
        test_fail_member_multisig_invalid_common(Some(NETWORK_VERSION_V0));
    }

    #[test]
    /// Checks that incorrect member multisig scripts are validated as such
    fn test_fail_member_multisig_invalid_temp() {
        test_fail_member_multisig_invalid_common(Some(NETWORK_VERSION_TEMP));
    }

    fn test_fail_member_multisig_invalid_common(address_version: Option<u64>) {
        let (_pk, sk) = sign::gen_keypair();
        let (pk, _sk) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let signature = sign::sign_detached(t_hash.as_bytes(), &sk);

        let tx_const = TxConstructor {
            previous_out: OutPoint::new(t_hash, 0),
            signatures: vec![signature],
            pub_keys: vec![pk],
            address_version,
        };

        let tx_ins = create_multisig_member_tx_ins(vec![tx_const]);

        assert!(!&tx_ins[0].clone().script_signature.interpret());
    }

    #[test]
    /// Checks that correct p2pkh transaction signatures are validated as such
    fn test_pass_p2pkh_sig_valid() {
        test_pass_p2pkh_sig_valid_common(None);
    }

    #[test]
    /// Checks that correct p2pkh transaction signatures are validated as such
    fn test_pass_p2pkh_sig_valid_v0() {
        test_pass_p2pkh_sig_valid_common(Some(NETWORK_VERSION_V0));
    }

    #[test]
    /// Checks that correct p2pkh transaction signatures are validated as such
    fn test_pass_p2pkh_sig_valid_temp() {
        test_pass_p2pkh_sig_valid_common(Some(NETWORK_VERSION_TEMP));
    }

    fn test_pass_p2pkh_sig_valid_common(address_version: Option<u64>) {
        let (pk, sk) = sign::gen_keypair();
        let outpoint = OutPoint {
            t_hash: hex::encode(vec![0, 0, 0]),
            n: 0,
        };

        let hash_to_sign = construct_tx_in_signable_hash(&outpoint);
        let signature = sign::sign_detached(hash_to_sign.as_bytes(), &sk);

        let tx_const = TxConstructor {
            previous_out: outpoint,
            signatures: vec![signature],
            pub_keys: vec![pk],
            address_version,
        };

        let tx_ins = construct_payment_tx_ins(vec![tx_const]);
        let tx_out_pk = construct_address_for(&pk, address_version);

        assert!(tx_has_valid_p2pkh_sig(
            &tx_ins[0].script_signature,
            &hash_to_sign,
            &tx_out_pk
        ));
    }

    #[test]
    /// Checks that invalid p2pkh transaction signatures are validated as such
    fn test_fail_p2pkh_sig_invalid() {
        test_fail_p2pkh_sig_invalid_common(None);
    }

    #[test]
    /// Checks that invalid p2pkh transaction signatures are validated as such
    fn test_fail_p2pkh_sig_invalid_v0() {
        test_fail_p2pkh_sig_invalid_common(Some(NETWORK_VERSION_V0));
    }

    fn test_fail_p2pkh_sig_invalid_common(address_version: Option<u64>) {
        let (pk, sk) = sign::gen_keypair();
        let (second_pk, _s) = sign::gen_keypair();
        let outpoint = OutPoint {
            t_hash: hex::encode(vec![0, 0, 0]),
            n: 0,
        };

        let hash_to_sign = construct_tx_in_signable_hash(&outpoint);
        let signature = sign::sign_detached(hash_to_sign.as_bytes(), &sk);

        let tx_const = TxConstructor {
            previous_out: outpoint,
            signatures: vec![signature],
            pub_keys: vec![second_pk],
            address_version,
        };

        let tx_ins = construct_payment_tx_ins(vec![tx_const]);
        let tx_out_pk = construct_address(&pk);

        assert!(!tx_has_valid_p2pkh_sig(
            &tx_ins[0].script_signature,
            &hash_to_sign,
            &tx_out_pk
        ));
    }

    #[test]
    /// Checks that invalid p2pkh transaction signatures are validated as such
    fn test_fail_p2pkh_sig_script_empty() {
        test_fail_p2pkh_sig_script_empty_common(None);
    }

    #[test]
    /// Checks that invalid p2pkh transaction signatures are validated as such
    fn test_fail_p2pkh_sig_script_empty_v0() {
        test_fail_p2pkh_sig_script_empty_common(Some(NETWORK_VERSION_V0));
    }

    #[test]
    /// Checks that invalid p2pkh transaction signatures are validated as such
    fn test_fail_p2pkh_sig_script_empty_temp() {
        test_fail_p2pkh_sig_script_empty_common(Some(NETWORK_VERSION_V0));
    }

    fn test_fail_p2pkh_sig_script_empty_common(address_version: Option<u64>) {
        let (pk, sk) = sign::gen_keypair();
        let outpoint = OutPoint {
            t_hash: hex::encode(vec![0, 0, 0]),
            n: 0,
        };

        let hash_to_sign = construct_tx_in_signable_hash(&outpoint);
        let signature = sign::sign_detached(hash_to_sign.as_bytes(), &sk);

        let tx_const = TxConstructor {
            previous_out: outpoint,
            signatures: vec![signature],
            pub_keys: vec![pk],
            address_version,
        };

        let mut tx_ins = Vec::new();

        for entry in vec![tx_const] {
            let mut new_tx_in = TxIn::new();
            new_tx_in.script_signature = Script::new();
            new_tx_in.previous_out = Some(entry.previous_out);

            tx_ins.push(new_tx_in);
        }

        let tx_out_pk = construct_address(&pk);

        assert!(!tx_has_valid_p2pkh_sig(
            &tx_ins[0].script_signature,
            &hash_to_sign,
            &tx_out_pk
        ));
    }

    #[test]
    /// Checks that invalid p2pkh transaction signatures are validated as such
    fn test_fail_p2pkh_sig_script_invalid_struct() {
        test_fail_p2pkh_sig_script_invalid_struct_common(None);
    }

    #[test]
    /// Checks that invalid p2pkh transaction signatures are validated as such
    fn test_fail_p2pkh_sig_script_invalid_struct_v0() {
        test_fail_p2pkh_sig_script_invalid_struct_common(Some(NETWORK_VERSION_V0));
    }

    #[test]
    /// Checks that invalid p2pkh transaction signatures are validated as such
    fn test_fail_p2pkh_sig_script_invalid_struct_temp() {
        test_fail_p2pkh_sig_script_invalid_struct_common(Some(NETWORK_VERSION_TEMP));
    }

    fn test_fail_p2pkh_sig_script_invalid_struct_common(address_version: Option<u64>) {
        let (pk, sk) = sign::gen_keypair();
        let outpoint = OutPoint {
            t_hash: hex::encode(vec![0, 0, 0]),
            n: 0,
        };

        let hash_to_sign = construct_tx_in_signable_hash(&outpoint);
        let signature = sign::sign_detached(hash_to_sign.as_bytes(), &sk);

        let tx_const = TxConstructor {
            previous_out: outpoint,
            signatures: vec![signature],
            pub_keys: vec![pk],
            address_version,
        };

        let mut tx_ins = Vec::new();

        for entry in vec![tx_const] {
            let mut new_tx_in = TxIn::new();
            new_tx_in.script_signature = Script::new();
            new_tx_in
                .script_signature
                .stack
                .push(StackEntry::Bytes("".to_string()));
            new_tx_in.previous_out = Some(entry.previous_out);

            tx_ins.push(new_tx_in);
        }

        let tx_out_pk = construct_address(&pk);

        assert!(!tx_has_valid_p2pkh_sig(
            &tx_ins[0].script_signature,
            &hash_to_sign,
            &tx_out_pk
        ));
    }

    #[test]
    /// Checks that correct multisig validation signatures are validated as such
    fn test_pass_multisig_validation_valid() {
        test_pass_multisig_validation_valid_common(None);
    }

    #[test]
    /// Checks that correct multisig validation signatures are validated as such
    fn test_pass_multisig_validation_valid_v0() {
        test_pass_multisig_validation_valid_common(Some(NETWORK_VERSION_V0));
    }

    #[test]
    /// Checks that correct multisig validation signatures are validated as such
    fn test_pass_multisig_validation_valid_temp() {
        test_pass_multisig_validation_valid_common(Some(NETWORK_VERSION_TEMP));
    }

    fn test_pass_multisig_validation_valid_common(address_version: Option<u64>) {
        let (first_pk, first_sk) = sign::gen_keypair();
        let (second_pk, second_sk) = sign::gen_keypair();
        let (third_pk, third_sk) = sign::gen_keypair();
        let check_data = hex::encode(vec![0, 0, 0]);

        let m = 2;
        let first_sig = sign::sign_detached(check_data.as_bytes(), &first_sk);
        let second_sig = sign::sign_detached(check_data.as_bytes(), &second_sk);

        let tx_const = TxConstructor {
            previous_out: OutPoint::new(check_data, 0),
            signatures: vec![first_sig, second_sig],
            pub_keys: vec![first_pk, second_pk, third_pk],
            address_version,
        };

        let tx_ins = create_multisig_tx_ins(vec![tx_const], m);

        assert!(&tx_ins[0].script_signature.interpret());
    }

    #[test]
    /// Validate tx_is_valid for multiple TxIn configurations
    fn test_tx_is_valid() {
        test_tx_is_valid_common(None, OpCodes::OP_HASH256);
    }

    #[test]
    /// Validate tx_is_valid for multiple TxIn configurations
    fn test_tx_is_valid_v0() {
        test_tx_is_valid_common(Some(NETWORK_VERSION_V0), OpCodes::OP_HASH256_V0);
    }

    #[test]
    /// Validate tx_is_valid for multiple TxIn configurations
    fn test_tx_is_valid_temp() {
        test_tx_is_valid_common(Some(NETWORK_VERSION_TEMP), OpCodes::OP_HASH256_TEMP);
    }

    fn test_tx_is_valid_common(address_version: Option<u64>, op_hash256: OpCodes) {
        //
        // Arrange
        //
        let (pk, sk) = sign::gen_keypair();
        let tx_hash = hex::encode(vec![0, 0, 0]);
        let tx_outpoint = OutPoint::new(tx_hash, 0);
        let script_public_key = construct_address_for(&pk, address_version);
        let tx_in_previous_out = TxOut::new_token_amount(script_public_key.clone(), TokenAmount(5));
        let ongoing_tx_outs = vec![tx_in_previous_out.clone()];

        let valid_bytes = construct_tx_in_signable_hash(&tx_outpoint);
        let valid_sig = sign::sign_detached(valid_bytes.as_bytes(), &sk);

        // Test cases:
        let inputs = vec![
            // 0. Happy case: valid test
            (
                vec![
                    StackEntry::Bytes(valid_bytes),
                    StackEntry::Signature(valid_sig),
                    StackEntry::PubKey(pk),
                    StackEntry::Op(OpCodes::OP_DUP),
                    StackEntry::Op(op_hash256),
                    StackEntry::PubKeyHash(script_public_key),
                    StackEntry::Op(OpCodes::OP_EQUALVERIFY),
                    StackEntry::Op(OpCodes::OP_CHECKSIG),
                ],
                true,
            ),
            // 2. Empty script
            (vec![StackEntry::Bytes("".to_string())], false),
        ];

        //
        // Act
        //
        let mut actual_result = Vec::new();
        for (script, _) in &inputs {
            let tx_ins = vec![TxIn {
                script_signature: Script {
                    stack: script.clone(),
                },
                previous_out: Some(tx_outpoint.clone()),
            }];

            let tx = Transaction {
                inputs: tx_ins,
                outputs: ongoing_tx_outs.clone(),
                ..Default::default()
            };

            let result = tx_is_valid(&tx, |v| {
                Some(&tx_in_previous_out).filter(|_| v == &tx_outpoint)
            });
            actual_result.push(result);
        }

        //
        // Assert
        //
        assert_eq!(
            actual_result,
            inputs.iter().map(|(_, e)| *e).collect::<Vec<bool>>(),
        );
    }

    #[test]
    /// ### Test Case 1
    ///
    ///  - *Tokens only*
    /// -  *Success*
    ///
    /// 1. Inputs contain two `TxIn`s for `Token`s of amounts `3` and `2`
    /// 2. Outputs contain `TxOut`s for `Token`s of amounts `3` and `2`
    fn test_tx_drs_tokens_only_success() {
        test_tx_drs_common(
            &[(3, None, None), (2, None, None)],
            &[(3, None), (2, None)],
            true,
        );
    }

    #[test]
    /// ### Test Case 2
    ///
    ///  - *Tokens only*
    /// -  *Failure*
    ///
    /// 1. Inputs contain two `TxIn`s for `Token`s of amounts `3` and `2`
    /// 2. Outputs contain `TxOut`s for `Token`s of amounts `3` and `3`
    /// 3. `TxIn` `Token`s amount does not match `TxOut` `Token`s amount
    fn test_tx_drs_tokens_only_failure_amount_mismatch() {
        test_tx_drs_common(
            &[(3, None, None), (2, None, None)],
            &[(3, None), (3, None)],
            false,
        );
    }

    #[test]
    /// ### Test Case 3
    ///
    ///  - *Receipts only*
    /// -  *Failure*
    ///
    /// 1. Inputs contain two `TxIn`s for `Receipt`s of amount `3` and `2` with different `drs_tx_hash` values
    /// 2. Outputs contain `TxOut`s for `Receipt`s of amount `3` and `3`
    /// 3. `TxIn` DRS matches `TxOut` DRS for `Receipt`s; Amount of `Receipt`s spent does not match    
    fn test_tx_drs_receipts_only_failure_amount_mismatch() {
        test_tx_drs_common(
            &[
                (3, Some("drs_tx_hash_1"), None),
                (2, Some("drs_tx_hash_2"), None),
            ],
            &[(3, Some("drs_tx_hash_1")), (3, Some("drs_tx_hash_2"))],
            false,
        );
    }

    #[test]
    /// ### Test Case 4
    ///
    ///  - *Receipts only*
    /// -  *Failure*
    ///
    /// 1. Inputs contain two `TxIn`s for `Receipt`s of amount `3` and `2` with different `drs_tx_hash` values
    /// 2. Outputs contain `TxOut`s for `Receipt`s of amount `3` and `2`
    /// 3. `TxIn` DRS does not match `TxOut` DRS for `Receipt`s; Amount of `Receipt`s spent matches     
    fn test_tx_drs_receipts_only_failure_drs_mismatch() {
        test_tx_drs_common(
            &[
                (3, Some("drs_tx_hash_1"), None),
                (2, Some("drs_tx_hash_2"), None),
            ],
            &[(3, Some("drs_tx_hash_1")), (2, Some("invalid_drs_tx_hash"))],
            false,
        );
    }

    #[test]
    /// ### Test Case 5
    ///
    ///  - *Receipts and Tokens*
    /// -  *Success*
    ///
    /// 1. Inputs contain two `TxIn`s for `Receipt`s of amount `3` and `Token`s of amount `2`
    /// 2. Outputs contain `TxOut`s for `Receipt`s of amount `3` and `Token`s of amount `2`
    /// 3. `TxIn` DRS matches `TxOut` DRS for `Receipt`s; Amount of `Receipt`s and `Token`s spent matches      
    fn test_tx_drs_receipts_and_tokens_success() {
        test_tx_drs_common(
            &[(3, Some("drs_tx_hash"), None), (2, None, None)],
            &[(3, Some("drs_tx_hash")), (2, None)],
            true,
        );
    }

    #[test]
    /// ### Test Case 6
    ///
    ///  - *Receipts and Tokens*
    /// -  *Failure*
    ///
    /// 1. Inputs contain two `TxIn`s for `Receipt`s of amount `3` and `Token`s of amount `2`
    /// 2. Outputs contain `TxOut`s for `Receipt`s of amount `2` and `Token`s of amount `2`
    /// 3. `TxIn` DRS matches `TxOut` DRS for `Receipt`s; Amount of `Receipt`s spent does not match      
    fn test_tx_drs_receipts_and_tokens_failure_amount_mismatch() {
        test_tx_drs_common(
            &[(3, Some("drs_tx_hash"), None), (2, None, None)],
            &[(2, Some("drs_tx_hash")), (2, None)],
            false,
        );
    }

    #[test]
    /// ### Test Case 7
    ///
    ///  - *Receipts and Tokens*
    /// -  *Failure*
    ///
    /// 1. Inputs contain two `TxIn`s for `Receipt`s of amount `3` and `Token`s of amount `2`
    /// 2. Outputs contain `TxOut`s for `Receipt`s of amount `1` and Tokens of amount `1`
    /// 3. `TxIn` DRS does not match `TxOut` DRS for `Receipt`s; Amount of `Receipt`s and `Token`s spent does not match;
    /// Metadata does not match                
    fn test_tx_drs_receipts_and_tokens_failure_amount_and_drs_mismatch() {
        let test_metadata: Option<String> = Some(
            "{\"name\":\"test\",\"description\":\"test\",\"image\":\"test\",\"url\":\"test\"}"
                .to_string(),
        );

        test_tx_drs_common(
            &[
                (3, Some("drs_tx_hash"), test_metadata.clone()),
                (2, None, test_metadata),
            ],
            &[(1, Some("invalid_drs_tx_hash")), (1, None)],
            false,
        );
    }

    /// Test transaction validation with multiple different DRS
    /// configurations for `TxIn` and `TxOut` values
    fn test_tx_drs_common(
        inputs: &[(u64, Option<&str>, Option<String>)],
        outputs: &[(u64, Option<&str>)],
        expected_result: bool,
    ) {
        ///
        /// Arrange
        ///
        let (utxo, tx) = generate_tx_with_ins_and_outs_assets(inputs, outputs);

        ///
        /// Act
        ///
        let actual_result = tx_is_valid(&tx, |v| utxo.get(v));

        ///
        /// Assert
        ///
        assert_eq!(actual_result, expected_result);
    }

    #[test]
    /// Checks that incorrect member interpret scripts are validated as such
    fn test_fail_interpret_valid() {
        test_fail_interpret_valid_common(None);
    }

    #[test]
    /// Checks that incorrect member interpret scripts are validated as such
    fn test_fail_interpret_valid_v0() {
        test_fail_interpret_valid_common(Some(NETWORK_VERSION_V0));
    }

    #[test]
    /// Checks that incorrect member interpret scripts are validated as such
    fn test_fail_interpret_valid_temp() {
        test_fail_interpret_valid_common(Some(NETWORK_VERSION_TEMP));
    }

    fn test_fail_interpret_valid_common(address_version: Option<u64>) {
        let (_pk, sk) = sign::gen_keypair();
        let (pk, _sk) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let signature = sign::sign_detached(t_hash.as_bytes(), &sk);

        let tx_const = TxConstructor {
            previous_out: OutPoint::new(t_hash, 0),
            signatures: vec![signature],
            pub_keys: vec![pk],
            address_version,
        };

        let tx_ins = create_multisig_member_tx_ins(vec![tx_const]);

        assert!(!&tx_ins[0].clone().script_signature.interpret());
    }

    #[test]
    /// Checks that interpret scripts are validated as such
    fn test_pass_interpret_valid() {
        test_pass_interpret_valid_common(None);
    }

    #[test]
    /// Checks that interpret scripts are validated as such
    fn test_pass_interpret_valid_v0() {
        test_pass_interpret_valid_common(Some(NETWORK_VERSION_V0));
    }

    #[test]
    /// Checks that interpret scripts are validated as such
    fn test_pass_interpret_valid_temp() {
        test_pass_interpret_valid_common(Some(NETWORK_VERSION_TEMP));
    }

    fn test_pass_interpret_valid_common(address_version: Option<u64>) {
        let (pk, sk) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let signature = sign::sign_detached(t_hash.as_bytes(), &sk);

        let tx_const = TxConstructor {
            previous_out: OutPoint::new(t_hash, 0),
            signatures: vec![signature],
            pub_keys: vec![pk],
            address_version,
        };

        let tx_ins = create_multisig_member_tx_ins(vec![tx_const]);

        assert!(&tx_ins[0].clone().script_signature.interpret());
    }
}
