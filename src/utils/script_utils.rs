#![allow(unused)]
use crate::constants::{
    MAX_METADATA_BYTES, MAX_STACK_SIZE, NETWORK_VERSION_TEMP, NETWORK_VERSION_V0, P2SH_PREPEND,
    TOTAL_TOKENS,
};
use crate::crypto::sha3_256;
use crate::crypto::sign_ed25519::{self as sign, PublicKey, Signature};
use crate::primitives::asset::{Asset, AssetValues, ReceiptAsset, TokenAmount};
use crate::primitives::druid::DruidExpectation;
use crate::primitives::transaction::*;
use crate::script::interface_ops;
use crate::script::lang::Script;
use crate::script::{OpCodes, StackEntry};
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

/// Verifies that a member of a multisig tx script is valid
///
/// ### Arguments
///
/// * `script`  - Script to verify
pub fn member_multisig_is_valid(script: Script) -> bool {
    let mut current_stack: Vec<StackEntry> = Vec::with_capacity(script.stack.len());
    let mut test_for_return = true;
    for stack_entry in script.stack {
        if test_for_return {
            match stack_entry {
                StackEntry::Op(OpCodes::OP_CHECKSIG) => {
                    test_for_return &= interface_ops::op_checkmultisigmem(&mut current_stack);
                }
                _ => {
                    interface_ops::push_entry_to_stack(stack_entry, &mut current_stack);
                }
            }
        } else {
            return false;
        }
    }

    test_for_return
}

/// Verifies that all incoming transactions are allowed to be spent. Returns false if a single
/// transaction doesn't verify
///
/// TODO: Currently assumes p2pkh, abstract to all tx types
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

/// Checks whether a complete validation multisig transaction is in fact valid
///
/// ### Arguments
///
/// * `script`  - `Script` to validate
fn tx_has_valid_multsig_validation(script: &Script) -> bool {
    let mut current_stack: Vec<StackEntry> = Vec::with_capacity(script.stack.len());
    let mut test_for_return = true;
    for stack_entry in &script.stack {
        if test_for_return {
            match stack_entry {
                StackEntry::Op(OpCodes::OP_CHECKMULTISIG) => {
                    test_for_return &= interface_ops::op_multisig(&mut current_stack);
                }
                _ => {
                    test_for_return &=
                        interface_ops::push_entry_to_stack_ref(stack_entry, &mut current_stack);
                }
            }
        } else {
            return false;
        }
    }

    test_for_return
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
        if b == &asset_hash && interpret_script(script) {
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
        if h == tx_out_pub_key && b == outpoint_hash && interpret_script(script) {
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
        return interpret_script(script);
    }

    trace!(
        "Invalid P2SH script: {:?}, address: {}",
        script.stack,
        address
    );

    false
}

/// Handles the byte code unwrap and execution for transaction scripts
///
/// ### Arguments
///
/// * `script`  - Script to unwrap and execute
fn interpret_script(script: &Script) -> bool {
    // TODO: add checks on constants
    let mut current_stack: Vec<StackEntry> = Vec::with_capacity(MAX_STACK_SIZE as usize);
    let mut current_alt_stack: Vec<StackEntry> = Vec::with_capacity(MAX_STACK_SIZE as usize);
    let mut test_for_return = true;
    for stack_entry in &script.stack {
        if test_for_return {
            match stack_entry {
                /*---- STACK OPS ----*/
                StackEntry::Op(OpCodes::OP_TOALTSTACK) => {
                    test_for_return &=
                        interface_ops::op_toaltstack(&mut current_stack, &mut current_alt_stack);
                }
                StackEntry::Op(OpCodes::OP_FROMALTSTACK) => {
                    test_for_return &=
                        interface_ops::op_fromaltstack(&mut current_stack, &mut current_alt_stack);
                }
                StackEntry::Op(OpCodes::OP_2DROP) => {
                    test_for_return &= interface_ops::op_2drop(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_2DUP) => {
                    test_for_return &= interface_ops::op_2dup(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_3DUP) => {
                    test_for_return &= interface_ops::op_3dup(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_2OVER) => {
                    test_for_return &= interface_ops::op_2over(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_2ROT) => {
                    test_for_return &= interface_ops::op_2rot(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_2SWAP) => {
                    test_for_return &= interface_ops::op_2swap(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_IFDUP) => {
                    test_for_return &= interface_ops::op_ifdup(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_DEPTH) => {
                    test_for_return &= interface_ops::op_depth(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_DROP) => {
                    test_for_return &= interface_ops::op_drop(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_DUP) => {
                    test_for_return &= interface_ops::op_dup(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_NIP) => {
                    test_for_return &= interface_ops::op_nip(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_OVER) => {
                    test_for_return &= interface_ops::op_over(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_PICK) => {
                    test_for_return &= interface_ops::op_pick(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_ROLL) => {
                    test_for_return &= interface_ops::op_roll(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_ROT) => {
                    test_for_return &= interface_ops::op_rot(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_SWAP) => {
                    test_for_return &= interface_ops::op_swap(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_TUCK) => {
                    test_for_return &= interface_ops::op_tuck(&mut current_stack);
                }
                /*---- SPLICE OPS ----*/
                StackEntry::Op(OpCodes::OP_SIZE) => {
                    test_for_return &= interface_ops::op_size(&mut current_stack);
                }
                /*---- BITWISE LOGIC OPS ----*/
                StackEntry::Op(OpCodes::OP_EQUAL) => {
                    test_for_return &= interface_ops::op_equal(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_EQUALVERIFY) => {
                    test_for_return &= interface_ops::op_equalverify(&mut current_stack);
                }
                /*---- ARITHMETIC OPS ----*/
                StackEntry::Op(OpCodes::OP_1ADD) => {
                    test_for_return &= interface_ops::op_1add(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_1SUB) => {
                    test_for_return &= interface_ops::op_1sub(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_NOT) => {
                    test_for_return &= interface_ops::op_not(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_0NOTEQUAL) => {
                    test_for_return &= interface_ops::op_0notequal(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_ADD) => {
                    test_for_return &= interface_ops::op_add(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_SUB) => {
                    test_for_return &= interface_ops::op_sub(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_BOOLAND) => {
                    test_for_return &= interface_ops::op_booland(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_BOOLOR) => {
                    test_for_return &= interface_ops::op_boolor(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_NUMEQUAL) => {
                    test_for_return &= interface_ops::op_numequal(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_NUMEQUALVERIFY) => {
                    test_for_return &= interface_ops::op_numequalverify(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_NUMNOTEQUAL) => {
                    test_for_return &= interface_ops::op_numnotequal(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_LESSTHAN) => {
                    test_for_return &= interface_ops::op_lessthan(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_GREATERTHAN) => {
                    test_for_return &= interface_ops::op_greaterthan(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_LESSTHANOREQUAL) => {
                    test_for_return &= interface_ops::op_lessthanorequal(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_GREATERTHANOREQUAL) => {
                    test_for_return &= interface_ops::op_greaterthanorequal(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_MIN) => {
                    test_for_return &= interface_ops::op_min(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_MAX) => {
                    test_for_return &= interface_ops::op_max(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_WITHIN) => {
                    test_for_return &= interface_ops::op_within(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_CREATE) => {
                    current_stack.pop();
                }

                /*---- CRYPTO OPS ----*/
                StackEntry::Op(OpCodes::OP_HASH256) => {
                    test_for_return &= interface_ops::op_hash256(&mut current_stack, None);
                }
                StackEntry::Op(OpCodes::OP_HASH256_V0) => {
                    test_for_return &=
                        interface_ops::op_hash256(&mut current_stack, Some(NETWORK_VERSION_V0));
                }
                StackEntry::Op(OpCodes::OP_HASH256_TEMP) => {
                    test_for_return &=
                        interface_ops::op_hash256(&mut current_stack, Some(NETWORK_VERSION_TEMP));
                }
                StackEntry::Op(OpCodes::OP_EQUALVERIFY) => {
                    test_for_return &= interface_ops::op_equalverify(&mut current_stack);
                }
                StackEntry::Op(OpCodes::OP_CHECKSIG) => {
                    test_for_return &= interface_ops::op_checksig(&mut current_stack);
                }
                _ => {
                    test_for_return &=
                        interface_ops::push_entry_to_stack_ref(stack_entry, &mut current_stack);
                }
            }
        } else {
            return false;
        }
    }

    test_for_return && current_stack.is_empty()
}

/// Does pairwise validation of signatures against public keys
///
/// ### Arguments
///
/// * `check_data`  - Data to verify against
/// * `signatures`  - Signatures to check
/// * `pub_keys`    - Public keys to check
/// * `m`           - Number of keys required
fn match_on_multisig_to_pubkey(
    check_data: String,
    signatures: Vec<Signature>,
    pub_keys: Vec<PublicKey>,
    m: usize,
) -> bool {
    let mut counter = 0;

    'outer: for sig in signatures {
        'inner: for pub_key in &pub_keys {
            if sign::verify_detached(&sig, check_data.as_bytes(), pub_key) {
                counter += 1;
                break 'inner;
            }
        }
    }

    counter >= m
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

        assert!(member_multisig_is_valid(tx_ins[0].clone().script_signature));
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

        assert!(!member_multisig_is_valid(
            tx_ins[0].clone().script_signature
        ));
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
        let third_sig = sign::sign_detached(check_data.as_bytes(), &third_sk);

        let tx_const = TxConstructor {
            previous_out: OutPoint::new(check_data, 0),
            signatures: vec![first_sig, second_sig, third_sig],
            pub_keys: vec![first_pk, second_pk, third_pk],
            address_version,
        };

        let tx_ins = create_multisig_tx_ins(vec![tx_const], m);

        assert!(tx_has_valid_multsig_validation(&tx_ins[0].script_signature));
    }

    #[test]
    /// Ensures that enough pubkey-sigs are provided to complete the multisig
    fn test_pass_sig_pub_keypairs_for_multisig_valid() {
        let (first_pk, first_sk) = sign::gen_keypair();
        let (second_pk, second_sk) = sign::gen_keypair();
        let (third_pk, third_sk) = sign::gen_keypair();
        let check_data = hex::encode(vec![0, 0, 0]);

        let m = 2;
        let first_sig = sign::sign_detached(check_data.as_bytes(), &first_sk);
        let second_sig = sign::sign_detached(check_data.as_bytes(), &second_sk);
        let third_sig = sign::sign_detached(check_data.as_bytes(), &third_sk);

        assert!(match_on_multisig_to_pubkey(
            check_data,
            vec![first_sig, second_sig, third_sig],
            vec![first_pk, second_pk, third_pk],
            m
        ));
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

        assert!(!interpret_script(&(tx_ins[0].clone().script_signature)));
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

        assert!(interpret_script(&(tx_ins[0].clone().script_signature)));
    }
}
