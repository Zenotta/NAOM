use crate::primitives::asset::Asset;
use crate::primitives::transaction::*;
use crate::script::lang::Script;
use crate::script::{OpCodes, StackEntry};
use crate::sha3::Digest;

use bincode::serialize;
use bytes::Bytes;
use hex::encode;
use sha3::Sha3_256;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::ed25519::{PublicKey, Signature};
use std::collections::BTreeMap;
use tracing::{debug, error, info};

/// Verifies that a member of a multisig tx script is valid
///
/// ### Arguments
///
/// * `script`  - Script to verify
pub fn member_multisig_is_valid(script: Script) -> bool {
    let mut current_stack: Vec<StackEntry> = Vec::with_capacity(script.stack.len());

    for stack_entry in script.stack {
        match stack_entry {
            StackEntry::Op(OpCodes::OP_CHECKSIG) => {
                println!("Checking signature matches public key for multisig member");
                let pub_key: PublicKey = match current_stack.pop().unwrap() {
                    StackEntry::PubKey(pub_key) => pub_key,
                    _ => panic!("Public key not present to verify transaction"),
                };

                let sig: Signature = match current_stack.pop().unwrap() {
                    StackEntry::Signature(sig) => sig,
                    _ => panic!("Signature not present to verify transaction"),
                };

                let check_data = match current_stack.pop().unwrap() {
                    StackEntry::Bytes(check_data) => check_data,
                    _ => panic!("Check data bytes not present to verify transaction"),
                };

                if (!sign::verify_detached(&sig, check_data.as_bytes(), &pub_key)) {
                    error!("Signature not valid. Member multisig input invalid");
                    return false;
                }
            }
            _ => {
                println!("Adding constant to stack: {:?}", stack_entry);
                current_stack.push(stack_entry);
            }
        }
    }

    true
}

/// Verifies that all incoming tx_ins are allowed to be spent. Returns false if a single
/// transaction doesn't verify
///
/// TODO: Currently assumes p2pkh, abstract to all tx types
///
/// ### Arguments
///
/// * `tx_ins`  - Tx_ins to verify
pub fn tx_ins_are_valid(tx_ins: &[TxIn], is_in_utxo: impl Fn(&OutPoint) -> bool) -> bool {
    for tx_in in tx_ins {
        let tx_out_point = tx_in.previous_out.as_ref().unwrap();

        if !is_in_utxo(tx_out_point) {
            println!();
            println!("UTXO DOESN'T CONTAIN THIS TX");
            println!();
        }

        if (!tx_has_valid_p2pkh_sig(&tx_in.script_signature)
            && !tx_has_valid_multsig_validation(&tx_in.script_signature))
            || !is_in_utxo(tx_out_point)
        {
            return false;
        }
    }

    true
}

/// Checks for sanctioned addresses in the `TxIn`s. If any
/// are found, returns false
///
/// ### Arguments
///
/// * `tx_ins`  - The OutPoints to check for sanctioned addresses
pub fn tx_sanction_filter(tx_ins: &Vec<TxIn>, sanction_list: &Vec<String>) -> bool {
    for entry in tx_ins {
        if let Some(o) = &entry.previous_out {
            if sanction_list.contains(&o.t_hash) {
                return false;
            }
        }
    }

    true
}

/// Checks whether a complete validation multisig transaction is in fact valid
///
/// ### Arguments
///
/// * `script`  - Script to validate
fn tx_has_valid_multsig_validation(script: &Script) -> bool {
    let mut current_stack: Vec<StackEntry> = Vec::with_capacity(script.stack.len());

    for stack_entry in &script.stack {
        match stack_entry {
            StackEntry::Op(OpCodes::OP_CHECKMULTISIG) => {
                let mut pub_keys = Vec::new();
                let mut signatures = Vec::new();
                let mut last_val = StackEntry::Op(OpCodes::OP_0);
                let n = match current_stack.pop().unwrap() {
                    StackEntry::Num(n) => n,
                    _ => panic!("No n value of keys for multisig present"),
                };

                while let StackEntry::PubKey(_pk) = current_stack[current_stack.len() - 1] {
                    let next_key = current_stack.pop();

                    if let Some(StackEntry::PubKey(pub_key)) = next_key {
                        pub_keys.push(pub_key);
                    }
                }

                // If there are too few public keys
                if pub_keys.len() < n {
                    println!("Too few public keys provided");
                    return false;
                }

                let m = match current_stack.pop().unwrap() {
                    StackEntry::Num(m) => m,
                    _ => panic!("No n value of keys for multisig present"),
                };

                // If there are more keys required than available
                if m > n || m > pub_keys.len() {
                    println!("Number of keys required is greater than the number available");
                    return false;
                }

                while let StackEntry::Signature(_sig) = current_stack[current_stack.len() - 1] {
                    let next_key = current_stack.pop();

                    if let Some(StackEntry::Signature(sig)) = next_key {
                        signatures.push(sig);
                    }
                }

                let check_data = match current_stack.pop().unwrap() {
                    StackEntry::Bytes(check_data) => check_data,
                    _ => panic!("Check data for validation not present"),
                };

                if !match_on_multisig_to_pubkey(check_data, signatures, pub_keys, m) {
                    return false;
                }
            }

            _ => {
                println!("Adding constant to stack: {:?}", stack_entry);
                current_stack.push(stack_entry.clone());
            }
        }
    }

    true
}

/// Checks whether a transaction to spend tokens in P2PKH has a valid signature
///
/// ### Arguments
///
/// * `script`  - Script to validate
fn tx_has_valid_p2pkh_sig(script: &Script) -> bool {
    let mut current_stack: Vec<StackEntry> = Vec::with_capacity(script.stack.len());

    for stack_entry in &script.stack {
        match stack_entry {
            StackEntry::Op(OpCodes::OP_DUP) => {
                println!("Duplicating last entry in script stack");
                let dup = current_stack[current_stack.len() - 1].clone();
                current_stack.push(dup);
            }
            StackEntry::Op(OpCodes::OP_HASH256) => {
                println!("256 bit hashing last stack entry");
                let last_entry = current_stack.pop().unwrap();
                let pub_key_bytes = Bytes::from(serialize(&last_entry).unwrap());
                let new_entry_raw = Sha3_256::digest(&pub_key_bytes).to_vec();
                let new_entry = hex::encode(new_entry_raw);

                current_stack.push(StackEntry::PubKeyHash(new_entry));
            }
            StackEntry::Op(OpCodes::OP_EQUALVERIFY) => {
                println!("Verifying p2pkh hash");
                let input_hash = current_stack.pop();
                let computed_hash = current_stack.pop();

                if input_hash != computed_hash {
                    error!("Hash not valid. Transaction input invalid");
                    return false;
                }
            }
            StackEntry::Op(OpCodes::OP_CHECKSIG) => {
                println!("Checking p2pkh signature");
                let pub_key: PublicKey = match current_stack.pop().unwrap() {
                    StackEntry::PubKey(pub_key) => pub_key,
                    _ => panic!("Public key not present to verify transaction"),
                };

                let sig: Signature = match current_stack.pop().unwrap() {
                    StackEntry::Signature(sig) => sig,
                    _ => panic!("Signature not present to verify transaction"),
                };

                let check_data = match current_stack.pop().unwrap() {
                    StackEntry::Bytes(check_data) => check_data,
                    _ => panic!("Check data bytes not present to verify transaction"),
                };

                if (!sign::verify_detached(&sig, check_data.as_bytes(), &pub_key)) {
                    error!("Signature not valid. Transaction input invalid");
                    return false;
                }
            }
            _ => {
                println!("Adding constant to stack: {:?}", stack_entry);
                current_stack.push(stack_entry.clone());
            }
        }
    }

    true
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::transaction_utils::construct_payment_tx_ins;

    /// Util function to create p2pkh TxIns
    fn create_multisig_tx_ins(tx_values: Vec<TxConstructor>, m: usize) -> Vec<TxIn> {
        let mut tx_ins = Vec::new();

        for entry in tx_values {
            let mut new_tx_in = TxIn::new();
            new_tx_in.script_signature = Script::multisig_validation(
                m,
                entry.pub_keys.len(),
                entry.t_hash.clone(),
                entry.signatures,
                entry.pub_keys,
            );
            new_tx_in.previous_out = Some(OutPoint::new(entry.t_hash, entry.prev_n));

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
                entry.t_hash.clone(),
                entry.pub_keys[0],
                entry.signatures[0],
            );
            new_tx_in.previous_out = Some(OutPoint::new(entry.t_hash, entry.prev_n));

            tx_ins.push(new_tx_in);
        }

        tx_ins
    }

    #[test]
    /// Checks that correct member multisig scripts are validated as such
    fn should_pass_member_multisig_valid() {
        let (pk, sk) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let signature = sign::sign_detached(t_hash.as_bytes(), &sk);

        let tx_const = TxConstructor {
            t_hash,
            prev_n: 0,
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = create_multisig_member_tx_ins(vec![tx_const]);

        assert!(member_multisig_is_valid(tx_ins[0].clone().script_signature));
    }

    #[test]
    /// Checks that incorrect member multisig scripts are validated as such
    fn should_fail_member_multisig_invalid() {
        let (_pk, sk) = sign::gen_keypair();
        let (pk, _sk) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let signature = sign::sign_detached(t_hash.as_bytes(), &sk);

        let tx_const = TxConstructor {
            t_hash,
            prev_n: 0,
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = create_multisig_member_tx_ins(vec![tx_const]);

        assert_eq!(
            member_multisig_is_valid(tx_ins[0].clone().script_signature),
            false
        );
    }

    #[test]
    /// Checks that correct p2pkh transaction signatures are validated as such
    fn should_pass_p2pkh_sig_valid() {
        let (pk, sk) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let signature = sign::sign_detached(t_hash.as_bytes(), &sk);

        let tx_const = TxConstructor {
            t_hash,
            prev_n: 0,
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = construct_payment_tx_ins(vec![tx_const]);

        assert!(tx_has_valid_p2pkh_sig(&tx_ins[0].script_signature));
    }

    #[test]
    /// Checks that invalid p2pkh transaction signatures are validated as such
    fn should_fail_p2pkh_sig_invalid() {
        let (_pk, sk) = sign::gen_keypair();
        let (second_pk, _s) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let signature = sign::sign_detached(t_hash.as_bytes(), &sk);

        let tx_const = TxConstructor {
            t_hash,
            prev_n: 0,
            signatures: vec![signature],
            pub_keys: vec![second_pk],
        };

        let tx_ins = construct_payment_tx_ins(vec![tx_const]);

        assert_eq!(tx_has_valid_p2pkh_sig(&tx_ins[0].script_signature), false);
    }

    #[test]
    /// Checks that correct multisig validation signatures are validated as such
    fn should_pass_multisig_validation_valid() {
        let (first_pk, first_sk) = sign::gen_keypair();
        let (second_pk, second_sk) = sign::gen_keypair();
        let (third_pk, third_sk) = sign::gen_keypair();
        let check_data = hex::encode(vec![0, 0, 0]);

        let m = 2;
        let first_sig = sign::sign_detached(check_data.as_bytes(), &first_sk);
        let second_sig = sign::sign_detached(check_data.as_bytes(), &second_sk);
        let third_sig = sign::sign_detached(check_data.as_bytes(), &third_sk);

        let tx_const = TxConstructor {
            t_hash: hex::encode(vec![0, 0, 0]),
            prev_n: 0,
            signatures: vec![first_sig, second_sig, third_sig],
            pub_keys: vec![first_pk, second_pk, third_pk],
        };

        let tx_ins = create_multisig_tx_ins(vec![tx_const], m);

        assert!(tx_has_valid_multsig_validation(&tx_ins[0].script_signature));
    }

    #[test]
    /// Ensures that enough pubkey-sigs are provided to complete the multisig
    fn should_pass_sig_pub_keypairs_for_multisig_valid() {
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
}
