#![allow(unused)]
use crate::constants::*;
use crate::crypto::sha3_256;
use crate::crypto::sign_ed25519::{
    PublicKey, Signature, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN,
};
use crate::script::interface_ops::*;
use crate::script::{OpCodes, StackEntry};
use crate::utils::error_utils::*;
use crate::utils::transaction_utils::{construct_address, construct_address_for};
use bincode::serialize;
use bytes::Bytes;
use hex::encode;
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

/// Stack for script execution
#[derive(Clone, Debug, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct Stack {
    pub main_stack: Vec<StackEntry>,
    pub alt_stack: Vec<StackEntry>,
}

impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}

impl Stack {
    /// Creates a new stack
    pub fn new() -> Self {
        Self {
            main_stack: Vec::with_capacity(MAX_STACK_SIZE as usize),
            alt_stack: Vec::with_capacity(MAX_STACK_SIZE as usize),
        }
    }

    /// Checks if the stack is valid
    pub fn is_valid(&self) -> bool {
        if self.main_stack.len() + self.alt_stack.len() > MAX_STACK_SIZE as usize {
            error_max_stack_size();
            return false;
        }
        true
    }

    /// Pops the top item from the stack
    pub fn pop(&mut self) -> Option<StackEntry> {
        self.main_stack.pop()
    }

    /// Returns the top item on the stack
    pub fn last(&self) -> Option<StackEntry> {
        self.main_stack.last().cloned()
    }

    /// Pushes a new entry onto the stack
    pub fn push(&mut self, stack_entry: StackEntry) -> bool {
        match stack_entry.clone() {
            StackEntry::Op(_) => {
                return false;
            }
            StackEntry::PubKeyHash(s) | StackEntry::Bytes(s) => {
                if s.len() > MAX_SCRIPT_ITEM_SIZE as usize {
                    return false;
                }
            }
            _ => (),
        }
        self.main_stack.push(stack_entry);
        true
    }
}

/// Stack for conditionals
#[derive(Clone, Debug, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConditionStack {
    pub size: usize,
    pub first_false_pos: Option<usize>,
}

impl Default for ConditionStack {
    fn default() -> Self {
        Self::new()
    }
}

impl ConditionStack {
    /// Creates a new stack for conditionals
    pub fn new() -> Self {
        Self {
            size: ZERO,
            first_false_pos: None,
        }
    }

    /// Checks if all values are true
    pub fn all_true(&self) -> bool {
        self.first_false_pos.is_none()
    }

    /// Checks if the condition stack is empty
    pub fn is_empty(&self) -> bool {
        self.size == ZERO
    }

    /// Pushes a new value onto the condition stack
    pub fn push(&mut self, cond: bool) {
        if self.first_false_pos.is_none() && !cond {
            self.first_false_pos = Some(self.size);
        }
        self.size += 1;
    }

    /// Pops the top value from the condition stack
    pub fn pop(&mut self) {
        assert!(self.size > ZERO, "Condition stack is empty");
        self.size -= ONE;
        if let Some(pos) = self.first_false_pos {
            if pos == self.size {
                self.first_false_pos.take();
            }
        }
    }

    /// Toggles the top value on the condition stack
    pub fn toggle(&mut self) {
        assert!(self.size > ZERO, "Condition stack is empty");
        match self.first_false_pos {
            Some(pos) => {
                if pos == self.size - ONE {
                    self.first_false_pos = None;
                }
            }
            _ => {
                self.first_false_pos = Some(self.size - ONE);
            }
        }
    }
}

/// Scripts are defined as a sequence of stack entries
/// NOTE: A tuple struct could probably work here as well
#[derive(Clone, Debug, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct Script {
    pub stack: Vec<StackEntry>,
}

impl Default for Script {
    fn default() -> Self {
        Self::new()
    }
}

impl Script {
    /// Constructs a new script
    pub fn new() -> Self {
        Self { stack: Vec::new() }
    }

    /// Checks if a script is valid
    pub fn is_valid(&self) -> bool {
        let mut len = ZERO; // script length in bytes
        let mut ops_count = ZERO; // number of opcodes in script
        for entry in &self.stack {
            match entry {
                StackEntry::Op(_) => {
                    len += ONE;
                    ops_count += ONE;
                }
                StackEntry::Signature(_) => len += ED25519_SIGNATURE_LEN,
                StackEntry::PubKey(_) => len += ED25519_PUBLIC_KEY_LEN,
                StackEntry::PubKeyHash(s) | StackEntry::Bytes(s) => len += s.len(),
                StackEntry::Num(_) => len += usize::BITS as usize / EIGHT,
            };
        }
        if len > MAX_SCRIPT_SIZE as usize {
            error_max_script_size();
            return false;
        }
        if ops_count > MAX_OPS_PER_SCRIPT as usize {
            error_max_ops_script();
            return false;
        }
        true
    }

    /// Interprets and executes a script
    pub fn interpret(&self) -> bool {
        if !self.is_valid() {
            return false;
        }
        let mut stack = Stack::new();
        let mut condition_stack = ConditionStack::new();
        let mut test_for_return = true;
        for stack_entry in &self.stack {
            match stack_entry {
                /*---- OPCODE ----*/
                // constants
                StackEntry::Op(OpCodes::OP_0) => test_for_return &= op_0(&mut stack),
                StackEntry::Op(OpCodes::OP_1) => test_for_return &= op_1(&mut stack),
                StackEntry::Op(OpCodes::OP_2) => test_for_return &= op_2(&mut stack),
                StackEntry::Op(OpCodes::OP_3) => test_for_return &= op_3(&mut stack),
                StackEntry::Op(OpCodes::OP_4) => test_for_return &= op_4(&mut stack),
                StackEntry::Op(OpCodes::OP_5) => test_for_return &= op_5(&mut stack),
                StackEntry::Op(OpCodes::OP_6) => test_for_return &= op_6(&mut stack),
                StackEntry::Op(OpCodes::OP_7) => test_for_return &= op_7(&mut stack),
                StackEntry::Op(OpCodes::OP_8) => test_for_return &= op_8(&mut stack),
                StackEntry::Op(OpCodes::OP_9) => test_for_return &= op_9(&mut stack),
                StackEntry::Op(OpCodes::OP_10) => test_for_return &= op_10(&mut stack),
                StackEntry::Op(OpCodes::OP_11) => test_for_return &= op_11(&mut stack),
                StackEntry::Op(OpCodes::OP_12) => test_for_return &= op_12(&mut stack),
                StackEntry::Op(OpCodes::OP_13) => test_for_return &= op_13(&mut stack),
                StackEntry::Op(OpCodes::OP_14) => test_for_return &= op_14(&mut stack),
                StackEntry::Op(OpCodes::OP_15) => test_for_return &= op_15(&mut stack),
                StackEntry::Op(OpCodes::OP_16) => test_for_return &= op_16(&mut stack),
                // flow control
                StackEntry::Op(OpCodes::OP_NOP) => test_for_return &= op_nop(&mut stack),
                StackEntry::Op(OpCodes::OP_VERIFY) => test_for_return &= op_verify(&mut stack),
                StackEntry::Op(OpCodes::OP_RETURN) => test_for_return &= op_return(&mut stack),
                // stack
                StackEntry::Op(OpCodes::OP_TOALTSTACK) => {
                    test_for_return &= op_toaltstack(&mut stack)
                }
                StackEntry::Op(OpCodes::OP_FROMALTSTACK) => {
                    test_for_return &= op_fromaltstack(&mut stack)
                }
                StackEntry::Op(OpCodes::OP_2DROP) => test_for_return &= op_2drop(&mut stack),
                StackEntry::Op(OpCodes::OP_2DUP) => test_for_return &= op_2dup(&mut stack),
                StackEntry::Op(OpCodes::OP_3DUP) => test_for_return &= op_3dup(&mut stack),
                StackEntry::Op(OpCodes::OP_2OVER) => test_for_return &= op_2over(&mut stack),
                StackEntry::Op(OpCodes::OP_2ROT) => test_for_return &= op_2rot(&mut stack),
                StackEntry::Op(OpCodes::OP_2SWAP) => test_for_return &= op_2swap(&mut stack),
                StackEntry::Op(OpCodes::OP_IFDUP) => test_for_return &= op_ifdup(&mut stack),
                StackEntry::Op(OpCodes::OP_DEPTH) => test_for_return &= op_depth(&mut stack),
                StackEntry::Op(OpCodes::OP_DROP) => test_for_return &= op_drop(&mut stack),
                StackEntry::Op(OpCodes::OP_DUP) => test_for_return &= op_dup(&mut stack),
                StackEntry::Op(OpCodes::OP_NIP) => test_for_return &= op_nip(&mut stack),
                StackEntry::Op(OpCodes::OP_OVER) => test_for_return &= op_over(&mut stack),
                StackEntry::Op(OpCodes::OP_PICK) => test_for_return &= op_pick(&mut stack),
                StackEntry::Op(OpCodes::OP_ROLL) => test_for_return &= op_roll(&mut stack),
                StackEntry::Op(OpCodes::OP_ROT) => test_for_return &= op_rot(&mut stack),
                StackEntry::Op(OpCodes::OP_SWAP) => test_for_return &= op_swap(&mut stack),
                StackEntry::Op(OpCodes::OP_TUCK) => test_for_return &= op_tuck(&mut stack),
                // splice
                StackEntry::Op(OpCodes::OP_SIZE) => test_for_return &= op_size(&mut stack),
                // bitwise logic
                StackEntry::Op(OpCodes::OP_EQUAL) => test_for_return &= op_equal(&mut stack),
                StackEntry::Op(OpCodes::OP_EQUALVERIFY) => {
                    test_for_return &= op_equalverify(&mut stack)
                }
                // arithmetic
                StackEntry::Op(OpCodes::OP_1ADD) => test_for_return &= op_1add(&mut stack),
                StackEntry::Op(OpCodes::OP_1SUB) => test_for_return &= op_1sub(&mut stack),
                StackEntry::Op(OpCodes::OP_NOT) => test_for_return &= op_not(&mut stack),
                StackEntry::Op(OpCodes::OP_0NOTEQUAL) => {
                    test_for_return &= op_0notequal(&mut stack)
                }
                StackEntry::Op(OpCodes::OP_ADD) => test_for_return &= op_add(&mut stack),
                StackEntry::Op(OpCodes::OP_SUB) => test_for_return &= op_sub(&mut stack),
                StackEntry::Op(OpCodes::OP_BOOLAND) => test_for_return &= op_booland(&mut stack),
                StackEntry::Op(OpCodes::OP_BOOLOR) => test_for_return &= op_boolor(&mut stack),
                StackEntry::Op(OpCodes::OP_NUMEQUAL) => test_for_return &= op_numequal(&mut stack),
                StackEntry::Op(OpCodes::OP_NUMEQUALVERIFY) => {
                    test_for_return &= op_numequalverify(&mut stack)
                }
                StackEntry::Op(OpCodes::OP_NUMNOTEQUAL) => {
                    test_for_return &= op_numnotequal(&mut stack)
                }
                StackEntry::Op(OpCodes::OP_LESSTHAN) => test_for_return &= op_lessthan(&mut stack),
                StackEntry::Op(OpCodes::OP_GREATERTHAN) => {
                    test_for_return &= op_greaterthan(&mut stack)
                }
                StackEntry::Op(OpCodes::OP_LESSTHANOREQUAL) => {
                    test_for_return &= op_lessthanorequal(&mut stack)
                }
                StackEntry::Op(OpCodes::OP_GREATERTHANOREQUAL) => {
                    test_for_return &= op_greaterthanorequal(&mut stack)
                }
                StackEntry::Op(OpCodes::OP_MIN) => test_for_return &= op_min(&mut stack),
                StackEntry::Op(OpCodes::OP_MAX) => test_for_return &= op_max(&mut stack),
                StackEntry::Op(OpCodes::OP_WITHIN) => test_for_return &= op_within(&mut stack),
                StackEntry::Op(OpCodes::OP_CREATE) => (),
                // crypto
                StackEntry::Op(OpCodes::OP_SHA3) => test_for_return &= op_sha3(&mut stack),
                StackEntry::Op(OpCodes::OP_HASH256) => test_for_return &= op_hash256(&mut stack),
                StackEntry::Op(OpCodes::OP_HASH256_V0) => {
                    test_for_return &= op_hash256_v0(&mut stack)
                }
                StackEntry::Op(OpCodes::OP_HASH256_TEMP) => {
                    test_for_return &= op_hash256_temp(&mut stack)
                }
                StackEntry::Op(OpCodes::OP_CHECKSIG) => test_for_return &= op_checksig(&mut stack),
                StackEntry::Op(OpCodes::OP_CHECKSIGVERIFY) => {
                    test_for_return &= op_checksigverify(&mut stack)
                }
                StackEntry::Op(OpCodes::OP_CHECKMULTISIG) => {
                    test_for_return &= op_checkmultisig(&mut stack)
                }
                StackEntry::Op(OpCodes::OP_CHECKMULTISIGVERIFY) => {
                    test_for_return &= op_checkmultisigverify(&mut stack)
                }
                /*---- SIGNATURE | PUBKEY | PUBKEYHASH | NUM | BYTES ----*/
                StackEntry::Signature(_)
                | StackEntry::PubKey(_)
                | StackEntry::PubKeyHash(_)
                | StackEntry::Num(_)
                | StackEntry::Bytes(_) => test_for_return &= stack.push(stack_entry.clone()),
                /*---- INVALID OPCODE ----*/
                _ => {
                    error_invalid_opcode();
                    return false;
                }
            }
            if !test_for_return || !stack.is_valid() {
                return false;
            }
        }
        test_for_return && stack.last() != Some(StackEntry::Num(ZERO))
    }

    /// Constructs a new script for coinbase
    ///
    /// ### Arguments
    ///
    /// * `block_number`  - The block time to push
    pub fn new_for_coinbase(block_number: u64) -> Self {
        Self {
            stack: vec![StackEntry::Num(block_number as usize)],
        }
    }

    /// Constructs a new script for an asset creation
    ///
    /// ### Arguments
    ///
    /// * `block_number`    - The block time
    /// * `asset_hash`      - The hash of the asset
    /// * `signature`       - The signature of the asset contents
    /// * `pub_key`         - The public key used in creating the signed content
    pub fn new_create_asset(
        block_number: u64,
        asset_hash: String,
        signature: Signature,
        pub_key: PublicKey,
    ) -> Self {
        let mut new_script = Script::new();

        new_script.stack.push(StackEntry::Op(OpCodes::OP_CREATE));
        new_script
            .stack
            .push(StackEntry::Num(block_number as usize));
        new_script.stack.push(StackEntry::Op(OpCodes::OP_DROP));
        new_script.stack.push(StackEntry::Bytes(asset_hash));
        new_script.stack.push(StackEntry::Signature(signature));
        new_script.stack.push(StackEntry::PubKey(pub_key));
        new_script.stack.push(StackEntry::Op(OpCodes::OP_CHECKSIG));

        new_script
    }

    /// Constructs a pay to public key hash script
    ///
    /// ### Arguments
    ///
    /// * `check_data`  - Check data to provide signature
    /// * `signature`   - Signature of check data
    /// * `pub_key`     - Public key of the payer
    pub fn pay2pkh(
        check_data: String,
        signature: Signature,
        pub_key: PublicKey,
        address_version: Option<u64>,
    ) -> Self {
        let mut new_script = Script::new();
        let pub_key_stack_entry = StackEntry::PubKey(pub_key);
        let new_key = construct_address_for(&pub_key, address_version);

        let op_hash_256 = match address_version {
            Some(NETWORK_VERSION_V0) => OpCodes::OP_HASH256_V0,
            Some(NETWORK_VERSION_TEMP) => OpCodes::OP_HASH256_TEMP,
            _ => OpCodes::OP_HASH256,
        };

        new_script.stack.push(StackEntry::Bytes(check_data));
        new_script.stack.push(StackEntry::Signature(signature));
        new_script.stack.push(pub_key_stack_entry);
        new_script.stack.push(StackEntry::Op(OpCodes::OP_DUP));
        new_script.stack.push(StackEntry::Op(op_hash_256));
        new_script.stack.push(StackEntry::PubKeyHash(new_key));
        new_script
            .stack
            .push(StackEntry::Op(OpCodes::OP_EQUALVERIFY));
        new_script.stack.push(StackEntry::Op(OpCodes::OP_CHECKSIG));

        new_script
    }

    /// Constructs one part of a multiparty transaction script
    ///
    /// ### Arguments
    ///
    /// * `check_data`  - Data to be signed for verification
    /// * `pub_key`     - Public key of this party
    /// * `signature`   - Signature of this party
    pub fn member_multisig(check_data: String, pub_key: PublicKey, signature: Signature) -> Self {
        let mut new_script = Script::new();

        new_script.stack.push(StackEntry::Bytes(check_data));
        new_script.stack.push(StackEntry::Signature(signature));
        new_script.stack.push(StackEntry::PubKey(pub_key));
        new_script.stack.push(StackEntry::Op(OpCodes::OP_CHECKSIG));

        new_script
    }

    /// Constructs a multisig locking script
    ///
    /// ### Arguments
    ///
    /// * `m`           - Number of signatures required to unlock
    /// * `n`           - Number of valid signatures total
    /// * `check_data`  - Data to have checked against signatures
    /// * `pub_keys`    - The constituent public keys
    pub fn multisig_lock(m: usize, n: usize, check_data: String, pub_keys: Vec<PublicKey>) -> Self {
        let mut new_script = Script::new();

        if n > pub_keys.len() || m > pub_keys.len() {
            error!("The number of keys required for multisig is greater than the number of keys provided");
        } else if m > n {
            error!("Multisig requiring more keys to lock than the total number of keys");
        } else {
            let mut new_stack = Vec::with_capacity(3 + pub_keys.len());

            new_stack.push(StackEntry::Bytes(check_data));
            new_stack.push(StackEntry::Num(m));
            new_stack.append(&mut pub_keys.iter().map(|e| StackEntry::PubKey(*e)).collect());
            new_stack.push(StackEntry::Num(n));
            new_stack.push(StackEntry::Op(OpCodes::OP_CHECKMULTISIG));

            new_script.stack = new_stack;
        }

        new_script
    }

    /// Constructs a multisig unlocking script
    ///
    /// ### Arguments
    ///
    /// * `check_data`  - Data to have signed
    /// * `signatures`  - Signatures to unlock with
    pub fn multisig_unlock(check_data: String, signatures: Vec<Signature>) -> Self {
        let mut new_script = Script::new();
        new_script.stack = vec![StackEntry::Bytes(check_data)];
        new_script.stack.append(
            &mut signatures
                .iter()
                .map(|e| StackEntry::Signature(*e))
                .collect(),
        );

        new_script
    }

    /// Constructs a multisig validation script
    ///
    /// ### Arguments
    ///
    /// * `m`           - Number of signatures to assure validity
    /// * `n`           - Number of public keys that are valid
    /// * `signatures`  - Signatures to validate
    /// * `pub_keys`    - Public keys to validate
    pub fn multisig_validation(
        m: usize,
        n: usize,
        check_data: String,
        signatures: Vec<Signature>,
        pub_keys: Vec<PublicKey>,
    ) -> Self {
        let mut new_script = Script::new();

        if n > pub_keys.len() || m > pub_keys.len() {
            error!("The number of keys required for multisig is greater than the number of keys provided");
        } else if m > n {
            error!("Multisig requiring more keys to lock than the total number of keys");
        } else {
            new_script.stack = vec![StackEntry::Bytes(check_data)];

            // Handle signatures
            new_script.stack.append(
                &mut signatures
                    .iter()
                    .map(|e| StackEntry::Signature(*e))
                    .collect(),
            );

            new_script.stack.push(StackEntry::Num(m));

            // Handle pub keys
            new_script
                .stack
                .append(&mut pub_keys.iter().map(|e| StackEntry::PubKey(*e)).collect());
            new_script.stack.push(StackEntry::Num(n));
            new_script
                .stack
                .push(StackEntry::Op(OpCodes::OP_CHECKMULTISIG));
        }

        new_script
    }
}
