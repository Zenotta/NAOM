#![allow(unused)]
use crate::constants::*;
use crate::crypto::sha3_256;
use crate::crypto::sign_ed25519 as sign;
use crate::crypto::sign_ed25519::{PublicKey, Signature};
use crate::primitives::asset::{Asset, TokenAmount};
use crate::primitives::transaction::*;
use crate::script::lang::{Script, Stack};
use crate::script::{OpCodes, StackEntry};
use crate::utils::error_utils::*;
use crate::utils::transaction_utils::{
    construct_address, construct_address_temp, construct_address_v0,
};
use bincode::serialize;
use bytes::Bytes;
use hex::encode;
use std::collections::BTreeMap;
use tracing::{debug, error, info, trace};

/*---- CONSTANTS OPS ----*/

/// OP_0: Pushes number ZERO onto the stack
///
/// Example: OP_0([]) -> [0]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_0(stack: &mut Stack) -> bool {
    let (op, desc) = (OP0, OP0_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(ZERO));
    true
}

/// OP_1: Pushes number ONE onto the stack
///
/// Example: OP_1([]) -> [1]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_1(stack: &mut Stack) -> bool {
    let (op, desc) = (OP1, OP1_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(ONE));
    true
}

/// OP_2: Pushes number TWO onto the stack
///
/// Example: OP_2([]) -> [2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_2(stack: &mut Stack) -> bool {
    let (op, desc) = (OP2, OP2_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(TWO));
    true
}

/// OP_3: Pushes number THREE onto the stack
///
/// Example: OP_3([]) -> [3]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_3(stack: &mut Stack) -> bool {
    let (op, desc) = (OP3, OP3_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(THREE));
    true
}

/// OP_4: Pushes number FOUR onto the stack
///
/// Example: OP_4([]) -> [4]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_4(stack: &mut Stack) -> bool {
    let (op, desc) = (OP4, OP4_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(FOUR));
    true
}

/// OP_5: Pushes number FIVE onto the stack
///
/// Example: OP_5([]) -> [5]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_5(stack: &mut Stack) -> bool {
    let (op, desc) = (OP5, OP5_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(FIVE));
    true
}

/// OP_6: Pushes number SIX onto the stack
///
/// Example: OP_6([]) -> [6]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_6(stack: &mut Stack) -> bool {
    let (op, desc) = (OP6, OP6_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(SIX));
    true
}

/// OP_7: Pushes number SEVEN onto the stack
///
/// Example: OP_7([]) -> [7]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_7(stack: &mut Stack) -> bool {
    let (op, desc) = (OP7, OP7_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(SEVEN));
    true
}

/// OP_8: Pushes number EIGHT onto the stack
///
/// Example: OP_8([]) -> [8]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_8(stack: &mut Stack) -> bool {
    let (op, desc) = (OP8, OP8_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(EIGHT));
    true
}

/// OP_9: Pushes number NINE onto the stack
///
/// Example: OP_9([]) -> [9]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_9(stack: &mut Stack) -> bool {
    let (op, desc) = (OP9, OP9_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(NINE));
    true
}

/// OP_10: Pushes number TEN onto the stack
///
/// Example: OP_10([]) -> [10]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_10(stack: &mut Stack) -> bool {
    let (op, desc) = (OP10, OP10_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(TEN));
    true
}

/// OP_11: Pushes number ELEVEN onto the stack
///
/// Example: OP_11([]) -> [11]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_11(stack: &mut Stack) -> bool {
    let (op, desc) = (OP11, OP11_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(ELEVEN));
    true
}

/// OP_12: Pushes number TWELVE onto the stack
///
/// Example: OP_12([]) -> [12]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_12(stack: &mut Stack) -> bool {
    let (op, desc) = (OP12, OP12_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(TWELVE));
    true
}

/// OP_13: Pushes number THIRTEEN onto the stack
///
/// Example: OP_13([]) -> [13]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_13(stack: &mut Stack) -> bool {
    let (op, desc) = (OP13, OP13_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(THIRTEEN));
    true
}

/// OP_14: Pushes number FOURTEEN onto the stack
///
/// Example: OP_14([]) -> [14]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_14(stack: &mut Stack) -> bool {
    let (op, desc) = (OP14, OP14_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(FOURTEEN));
    true
}

/// OP_15: Pushes number FIFTEEN onto the stack
///
/// Example: OP_15([]) -> [15]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_15(stack: &mut Stack) -> bool {
    let (op, desc) = (OP15, OP15_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(FIFTEEN));
    true
}

/// OP_16: Pushes number SIXTEEN onto the stack
///
/// Example: OP_16([]) -> [16]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_16(stack: &mut Stack) -> bool {
    let (op, desc) = (OP16, OP16_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(SIXTEEN));
    true
}

/*---- FLOW CONTROL OPS ----*/

/// OP_NOP: Does nothing
///
/// Example: OP_NOP([x]) -> [x]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_nop(stack: &mut Stack) -> bool {
    let (op, desc) = (OPNOP, OPNOP_DESC);
    trace(op, desc);
    true
}

/// OP_IF: Checks if the top item on the stack is not ZERO and executes the next block of instructions
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_if(stack: &mut Stack) -> bool {
    let (op, desc) = (OPIF, OPIF_DESC);
    trace(op, desc);
    true
}

/// OP_NOTIF: Checks if the top item on the stack is ZERO and executes the next block of instructions
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_notif(stack: &mut Stack) -> bool {
    let (op, desc) = (OPNOTIF, OPNOTIF_DESC);
    trace(op, desc);
    true
}

/// OP_ELSE: Executes the next block of instructions if the previous OP_IF or OP_NOTIF was not executed
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_else(stack: &mut Stack) -> bool {
    let (op, desc) = (OPELSE, OPELSE_DESC);
    trace(op, desc);
    true
}

/// OP_ ENDIF: Ends an OP_IF or OP_NOTIF block
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_endif(stack: &mut Stack) -> bool {
    let (op, desc) = (OPENDIF, OPENDIF_DESC);
    trace(op, desc);
    true
}

/// OP_VERIFY: Removes the top item from the stack and ends execution with an error if it is ZERO
///
/// Example: OP_VERIFY([x]) -> []   if x != 0
///          OP_VERIFY([x]) -> fail if x == 0
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_verify(stack: &mut Stack) -> bool {
    let (op, desc) = (OPVERIFY, OPVERIFY_DESC);
    trace(op, desc);
    match stack.pop() {
        Some(x) => {
            if x == StackEntry::Num(ZERO) {
                error_verify(op);
                return false;
            }
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    true
}

/// OP_RETURN: Ends execution with an error
///
/// Example: OP_RETURN([x]) -> fail
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_return(stack: &mut Stack) -> bool {
    let (op, desc) = (OPRETURN, OPRETURN_DESC);
    trace(op, desc);
    error_return(op);
    false
}

/*---- STACK OPS ----*/

/// OP_TOALTSTACK: Moves the top item from the main stack to the top of the alt stack
///                
///
/// Example: OP_TOALTSTACK([x], []) -> [], [x]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_toaltstack(stack: &mut Stack) -> bool {
    let (op, desc) = (OPTOALTSTACK, OPTOALTSTACK_DESC);
    trace(op, desc);
    match stack.pop() {
        Some(x) => stack.alt_stack.push(x),
        _ => {
            error_num_items(op);
            return false;
        }
    };
    true
}

/// OP_FROMALTSTACK: Moves the top item from the alt stack to the top of the main stack
///                  
/// Example: OP_FROMALTSTACK([], [x]) -> [x], []
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_fromaltstack(stack: &mut Stack) -> bool {
    let (op, desc) = (OPFROMALTSTACK, OPFROMALTSTACK_DESC);
    trace(op, desc);
    match stack.alt_stack.pop() {
        Some(x) => stack.push(x),
        _ => {
            error_num_items(op);
            return false;
        }
    };
    true
}

/// OP_2DROP: Removes the top two items from the stack
///
/// Example: OP_2DROP([x1, x2]) -> []
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_2drop(stack: &mut Stack) -> bool {
    let (op, desc) = (OP2DROP, OP2DROP_DESC);
    trace(op, desc);
    let len = stack.main_stack.len();
    if len < TWO {
        error_num_items(op);
        return false;
    }
    stack.main_stack.drain(len - TWO..);
    true
}

/// OP_2DUP: Duplicates the top two items on the stack
///
/// Example: OP_2DUP([x1, x2]) -> [x1, x2, x1, x2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_2dup(stack: &mut Stack) -> bool {
    let (op, desc) = (OP2DUP, OP2DUP_DESC);
    trace(op, desc);
    let len = stack.main_stack.len();
    if len < TWO {
        error_num_items(op);
        return false;
    }
    let last_two = stack.main_stack[len - TWO..].to_vec();
    stack.main_stack.extend_from_slice(&last_two);
    true
}

/// OP_3DUP: Duplicates the top three items on the stack
///
/// Example: OP_3DUP([x1, x2, x3]) -> [x1, x2, x3, x1, x2, x3]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_3dup(stack: &mut Stack) -> bool {
    let (op, desc) = (OP3DUP, OP3DUP_DESC);
    trace(op, desc);
    let len = stack.main_stack.len();
    if len < THREE {
        error_num_items(op);
        return false;
    }
    let last_three = stack.main_stack[len - THREE..].to_vec();
    stack.main_stack.extend_from_slice(&last_three);
    true
}

/// OP_2OVER: Copies the second-to-top pair of items to the top of the stack
///           
/// Example: OP_2OVER([x1, x2, x3, x4]) -> [x1, x2, x3, x4, x1, x2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_2over(stack: &mut Stack) -> bool {
    let (op, desc) = (OP2OVER, OP2OVER_DESC);
    trace(op, desc);
    let len = stack.main_stack.len();
    if len < FOUR {
        error_num_items(op);
        return false;
    }
    let items = stack.main_stack[len - FOUR..len - TWO].to_vec();
    stack.main_stack.extend_from_slice(&items);
    true
}

/// OP_2ROT: Moves the third-to-top pair of items to the top of the stack
///          
/// Example: OP_2ROT([x1, x2, x3, x4, x5, x6]) -> [x3, x4, x5, x6, x1, x2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_2rot(stack: &mut Stack) -> bool {
    let (op, desc) = (OP2ROT, OP2ROT_DESC);
    trace(op, desc);
    let len = stack.main_stack.len();
    if len < SIX {
        error_num_items(op);
        return false;
    }
    let items = stack.main_stack[len - SIX..len - FOUR].to_vec();
    stack.main_stack.drain(len - SIX..len - FOUR);
    stack.main_stack.extend_from_slice(&items);
    true
}

/// OP_2SWAP: Swaps the top two pairs of items on the stack
///
/// Example: OP_2SWAP([x1, x2, x3, x4]) -> [x3, x4, x1, x2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_2swap(stack: &mut Stack) -> bool {
    let (op, desc) = (OP2SWAP, OP2SWAP_DESC);
    trace(op, desc);
    let len = stack.main_stack.len();
    if len < FOUR {
        error_num_items(op);
        return false;
    }
    stack.main_stack.swap(len - FOUR, len - TWO);
    stack.main_stack.swap(len - THREE, len - ONE);
    true
}

/// OP_IFDUP: Duplicates the top item on the stack if it is not ZERO
///           
/// Example: OP_IFDUP([x]) -> [x, x] if x != 0
///          OP_IFDUP([x]) -> [x]    if x == 0
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_ifdup(stack: &mut Stack) -> bool {
    let (op, desc) = (OPIFDUP, OPIFDUP_DESC);
    trace(op, desc);
    match stack.last() {
        Some(x) => {
            if x != StackEntry::Num(ZERO) {
                stack.push(x);
            }
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    true
}

/// OP_DEPTH: Pushes the stack size onto the stack
///
/// Example: OP_DEPTH([x1, x2, x3, x4]) -> [x1, x2, x3, x4, 4]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_depth(stack: &mut Stack) -> bool {
    let (op, desc) = (OPDEPTH, OPDEPTH_DESC);
    trace(op, desc);
    stack.push(StackEntry::Num(stack.main_stack.len()));
    true
}

/// OP_DROP: Removes the top item from the stack
///
/// Example: OP_DROP([x]) -> []
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_drop(stack: &mut Stack) -> bool {
    let (op, desc) = (OPDROP, OPDROP_DESC);
    trace(op, desc);
    match stack.pop() {
        Some(x) => (),
        _ => {
            error_num_items(op);
            return false;
        }
    };
    true
}

/// OP_DUP: Duplicates the top item on the stack
///
/// Example: OP_DUP([x]) -> [x, x]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_dup(stack: &mut Stack) -> bool {
    let (op, desc) = (OPDUP, OPDUP_DESC);
    trace(op, desc);
    match stack.last() {
        Some(x) => stack.push(x),
        _ => {
            error_num_items(op);
            return false;
        }
    };
    true
}

/// OP_NIP: Removes the second-to-top item from the stack
///
/// Example: OP_NIP([x1, x2]) -> [x2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_nip(stack: &mut Stack) -> bool {
    let (op, desc) = (OPNIP, OPNIP_DESC);
    trace(op, desc);
    let len = stack.main_stack.len();
    if len < TWO {
        error_num_items(op);
        return false;
    }
    stack.main_stack.remove(len - TWO);
    true
}

/// OP_OVER: Copies the second-to-top item to the top of the stack
///
/// Example: OP_OVER([x1, x2]) -> [x1, x2, x1]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_over(stack: &mut Stack) -> bool {
    let (op, desc) = (OPOVER, OPOVER_DESC);
    trace(op, desc);
    let len = stack.main_stack.len();
    if len < TWO {
        error_num_items(op);
        return false;
    }
    let x1 = stack.main_stack[len - TWO].clone();
    stack.push(x1);
    true
}

/// OP_PICK: Copies the (n+1)th-to-top item to the top of the stack, where n is the top item on the stack
///
/// Example: OP_PICK([x, x2, x1, x0, 3]) -> [x, x2, x1, x0, x]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_pick(stack: &mut Stack) -> bool {
    let (op, desc) = (OPPICK, OPPICK_DESC);
    trace(op, desc);
    let n = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let len = stack.main_stack.len();
    if n >= len {
        error_item_index(op);
        return false;
    }
    let x = stack.main_stack[len - ONE - n].clone();
    stack.push(x);
    true
}

/// OP_ROLL: Moves the (n+1)th-to-top item to the top of the stack, where n is the top item on the stack
///
/// Example: OP_ROLL([x, x2, x1, x0, 3]) -> [x2, x1, x0, x]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_roll(stack: &mut Stack) -> bool {
    let (op, desc) = (OPROLL, OPROLL_DESC);
    trace(op, desc);
    let n = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let len = stack.main_stack.len();
    if n >= len {
        error_item_index(op);
        return false;
    }
    let x = stack.main_stack[len - ONE - n].clone();
    stack.main_stack.remove(len - ONE - n);
    stack.push(x);
    true
}

/// OP_ROT: Moves the third-to-top item to the top of the stack
///
/// Example: OP_ROT([x1, x2, x3]) -> [x2, x3, x1]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_rot(stack: &mut Stack) -> bool {
    let (op, desc) = (OPROT, OPROT_DESC);
    trace(op, desc);
    let len = stack.main_stack.len();
    if len < THREE {
        error_num_items(op);
        return false;
    }
    stack.main_stack.swap(len - THREE, len - TWO);
    stack.main_stack.swap(len - TWO, len - ONE);
    true
}

/// OP_SWAP: Swaps the top two items on the stack
///
/// Example: OP_SWAP([x1, x2]) -> [x2, x1]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_swap(stack: &mut Stack) -> bool {
    let (op, desc) = (OPSWAP, OPSWAP_DESC);
    trace(op, desc);
    let len = stack.main_stack.len();
    if len < TWO {
        error_num_items(op);
        return false;
    }
    stack.main_stack.swap(len - TWO, len - ONE);
    true
}

/// OP_TUCK: Copies the top item behind the second-to-top item on the stack
///
/// Example: OP_TUCK([x1, x2]) -> [x2, x1, x2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_tuck(stack: &mut Stack) -> bool {
    let (op, desc) = (OPTUCK, OPTUCK_DESC);
    trace(op, desc);
    let len = stack.main_stack.len();
    if len < TWO {
        error_num_items(op);
        return false;
    }
    let x2 = stack.main_stack[len - ONE].clone();
    stack.main_stack.insert(len - TWO, x2);
    true
}

/*---- SPLICE OPS ----*/

/// OP_CAT: Concatenates the two strings on top of the stack
///
/// Example: OP_CAT([s1, s2]) -> [s1s2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_cat(stack: &mut Stack) -> bool {
    let (op, desc) = (OPCAT, OPCAT_DESC);
    trace(op, desc);
    let s2 = match stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let s1 = match stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if s1.len() + s2.len() > MAX_SCRIPT_ITEM_SIZE as usize {
        error_item_size(op);
        return false;
    }
    let cat = [s1, s2].join("");
    stack.push(StackEntry::Bytes(cat))
}

/// OP_SUBSTR: Extracts a substring from the third-to-top item on the stack
///
/// Example: OP_SUBSTR([s, n1, n2]) -> [s[n1..n1+n2-1]]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_substr(stack: &mut Stack) -> bool {
    let (op, desc) = (OPSUBSTR, OPSUBSTR_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let s = match stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 >= s.len() {
        error_item_index(op);
        return false;
    }
    if n2 > s.len() {
        error_item_index(op);
        return false;
    }
    if n1 + n2 > s.len() {
        error_item_index(op);
        return false;
    }
    let substr = s[n1..n1 + n2].to_string();
    stack.push(StackEntry::Bytes(substr))
}

/// OP_LEFT: Extracts a left substring from the second-to-top item on the stack
///
/// Example: OP_LEFT([s, n]) -> [s[..n-1]] if n < len(s)
///          OP_LEFT([s, n]) -> [s]        if n >= len(s)
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_left(stack: &mut Stack) -> bool {
    let (op, desc) = (OPLEFT, OPLEFT_DESC);
    trace(op, desc);
    let n = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let s = match stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n >= s.len() {
        stack.push(StackEntry::Bytes(s))
    } else {
        let left = s[..n].to_string();
        stack.push(StackEntry::Bytes(left))
    }
}

/// OP_RIGHT: Extracts a right substring from the second-to-top item on the stack
///
/// Example: OP_RIGHT([s, n]) -> [s[n..]] if n < len(s)
///          OP_RIGHT([s, n]) -> [""]     if n >= len(s)
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_right(stack: &mut Stack) -> bool {
    let (op, desc) = (OPRIGHT, OPRIGHT_DESC);
    trace(op, desc);
    let n = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let s = match stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n >= s.len() {
        stack.push(StackEntry::Bytes("".to_string()))
    } else {
        let right = s[n..].to_string();
        stack.push(StackEntry::Bytes(right))
    }
}

/// OP_SIZE: Computes the size in bytes of the string on top of the stack
///
/// Example: OP_SIZE([s]) -> [s, len(s)]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_size(stack: &mut Stack) -> bool {
    let (op, desc) = (OPSIZE, OPSIZE_DESC);
    trace(op, desc);
    let s = match stack.last() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    stack.push(StackEntry::Num(s.len()))
}

/*---- BITWISE LOGIC OPS ----*/

/// OP_INVERT: Computes bitwise NOT of the number on top of the stack
///
/// Example: OP_INVERT([n]) -> [!n]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_invert(stack: &mut Stack) -> bool {
    let (op, desc) = (OPINVERT, OPINVERT_DESC);
    trace(op, desc);
    let n = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    stack.push(StackEntry::Num(!n))
}

/// OP_AND: Computes bitwise AND between the two numbers on top of the stack
///
/// Example: OP_AND([n1, n2]) -> [n1&n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_and(stack: &mut Stack) -> bool {
    let (op, desc) = (OPAND, OPAND_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    stack.push(StackEntry::Num(n1 & n2))
}

/// OP_OR: Computes bitwise OR between the two numbers on top of the stack
///
/// Example: OP_OR([n1, n2]) -> [n1|n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_or(stack: &mut Stack) -> bool {
    let (op, desc) = (OPOR, OPOR_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    stack.push(StackEntry::Num(n1 | n2))
}

/// OP_XOR: Computes bitwise XOR between the two numbers on top of the stack
///
/// Example: OP_XOR([n1, n2]) -> [n1^n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_xor(stack: &mut Stack) -> bool {
    let (op, desc) = (OPXOR, OPXOR_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    stack.push(StackEntry::Num(n1 ^ n2))
}

/// OP_EQUAL: Substitutes the top two items on the stack with ONE if they are equal, with ZERO otherwise.
///
/// Example: OP_EQUAL([x1, x2]) -> [1] if x1 == x2
///          OP_EQUAL([x1, x2]) -> [0] if x1 != x2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_equal(stack: &mut Stack) -> bool {
    let (op, desc) = (OPEQUAL, OPEQUAL_DESC);
    trace(op, desc);
    let x2 = match stack.pop() {
        Some(x) => x,
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let x1 = match stack.pop() {
        Some(x) => x,
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if x1 == x2 {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_EQUALVERIFY: Computes OP_EQUAL and OP_VERIFY in sequence
///
/// Example: OP_EQUALVERIFY([x1, x2]) -> []   if x1 == x2
///          OP_EQUALVERIFY([x1, x2]) -> fail if x1 != x2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_equalverify(stack: &mut Stack) -> bool {
    let (op, desc) = (OPEQUALVERIFY, OPEQUALVERIFY_DESC);
    trace(op, desc);
    let x2 = match stack.pop() {
        Some(x) => x,
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let x1 = match stack.pop() {
        Some(x) => x,
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if x1 != x2 {
        error_not_equal_items(op);
        return false;
    }
    true
}

/*---- ARITHMETIC OPS ----*/

/// OP_1ADD: Adds ONE to the number on top of the stack
///
/// Example: OP_1ADD([n]) -> [n+1]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_1add(stack: &mut Stack) -> bool {
    let (op, desc) = (OP1ADD, OP1ADD_DESC);
    trace(op, desc);
    let n = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n.checked_add(ONE) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => {
            error_overflow(op);
            false
        }
    }
}

/// OP_1SUB: Subtracts ONE from the number on top of the stack.
///
/// Example: OP_1SUB([n]) -> [n-1]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_1sub(stack: &mut Stack) -> bool {
    let (op, desc) = (OP1SUB, OP1SUB_DESC);
    trace(op, desc);
    let n = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n.checked_sub(ONE) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => {
            error_overflow(op);
            false
        }
    }
}

/// OP_2MUL: Multiplies by TWO the number on top of the stack
///
/// Example: OP_2MUL([n]) -> [n*2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_2mul(stack: &mut Stack) -> bool {
    let (op, desc) = (OP2MUL, OP2MUL_DESC);
    trace(op, desc);
    let n = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n.checked_mul(TWO) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => {
            error_overflow(op);
            false
        }
    }
}

/// OP_2DIV: Divides by TWO the number on top of the stack
///
/// Example: OP_2DIV([n]) -> [n/2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_2div(stack: &mut Stack) -> bool {
    let (op, desc) = (OP2DIV, OP2DIV_DESC);
    trace(op, desc);
    let n = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    stack.push(StackEntry::Num(n / TWO))
}

/// OP_NOT: Substitutes the number on top of the stack with ONE if it is equal to ZERO, with ZERO otherwise
///
/// Example: OP_NOT([n]) -> [1] if n == 0
///          OP_NOT([n]) -> [0] if n != 0
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_not(stack: &mut Stack) -> bool {
    let (op, desc) = (OPNOT, OPNOT_DESC);
    trace(op, desc);
    let n = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n == ZERO {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_0NOTEQUAL: Substitutes the number on top of the stack with ONE if it is not equal to ZERO, with ZERO otherwise
///
/// Example: OP_0NOTEQUAL([n]) -> [1] if n != 0
///          OP_0NOTEQUAL([n]) -> [0] if n == 0
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_0notequal(stack: &mut Stack) -> bool {
    let (op, desc) = (OP0NOTEQUAL, OP0NOTEQUAL_DESC);
    trace(op, desc);
    let n = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n != ZERO {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_ADD: Adds the two numbers on top of the stack
///
/// Example: OP_ADD([n1, n2]) -> [n1+n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_add(stack: &mut Stack) -> bool {
    let (op, desc) = (OPADD, OPADD_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n1.checked_add(n2) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => {
            error_overflow(op);
            false
        }
    }
}

/// OP_SUB: Subtracts the number on top of the stack from the second-to-top number on the stack
///
/// Example: OP_SUB([n1, n2]) -> [n1-n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_sub(stack: &mut Stack) -> bool {
    let (op, desc) = (OPSUB, OPSUB_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n1.checked_sub(n2) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => {
            error_overflow(op);
            false
        }
    }
}

/// OP_MUL: Multiplies the second-to-top number by the number on top of the stack
///
/// Example: OP_MUL([n1, n2]) -> [n1*n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_mul(stack: &mut Stack) -> bool {
    let (op, desc) = (OPMUL, OPMUL_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n1.checked_mul(n2) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => {
            error_overflow(op);
            false
        }
    }
}

/// OP_DIV: Divides the second-to-top number by the number on top of the stack
///
/// Example: OP_DIV([n1, n2]) -> [n1/n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_div(stack: &mut Stack) -> bool {
    let (op, desc) = (OPDIV, OPDIV_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n1.checked_div(n2) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => {
            error_div_zero(op);
            false
        }
    }
}

/// OP_MOD: Computes the remainder of the division of the second-to-top number by the number on top of the stack
///
/// Example: OP_MOD([n1, n2]) -> [n1%n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_mod(stack: &mut Stack) -> bool {
    let (op, desc) = (OPMOD, OPMOD_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n1.checked_rem(n2) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => {
            error_div_zero(op);
            false
        }
    }
}

/// OP_LSHIFT: Computes the left shift of the second-to-top number by the number on top of the stack
///
/// Example: OP_LSHIFT([n1, n2]) -> [n1<<n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_lshift(stack: &mut Stack) -> bool {
    let (op, desc) = (OPLSHIFT, OPLSHIFT_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n1.checked_shl(n2 as u32) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => {
            error_div_zero(op);
            false
        }
    }
}

/// OP_RSHIFT: Computes the right shift of the second-to-top number by the number on top of the stack
///
/// Example: OP_RSHIFT([n1, n2]) -> [n1>>n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_rshift(stack: &mut Stack) -> bool {
    let (op, desc) = (OPRIGHT, OPRIGHT_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n1.checked_shr(n2 as u32) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => {
            error_div_zero(op);
            false
        }
    }
}

/// OP_BOOLAND: Substitutes the two numbers on top of the stack with ONE if they are both non-zero, with ZERO otherwise
///
/// Example: OP_BOOLAND([n1, n2]) -> [1] if n1 != 0 and n2 != 0
///          OP_BOOLAND([n1, n2]) -> [0] if n1 == 0 or n2 == 0
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_booland(stack: &mut Stack) -> bool {
    let (op, desc) = (OPBOOLAND, OPBOOLAND_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 != ZERO && n2 != ZERO {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_BOOLOR: Substitutes the two numbers on top of the stack with ONE if they are not both ZERO, with ZERO otherwise
///
/// Example: OP_BOOLOR([n1, n2]) -> [1] if n1 != 0 or n2 != 0
///          OP_BOOLOR([n1, n2]) -> [0] if n1 == 0 and n2 == 0
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_boolor(stack: &mut Stack) -> bool {
    let (op, desc) = (OPBOOLOR, OPBOOLOR_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 != ZERO || n2 != ZERO {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_NUMEQUAL: Substitutes the two numbers on top of the stack with ONE if they are equal, with ZERO otherwise
///
/// Example: OP_NUMEQUAL([n1, n2]) -> [1] if n1 == n2
///          OP_NUMEQUAL([n1, n2]) -> [0] if n1 != n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_numequal(stack: &mut Stack) -> bool {
    let (op, desc) = (OPNUMEQUAL, OPNUMEQUAL_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 == n2 {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_NUMEQUALVERIFY: Computes OP_NUMEQUAL and OP_VERIFY in sequence
///
/// Example: OP_NUMEQUALVERIFY([n1, n2]) -> []   if n1 == n2
///          OP_NUMEQUALVERIFY([n1, n2]) -> fail if n1 != n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_numequalverify(stack: &mut Stack) -> bool {
    let (op, desc) = (OPNUMEQUALVERIFY, OPNUMEQUALVERIFY_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 != n2 {
        error_not_equal_items(op);
        return false;
    }
    true
}

/// OP_NUMNOTEQUAL: Substitutes the two numbers on top of the stack with ONE if they are not equal, with ZERO otherwise
///
/// Example: OP_NUMNOTEQUAL([n1, n2]) -> [1] if n1 != n2
///          OP_NUMNOTEQUAL([n1, n2]) -> [0] if n1 == n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_numnotequal(stack: &mut Stack) -> bool {
    let (op, desc) = (OPNUMNOTEQUAL, OPNUMNOTEQUAL_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 != n2 {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_LESSTHAN: Substitutes the two numbers on top of the stack with ONE if the second-to-top is less than the top item, with ZERO otherwise
///
/// Example: OP_LESSTHAN([n1, n2]) -> [1] if n1 < n2
///          OP_LESSTHAN([n1, n2]) -> [0] if n1 >= n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_lessthan(stack: &mut Stack) -> bool {
    let (op, desc) = (OPLESSTHAN, OPLESSTHAN_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 < n2 {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_GREATERTHAN: Substitutes the two numbers on top of the stack with ONE if the second-to-top is greater than the top item, with ZERO otherwise
///
/// Example: OP_GREATERTHAN([n1, n2]) -> [1] if n1 > n2
///          OP_GREATERTHAN([n1, n2]) -> [0] if n1 <= n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_greaterthan(stack: &mut Stack) -> bool {
    let (op, desc) = (OP0NOTEQUAL, OP0NOTEQUAL_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 > n2 {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_LESSTHANOREQUAL: Substitutes the two numbers on top of the stack with ONE if the second-to-top is less than or equal to the top item, with ZERO otherwise
///
/// Example: OP_LESSTHANOREQUAL([n1, n2]) -> [1] if n1 <= n2
///          OP_LESSTHANOREQUAL([n1, n2]) -> [0] if n1 > n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_lessthanorequal(stack: &mut Stack) -> bool {
    let (op, desc) = (OPLESSTHANOREQUAL, OPLESSTHANOREQUAL_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 <= n2 {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_GREATERTHANOREQUAL: Substitutes the two numbers on top of the stack with ONE if the second-to-top is greater than or equal to the top item, with ZERO otherwise
///
/// Example: OP_GREATERTHANOREQUAL([n1, n2]) -> [1] if n1 >= n2
///          OP_GREATERTHANOREQUAL([n1, n2]) -> [0] if n1 < n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_greaterthanorequal(stack: &mut Stack) -> bool {
    let (op, desc) = (OPGREATERTHANOREQUAL, OPGREATERTHANOREQUAL_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 >= n2 {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_MIN: Substitutes the two numbers on top of the stack with the minimum between the two
///
/// Example: OP_MIN([n1, n2]) -> [n1] if n1 <= n2
///          OP_MIN([n1, n2]) -> [n2] if n1 > n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_min(stack: &mut Stack) -> bool {
    let (op, desc) = (OPMIN, OPMIN_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    stack.push(StackEntry::Num(n1.min(n2)))
}

/// OP_MAX: Substitutes the two numbers on top of the stack with the maximum between the two
///
/// Example: OP_MAX([n1, n2]) -> [n1] if n1 >= n2
///          OP_MAX([n1, n2]) -> [n2] if n1 < n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_max(stack: &mut Stack) -> bool {
    let (op, desc) = (OPMAX, OPMAX_DESC);
    trace(op, desc);
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    stack.push(StackEntry::Num(n1.max(n2)))
}

/// OP_WITHIN: Substitutes the three numbers on top of the the stack with ONE if the third-to-top is greater or equal to the second-to-top and less than the top item, with ZERO otherwise
///
/// Example: OP_WITHIN([n1, n2, n3]) -> [1] if n1 >= n2 and n1 < n3
///          OP_WITHIN([n1, n2, n3]) -> [0] if n1 < n2 or n1 >= n3
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_within(stack: &mut Stack) -> bool {
    let (op, desc) = (OPWITHIN, OPWITHIN_DESC);
    trace(op, desc);
    let n3 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n2 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 >= n2 && n1 < n3 {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/*---- CRYPTO OPS ----*/

/// OP_SHA3: Hashes the top item on the stack using SHA3-256
///
/// Example: OP_SHA3([x]) -> [SHA3-256(x)]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_sha3(stack: &mut Stack) -> bool {
    let (op, desc) = (OPSHA3, OPSHA3_DESC);
    trace(op, desc);
    let data = match stack.pop() {
        Some(StackEntry::Signature(sig)) => sig.as_ref().to_owned(),
        Some(StackEntry::PubKey(pk)) => pk.as_ref().to_owned(),
        Some(StackEntry::PubKeyHash(s)) | Some(StackEntry::Bytes(s)) => s.as_bytes().to_owned(),
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let hash = hex::encode(sha3_256::digest(&data));
    stack.push(StackEntry::Bytes(hash))
}

/// OP_HASH256: Creates standard address from public key and pushes it onto the stack
///
/// Example: OP_HASH256([pk]) -> [addr]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_hash256(stack: &mut Stack) -> bool {
    let (op, desc) = (OPHASH256, OPHASH256_DESC);
    trace(op, desc);
    let pk = match stack.pop() {
        Some(StackEntry::PubKey(pk)) => pk,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let addr = construct_address(&pk);
    stack.push(StackEntry::PubKeyHash(addr))
}

/// OP_HASH256_V0: Creates v0 address from public key and pushes it onto the stack
///
/// Example: OP_HASH256_V0([pk]) -> [addr_v0]
///
/// Info: Support for old 32-byte addresses
///
/// TODO: Deprecate after addresses retire
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_hash256_v0(stack: &mut Stack) -> bool {
    let (op, desc) = (OPHASH256V0, OPHASH256V0_DESC);
    trace(op, desc);
    let pk = match stack.pop() {
        Some(StackEntry::PubKey(pk)) => pk,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let addr_v0 = construct_address_v0(&pk);
    stack.push(StackEntry::PubKeyHash(addr_v0))
}

/// OP_HASH256_TEMP: Creates temporary address from public key and pushes it onto the stack
///
/// Example: OP_HASH256_TEMP([pk]) -> [addr_temp]
///
/// Info: Support for temporary address scheme used in wallet
///
/// TODO: Deprecate after addresses retire
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_hash256_temp(stack: &mut Stack) -> bool {
    let (op, desc) = (OPHASH256TEMP, OPHASH256TEMP_DESC);
    trace(op, desc);
    let pk = match stack.pop() {
        Some(StackEntry::PubKey(pk)) => pk,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let addr_temp = construct_address_temp(&pk);
    stack.push(StackEntry::PubKeyHash(addr_temp))
}

/// OP_CHECKSIG: Pushes ONE onto the stack if the signature is valid, ZERO otherwise
///
/// Example: OP_CHECKSIG([msg, sig, pk]) -> [1] if Verify(sig, msg, pk) == 1
///          OP_CHECKSIG([msg, sig, pk]) -> [0] if Verify(sig, msg, pk) == 0
///
/// Info: It allows signature verification on arbitrary messsages, not only transactions
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_checksig(stack: &mut Stack) -> bool {
    let (op, desc) = (OPCHECKSIG, OPCHECKSIG_DESC);
    trace(op, desc);
    let pk = match stack.pop() {
        Some(StackEntry::PubKey(pk)) => pk,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let sig = match stack.pop() {
        Some(StackEntry::Signature(sig)) => sig,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let msg = match stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if (!sign::verify_detached(&sig, msg.as_bytes(), &pk)) {
        stack.push(StackEntry::Num(ZERO))
    } else {
        stack.push(StackEntry::Num(ONE))
    }
}

/// OP_CHECKSIGVERIFY: Runs OP_CHECKSIG and OP_VERIFY in sequence
///
/// Example: OP_CHECKSIGVERIFY([msg, sig, pk]) -> []   if Verify(sig, msg, pk) == 1
///          OP_CHECKSIGVERIFY([msg, sig, pk]) -> fail if Verify(sig, msg, pk) == 0
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_checksigverify(stack: &mut Stack) -> bool {
    let (op, desc) = (OPCHECKSIGVERIFY, OPCHECKSIGVERIFY_DESC);
    trace(op, desc);
    let pk = match stack.pop() {
        Some(StackEntry::PubKey(pk)) => pk,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let sig = match stack.pop() {
        Some(StackEntry::Signature(sig)) => sig,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let msg = match stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if (!sign::verify_detached(&sig, msg.as_bytes(), &pk)) {
        error_invalid_signature(op);
        return false;
    }
    true
}

/// OP_CHECKMULTISIG: Pushes ONE onto the stack if the m-of-n multi-signature is valid, ZERO otherwise
///
/// Example: OP_CHECKMULTISIG([msg, sig1, sig2, m, pk1, pk2, pk3, n]) -> [1] if Verify(sig1, sig2, msg, pk1, pk2, pk3) == 1
///          OP_CHECKMULTISIG([msg, sig1, sig2, m, pk1, pk2, pk3, n]) -> [0] if Verify(sig1, sig2, msg, pk1, pk2, pk3) == 0
///
/// Info: It allows multi-signature verification on arbitrary messsages, not only transactions
///       Ordering of signatures and public keys is not relevant
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_checkmultisig(stack: &mut Stack) -> bool {
    let (op, desc) = (OPCHECKMULTISIG, OPCHECKMULTISIG_DESC);
    trace(op, desc);
    let n = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n > MAX_PUB_KEYS_PER_MULTISIG as usize {
        error_num_pubkeys(op);
        return false;
    }
    let mut pks = Vec::new();
    while let Some(StackEntry::PubKey(_)) = stack.last() {
        if let Some(StackEntry::PubKey(pk)) = stack.pop() {
            pks.push(pk);
        }
    }
    if pks.len() != n {
        error_num_pubkeys(op);
        return false;
    }
    let m = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if m > n {
        error_num_signatures(op);
        return false;
    }
    let mut sigs = Vec::new();
    while let Some(StackEntry::Signature(_)) = stack.last() {
        if let Some(StackEntry::Signature(sig)) = stack.pop() {
            sigs.push(sig);
        }
    }
    if sigs.len() != m {
        error_num_signatures(op);
        return false;
    }
    let msg = match stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if !verify_multisig(&sigs, &msg, &mut pks) {
        stack.push(StackEntry::Num(ZERO))
    } else {
        stack.push(StackEntry::Num(ONE))
    }
}

/// OP_CHECKMULTISIGVERIFY: Runs OP_CHECKMULTISIG and OP_VERIFY in sequence
///
/// Example: OP_CHECKMULTISIGVERIFY([msg, sig1, sig2, m, pk1, pk2, pk3, n]) -> []   if Verify(sig1, sig2, msg, pk1, pk2, pk3) == 1
///          OP_CHECKMULTISIGVERIFY([msg, sig1, sig2, m, pk1, pk2, pk3, n]) -> fail if Verify(sig1, sig2, msg, pk1, pk2, pk3) == 0
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_checkmultisigverify(stack: &mut Stack) -> bool {
    let (op, desc) = (OPCHECKMULTISIG, OPCHECKMULTISIG_DESC);
    trace(op, desc);
    let n = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n > MAX_PUB_KEYS_PER_MULTISIG as usize {
        error_num_pubkeys(op);
        return false;
    }
    let mut pks = Vec::new();
    while let Some(StackEntry::PubKey(_)) = stack.last() {
        if let Some(StackEntry::PubKey(pk)) = stack.pop() {
            pks.push(pk);
        }
    }
    if pks.len() != n {
        error_num_pubkeys(op);
        return false;
    }
    let m = match stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if m > n {
        error_num_signatures(op);
        return false;
    }
    let mut sigs = Vec::new();
    while let Some(StackEntry::Signature(_)) = stack.last() {
        if let Some(StackEntry::Signature(sig)) = stack.pop() {
            sigs.push(sig);
        }
    }
    let msg = match stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if !verify_multisig(&sigs, &msg, &mut pks) {
        error_invalid_multisignature(op);
        return false;
    }
    true
}

/// Verifies an m-of-n multi-signature
///
/// ### Arguments
///
/// * `sigs` - signatures to verify
/// * `msg`  - data to verify against
/// * `pks`  - public keys to match against
fn verify_multisig(sigs: &[Signature], msg: &String, pks: &mut Vec<PublicKey>) -> bool {
    let mut num_valid_sigs = ZERO;
    for (index_sig, sig) in sigs.iter().enumerate() {
        for (index_pk, pk) in pks.iter().enumerate() {
            if sign::verify_detached(sig, msg.as_bytes(), pk) {
                num_valid_sigs += ONE;
                pks.remove(index_pk);
                break;
            }
        }
        if num_valid_sigs != index_sig + ONE {
            return false;
        }
    }
    true
}

/*---- TESTS ----*/

#[cfg(test)]
mod tests {
    use super::*;

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
}
