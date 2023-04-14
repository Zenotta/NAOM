use crate::script::OpCodes;

/*------- TRANSACTION CONSTANTS -------*/

pub const RECEIPT_DEFAULT_DRS_TX_HASH: &str = "default_drs_tx_hash";
pub const MAX_METADATA_BYTES: usize = 800;

/*------- NETWORK CONSTANTS --------*/

/// Current network version: Always bump immediately after a version is deployed.
pub const NETWORK_VERSION: u32 = 4;
pub const NETWORK_VERSION_SERIALIZED: &[u8] = b"4";

/*------- VALUE HANDLING CONSTANTS --------*/

// Number of decimal places to divide to in display
pub const D_DISPLAY_PLACES_U64: u64 = 25200;
pub const D_DISPLAY_PLACES: f64 = 25200.0;

// Number of possible tokens in existence (10 billion)
pub const TOTAL_TOKENS: u64 = D_DISPLAY_PLACES_U64 * 10000000000;

/*------- ASSET CONSTANTS -------*/

// The value to sign/verify for receipt-based payments
pub const RECEIPT_ACCEPT_VAL: &str = "PAYMENT_ACCEPT";

/*------- BLOCK CONSTANTS --------*/

// Maximum number of bytes that a block can contain
pub const MAX_BLOCK_SIZE: usize = 1000;

/*------- SCRIPT CONSTANTS -------*/

// Maximum number of bytes pushable to the stack
pub const MAX_SCRIPT_ITEM_SIZE: u16 = 520;

// Maximum number of non-push operations per script
pub const MAX_OPS_PER_SCRIPT: u8 = 201;

// Maximum number of public keys per multisig
pub const MAX_PUB_KEYS_PER_MULTISIG: u8 = 20;

// Maximum script length in bytes
pub const MAX_SCRIPT_SIZE: u16 = 10000;

// Maximum number of values on script interpreter stack
pub const MAX_STACK_SIZE: u16 = 1000;

// Threshold for lock_time: below this value it is interpreted as block number,
// otherwise as UNIX timestamp.
pub const LOCKTIME_THRESHOLD: u32 = 500000000; // Tue Nov 5 00:53:20 1985 UTC

// Maximum value that an opcode can be
pub const MAX_OPCODE: u8 = OpCodes::MAX_OPCODE as u8;

/*------- STORAGE CONSTANTS -------*/

/// The constant prepending character for a transaction
pub const TX_PREPEND: u8 = b'g';

pub const P2SH_PREPEND: u8 = b'H';

/*------- PREVIOUS NETWORK VERSIONS -------*/

// Network version 0
pub const NETWORK_VERSION_V0: u64 = 0;

// Network version to support temporary address structure on wallet
// TODO: Deprecate after addresses retire
pub const NETWORK_VERSION_TEMP: u64 = 99999;

/*------- NUMBERS -------*/
pub const ZERO: usize = 0;
pub const ONE: usize = 1;
pub const TWO: usize = 2;
pub const THREE: usize = 3;
pub const FOUR: usize = 4;
pub const FIVE: usize = 5;
pub const SIX: usize = 6;
pub const SEVEN: usize = 7;
pub const EIGHT: usize = 8;
pub const NINE: usize = 9;
pub const TEN: usize = 10;
pub const ELEVEN: usize = 11;
pub const TWELVE: usize = 12;
pub const THIRTEEN: usize = 13;
pub const FOURTEEN: usize = 14;
pub const FIFTEEN: usize = 15;
pub const SIXTEEN: usize = 16;

/*------- TRACE MESSAGES -------*/

// constants
pub const OP0: &str = "OP_0";
pub const OP1: &str = "OP_1";
pub const OP2: &str = "OP_2";
pub const OP3: &str = "OP_3";
pub const OP4: &str = "OP_4";
pub const OP5: &str = "OP_5";
pub const OP6: &str = "OP_6";
pub const OP7: &str = "OP_7";
pub const OP8: &str = "OP_8";
pub const OP9: &str = "OP_9";
pub const OP10: &str = "OP_10";
pub const OP11: &str = "OP_11";
pub const OP12: &str = "OP_12";
pub const OP13: &str = "OP_13";
pub const OP14: &str = "OP_14";
pub const OP15: &str = "OP_15";
pub const OP16: &str = "OP_16";

pub const OP0_DESC: &str = "Pushes number ZERO onto the stack";
pub const OP1_DESC: &str = "Pushes number ONE onto the stack";
pub const OP2_DESC: &str = "Pushes number TWO onto the stack";
pub const OP3_DESC: &str = "Pushes number THREE onto the stack";
pub const OP4_DESC: &str = "Pushes number FOUR onto the stack";
pub const OP5_DESC: &str = "Pushes number FIVE onto the stack";
pub const OP6_DESC: &str = "Pushes number SIX onto the stack";
pub const OP7_DESC: &str = "Pushes number SEVEN onto the stack";
pub const OP8_DESC: &str = "Pushes number EIGHT onto the stack";
pub const OP9_DESC: &str = "Pushes number NINE onto the stack";
pub const OP10_DESC: &str = "Pushes number TEN onto the stack";
pub const OP11_DESC: &str = "Pushes number ELEVEN onto the stack";
pub const OP12_DESC: &str = "Pushes number TWELVE onto the stack";
pub const OP13_DESC: &str = "Pushes number THIRTEEN onto the stack";
pub const OP14_DESC: &str = "Pushes number FOURTEEN onto the stack";
pub const OP15_DESC: &str = "Pushes number FIFTEEN onto the stack";
pub const OP16_DESC: &str = "Pushes number SIXTEEN onto the stack";

// control flow
pub const OPNOP: &str = "OP_NOP";
pub const OPIF: &str = "OP_IF";
pub const OPNOTIF: &str = "OP_NOTIF";
pub const OPELSE: &str = "OP_ELSE";
pub const OPENDIF: &str = "OP_ENDIF";
pub const OPVERIFY: &str = "OP_VERIFY";
pub const OPRETURN: &str = "OP_RETURN";

pub const OPNOP_DESC: &str = "Does nothing";
pub const OPIF_DESC: &str =
    "Checks if the top item on the stack is not ZERO and executes the next block of instructions";
pub const OPNOTIF_DESC: &str =
    "Checks if the top item on the stack is ZERO and executes the next block of instructions";
pub const OPELSE_DESC: &str =
    "Executes the next block of instructions if the previous OP_IF or OP_NOTIF was not executed";
pub const OPENDIF_DESC: &str = "Ends an OP_IF or OP_NOTIF block";
pub const OPVERIFY_DESC: &str =
    "Removes the top item from the stack and ends execution with an error if it is ZERO";
pub const OPRETURN_DESC: &str = "Ends execution with an error";

// stack
pub const OPTOALTSTACK: &str = "OP_TOALTSTACK";
pub const OPFROMALTSTACK: &str = "OP_FROMALTSTACK";
pub const OP2DROP: &str = "OP_2DROP";
pub const OP2DUP: &str = "OP_2DUP";
pub const OP3DUP: &str = "OP_3DUP";
pub const OP2OVER: &str = "OP_2OVER";
pub const OP2ROT: &str = "OP_2ROT";
pub const OP2SWAP: &str = "OP_2SWAP";
pub const OPIFDUP: &str = "OP_IFDUP";
pub const OPDEPTH: &str = "OP_DEPTH";
pub const OPDROP: &str = "OP_DROP";
pub const OPDUP: &str = "OP_DUP";
pub const OPNIP: &str = "OP_NIP";
pub const OPOVER: &str = "OP_OVER";
pub const OPPICK: &str = "OP_PICK";
pub const OPROLL: &str = "OP_ROLL";
pub const OPROT: &str = "OP_ROT";
pub const OPSWAP: &str = "OP_SWAP";
pub const OPTUCK: &str = "OP_TUCK";

pub const OPTOALTSTACK_DESC: &str =
    "Moves the top item from the main stack to the top of the alt stack";
pub const OPFROMALTSTACK_DESC: &str =
    "Moves the top item from the alt stack to the top of the main stack";
pub const OP2DROP_DESC: &str = "Removes the top two items from the stack";
pub const OP2DUP_DESC: &str = "Duplicates the top two items on the stack";
pub const OP3DUP_DESC: &str = "Duplicates the top three items on the stack";
pub const OP2OVER_DESC: &str = "Copies the second-to-top pair of items to the top of the stack";
pub const OP2ROT_DESC: &str = "Moves the third-to-top pair of items to the top of the stack";
pub const OP2SWAP_DESC: &str = "Swaps the top two pairs of items on the stack";
pub const OPIFDUP_DESC: &str = "Duplicates the top item on the stack if it is not ZERO";
pub const OPDEPTH_DESC: &str = "Pushes the stack size onto the stack";
pub const OPDROP_DESC: &str = "Removes the top item from the stack";
pub const OPDUP_DESC: &str = "Duplicates the top item on the stack";
pub const OPNIP_DESC: &str = "Removes the second-to-top item from the stack";
pub const OPOVER_DESC: &str = "Copies the second-to-top item to the top of the stack";
pub const OPPICK_DESC: &str =
    "Copies the nth-to-top item to the top of the stack, where n is the top item on the stack";
pub const OPROLL_DESC: &str =
    "Moves the nth-to-top item to the top of the stack, where n is the top item on the stack";
pub const OPROT_DESC: &str = "Moves the third-to-top item to the top of the stack";
pub const OPSWAP_DESC: &str = "Swaps the top two items on the stack";
pub const OPTUCK_DESC: &str = "Copies the top item behind the second-to-top item on the stack";

// splice
pub const OPCAT: &str = "OP_CAT";
pub const OPSUBSTR: &str = "OP_SUBSTR";
pub const OPLEFT: &str = "OP_LEFT";
pub const OPRIGHT: &str = "OP_RIGHT";
pub const OPSIZE: &str = "OP_SIZE";

pub const OPCAT_DESC: &str = "Concatenates the two strings on top of the stack";
pub const OPSUBSTR_DESC: &str = "Extracts a substring from the third-to-top item on the stack";
pub const OPLEFT_DESC: &str = "Extracts a left substring from the second-to-top item on the stack";
pub const OPRIGHT_DESC: &str =
    "Extracts a right substring from the second-to-top item on the stack";
pub const OPSIZE_DESC: &str = "Computes the size in bytes of the string on top of the stack";

// bitwise logic
pub const OPINVERT: &str = "OP_INVERT";
pub const OPAND: &str = "OP_AND";
pub const OPOR: &str = "OP_OR";
pub const OPXOR: &str = "OP_XOR";
pub const OPEQUAL: &str = "OP_EQUAL";
pub const OPEQUALVERIFY: &str = "OP_EQUALVERIFY";

pub const OPINVERT_DESC: &str = "Computes bitwise NOT of the number on top of the stack";
pub const OPAND_DESC: &str = "Computes bitwise AND between the two numbers on top of the stack";
pub const OPOR_DESC: &str = "Computes bitwise OR between the two numbers on top of the stack";
pub const OPXOR_DESC: &str = "Computes bitwise XOR between the two numbers on top of the stack";
pub const OPEQUAL_DESC: &str =
    "Substitutes the top two items on the stack with ONE if they are equal, with ZERO otherwise";
pub const OPEQUALVERIFY_DESC: &str = "Computes OP_EQUAL and OP_VERIFY in sequence";

// arithmetic
pub const OP1ADD: &str = "OP_1ADD";
pub const OP1SUB: &str = "OP_1SUB";
pub const OP2MUL: &str = "OP_2MUL";
pub const OP2DIV: &str = "OP_2DIV";
pub const OPNOT: &str = "OP_NOT";
pub const OP0NOTEQUAL: &str = "OP_0NOTEQUAL";
pub const OPADD: &str = "OP_ADD";
pub const OPSUB: &str = "OP_SUB";
pub const OPMUL: &str = "OP_MUL";
pub const OPDIV: &str = "OP_DIV";
pub const OPMOD: &str = "OP_MOD";
pub const OPLSHIFT: &str = "OP_LSHIFT";
pub const OPRSHIFT: &str = "OP_RSHIFT";
pub const OPBOOLAND: &str = "OP_BOOLAND";
pub const OPBOOLOR: &str = "OP_BOOLOR";
pub const OPNUMEQUAL: &str = "OP_NUMEQUAL";
pub const OPNUMEQUALVERIFY: &str = "OP_NUMEQUALVERIFY";
pub const OPNUMNOTEQUAL: &str = "OP_NUMNOTEQUAL";
pub const OPLESSTHAN: &str = "OP_LESSTHAN";
pub const OPGREATERTHAN: &str = "OP_GREATERTHAN";
pub const OPLESSTHANOREQUAL: &str = "OP_LESSTHANOREQUAL";
pub const OPGREATERTHANOREQUAL: &str = "OP_GREATERTHANOREQUAL";
pub const OPMIN: &str = "OP_MIN";
pub const OPMAX: &str = "OP_MAX";
pub const OPWITHIN: &str = "OP_WITHIN";

pub const OP1ADD_DESC: &str = "Adds ONE to the number on top of the stack";
pub const OP1SUB_DESC: &str = "Subtracts ONE from the number on top of the stack";
pub const OP2MUL_DESC: &str = "Multiplies by TWO the number on top of the stack";
pub const OP2DIV_DESC: &str = "Divides by TWO the number on top of the stack";
pub const OPNOT_DESC: &str =
    "Substitutes the number on top of the stack with ONE if it is equal to ZERO, with ZERO otherwise";
pub const OP0NOTEQUAL_DESC: &str =
    "Substitutes the number on top of the stack with ONE if it is not equal to ZERO, with ZERO otherwise";
pub const OPADD_DESC: &str = "Adds the two numbers on top of the stack";
pub const OPSUB_DESC: &str =
    "Subtracts the number on top of the stack from the second-to-top number on the stack";
pub const OPMUL_DESC: &str =
    "Multiplies the second-to-top number by the number on top of the stack";
pub const OPDIV_DESC: &str = "Divides the second-to-top number by the number on top of the stack";
pub const OPMOD_DESC: &str =
    "Computes the remainder of the division of the second-to-top number by the number on top of the stack";
pub const OPLSHIFT_DESC: &str =
    "Computes the left shift of the second-to-top number by the number on top of the stack";
pub const OPRSHIFT_DESC: &str =
    "Computes the right shift of the second-to-top number by the number on top of the stack";
pub const OPBOOLAND_DESC: &str = "Substitutes the two numbers on top of the stack with ONE if they are both non-zero, with ZERO otherwise";
pub const OPBOOLOR_DESC: &str = "Substitutes the two numbers on top of the stack with ONE if they are not both ZERO, with ZERO otherwise";
pub const OPNUMEQUAL_DESC: &str = "Substitutes the two numbers on top of the stack with ONE if they are equal, with ZERO otherwise";
pub const OPNUMEQUALVERIFY_DESC: &str = "Computes OP_NUMEQUAL and OP_VERIFY in sequence";
pub const OPNUMNOTEQUAL_DESC: &str = "Substitutes the two numbers on top of the stack with ONE if they are not equal, with ZERO otherwise";
pub const OPLESSTHAN_DESC: &str = "Substitutes the two numbers on top of the stack with ONE if the second-to-top is less than the top item, with ZERO otherwise";
pub const OPGREATERTHAN_DESC: &str = "Substitutes the two numbers on top of the stack with ONE if the second-to-top is greater than the top item, with ZERO otherwise";
pub const OPLESSTHANOREQUAL_DESC: &str = "Substitutes the two numbers on top of the stack with ONE if the second-to-top is less than or equal to the top item, with ZERO otherwise";
pub const OPGREATERTHANOREQUAL_DESC: &str = "Substitutes the two numbers on top of the stack with ONE if the second-to-top is greater than or equal to the top item, with ZERO otherwise";
pub const OPMIN_DESC: &str =
    "Substitutes the two numbers on top of the stack with the minimum between the two";
pub const OPMAX_DESC: &str =
    "Substitutes the two numbers on top of the stack with the maximum between the two";
pub const OPWITHIN_DESC: &str = "Substitutes the three numbers on top of the the stack with ONE if the third-to-top is greater or equal to the second-to-top and less than the top item, with ZERO otherwise";

// crypto
pub const OPSHA3: &str = "OP_SHA3";
pub const OPHASH256: &str = "OP_HASH256";
pub const OPHASH256V0: &str = "OP_HASH256_V0";
pub const OPHASH256TEMP: &str = "OP_HASH256_TEMP";
pub const OPCHECKSIG: &str = "OP_CHECKSIG";
pub const OPCHECKSIGVERIFY: &str = "OP_CHECKSIGVERIFY";
pub const OPCHECKMULTISIG: &str = "OP_CHECKMULTISIG";
pub const OPCHECKMULTISIGVERIFY: &str = "OP_CHECKMULTISIGVERIFY";

pub const OPSHA3_DESC: &str = "Hashes the top item on the stack using SHA3-256";
pub const OPHASH256_DESC: &str =
    "Creates standard address from public key and pushes it onto the stack";
pub const OPHASH256V0_DESC: &str =
    "Creates v0 address from public key and pushes it onto the stack";
pub const OPHASH256TEMP_DESC: &str =
    "Creates temporary address from public key and pushes it onto the stack";
pub const OPCHECKSIG_DESC: &str =
    "Pushes ONE onto the stack if the signature is valid, ZERO otherwise";
pub const OPCHECKSIGVERIFY_DESC: &str = "Runs OP_CHECKSIG and OP_VERIFY in sequence";
pub const OPCHECKMULTISIG_DESC: &str =
    "Pushes ONE onto the stack if the m-of-n multi-signature is valid, ZERO otherwise";
pub const OPCHECKMULTISIGVERIFY_DESC: &str = "Runs OP_CHECKMULTISIG and OP_VERIFY in sequence";

/*------- ERROR MESSAGES -------*/

// opcodes
pub const ERROR_VERIFY: &str = "The top item on the stack is ZERO";
pub const ERROR_RETURN: &str = "OP_RETURN executed";
pub const ERROR_NUM_ITEMS: &str = "Not enough items on the stack";
pub const ERROR_ITEM_TYPE: &str = "Item type is not correct";
pub const ERROR_ITEM_INDEX: &str = "Index is out of bound";
pub const ERROR_ITEM_SIZE: &str = "Item size exceeds MAX_SCRIPT_ITEM_SIZE-byte limit";
pub const ERROR_NOT_EQUAL_ITEMS: &str = "The two top items are not equal";
pub const ERROR_OVERFLOW: &str = "Attempt to overflow";
pub const ERROR_DIV_ZERO: &str = "Attempt to divide by ZERO";
pub const ERROR_INVALID_SIGNATURE: &str = "Signature is not valid";
pub const ERROR_INVALID_MULTISIGNATURE: &str = "Multi-signature is not valid";
pub const ERROR_NUM_PUBKEYS: &str = "Number of public keys provided is not correct";
pub const ERROR_NUM_SIGNATURES: &str = "Number of signatures provided is not correct";

// script
pub const ERROR_MAX_SCRIPT_SIZE: &str = "Script size exceeds MAX_SCRIPT_SIZE-byte limit";
pub const ERROR_MAX_STACK_SIZE: &str = "Stack size exceeds MAX_STACK_SIZE limit";
pub const ERROR_MAX_OPS_SCRIPT: &str =
    "Number of opcodes in script exceeds MAX_OPS_PER_SCRIPT limit";
pub const ERROR_INVALID_OPCODE: &str = "Attempt to execute invalid opcode";
