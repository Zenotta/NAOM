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
pub const MAX_SCRIPT_ELEMENT_SIZE: u16 = 520;

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
// TODO: Depreciate after addresses retire
pub const NETWORK_VERSION_TEMP: u64 = 99999;

/*------- NUMBERS -------*/
pub const ZERO: usize = 0;
pub const ONE: usize = 1;
pub const TWO: usize = 2;
pub const THREE: usize = 3;
pub const FOUR: usize = 4;
pub const FIVE: usize = 5;
pub const SIX: usize = 6;
