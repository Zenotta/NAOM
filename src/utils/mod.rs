use crate::constants::D_DISPLAY_PLACES;
use crate::primitives::asset::TokenAmount;
use crate::primitives::transaction::{OutPoint, TxOut};

// ------- MODS ------- //

pub mod druid_utils;
pub mod script_utils;
pub mod test_utils;
pub mod transaction_utils;

// ------- FUNCTIONS ------- //

/// Determines whether the passed value is within bounds of
/// available tokens in the supply.
///
/// TODO: Currently placeholder, needs to be filled in once requirements known
pub fn is_valid_amount(_value: &TokenAmount) -> bool {
    true
}

/// Formats an incoming value to be displayed
///
/// ### Arguments
///
/// * `value`   - Value to format for display
pub fn format_for_display(value: &u64) -> String {
    let value_f64 = *value as f64;
    (value_f64 / D_DISPLAY_PLACES).to_string()
}

/// Get the `drs_tx_hash` value from a given `OutPoint` and its corresponding `TxOut` value
///
/// ### Arguments
///
/// * `outpoint` - The `OutPoint` to get the drs_tx_hash value from
/// * `tx_out`   - The `TxOut` to get the drs_tx_hash value from
///
///  TODO: Add support for `Data` asset variant
pub fn get_drs_tx_hash(out_point: &OutPoint, tx_out: &TxOut) -> Option<String> {
    if tx_out.value.is_receipt() {
        return Some(
            tx_out
                .drs_tx_hash
                .clone()
                .unwrap_or_else(|| out_point.t_hash.clone()), /* Assume create transaction */
        );
    }
    //  Assume `Token` type
    None
}
