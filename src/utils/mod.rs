use std::collections::BTreeMap;

use crate::constants::D_DISPLAY_PLACES;
use crate::primitives::asset::TokenAmount;

// ------- MODS ------- //

pub mod druid_utils;
pub mod error_utils;
pub mod merkle_utils;
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

/// Create a single `BTreeMap<E, T>` struct from two `BTreeMap<E, T>` structs
/// , summing the values of `T` for each corresponding entry `E`
///
/// ### Arguments
///
/// * `m1` - First map
/// * `m2` - Second map
pub fn add_btreemap<E: Ord, T: Copy + std::ops::AddAssign>(
    m1: &mut BTreeMap<E, T>,
    m2: BTreeMap<E, T>,
) -> &BTreeMap<E, T> {
    m2.into_iter().for_each(|(key, value)| {
        m1.entry(key).and_modify(|e| *e += value).or_insert(value);
    });
    m1
}
