use crate::primitives::asset::Asset;
use serde::{Deserialize, Serialize};

/// The expectation to be met in a specific DRUID transaction
#[derive(Default, Clone, Debug, Ord, Eq, PartialEq, Serialize, Deserialize, PartialOrd)]
pub struct DruidExpectation {
    pub from: String,
    pub to: String,
    pub asset: Asset,
    pub drs_tx_hash: Option<String>,
}

/// A structure to hold DDE-specific content in a transaction
///
/// `druid`                 - DRUID to match on
/// `participants`          - Participants in trade
/// `expect_value`          - The value expected by another party for this tx
/// `expect_value_amount`   - The amount of the asset expected by another party for this tx
/// `expect_address`        - The address the other party is expected to pay to
#[derive(Default, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DdeValues {
    pub druid: String,
    pub participants: usize,
    pub expectations: Vec<DruidExpectation>,
}

impl DdeValues {
    /// Creates a new DdeValues instance
    pub fn new() -> Self {
        Default::default()
    }
}
