use crate::primitives::transaction::OutPoint;
use crate::utils::{add_btreemap, format_for_display};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, iter, mem::size_of, ops};

/// A structure representing the amount of tokens in an instance
#[derive(Deserialize, Serialize, Default, Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct TokenAmount(pub u64);

impl fmt::Display for TokenAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let format_result = format_for_display(&self.0);
        write!(f, "{format_result}")
    }
}

impl ops::Add for TokenAmount {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl ops::AddAssign for TokenAmount {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

impl ops::Sub for TokenAmount {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

impl ops::SubAssign for TokenAmount {
    fn sub_assign(&mut self, other: Self) {
        self.0 -= other.0;
    }
}

impl ops::Div<u64> for TokenAmount {
    type Output = Self;

    fn div(self, rhs: u64) -> Self {
        Self(self.0 / rhs)
    }
}

impl ops::DivAssign<u64> for TokenAmount {
    fn div_assign(&mut self, rhs: u64) {
        self.0 /= rhs;
    }
}

impl ops::Mul<u64> for TokenAmount {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self {
        Self(self.0 * rhs)
    }
}

impl ops::MulAssign<u64> for TokenAmount {
    fn mul_assign(&mut self, rhs: u64) {
        self.0 *= rhs;
    }
}

impl iter::Sum for TokenAmount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), |r, l| r + l)
    }
}

/// Receipt asset struct
#[derive(Default, Deserialize, Serialize, Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReceiptAsset {
    pub amount: u64,
    pub drs_tx_hash: Option<String>,
    pub metadata: Option<String>,
}

impl ReceiptAsset {
    pub fn new(amount: u64, drs_tx_hash: Option<String>, metadata: Option<String>) -> Self {
        Self {
            amount,
            drs_tx_hash,
            metadata,
        }
    }
}

/// ERD (Electronic Resource Definition) data type enum
#[derive(Deserialize, Serialize, Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum ERDType {
    SDV1 {
        amount: u64,
        data_hash: String,           // Original data's hash | HEX
        data_hash_mr: String,        // Encrypted data's hash | HEX
        perm_table: String,          // Base64-encoded perm table
        associated_data: String,     // AEAD associated data | HEX
        drs_tx_hash: Option<String>, // DRS tx_hash specification
    },
}

/// Retrieves the length of an ERDType
fn get_erd_len(erd: &ERDType) -> usize {
    match erd {
        ERDType::SDV1 {
            amount: _amount,
            data_hash,
            data_hash_mr,
            perm_table,
            associated_data,
            drs_tx_hash,
        } => {
            size_of::<u64>()
                + data_hash.len()
                + data_hash_mr.len()
                + perm_table.len()
                + associated_data.len()
                + drs_tx_hash.as_ref().map_or(0, |s| s.len())
        }
    }
}

/// Asset struct
///
/// * `Token`   - An asset struct representation of the ZNT token
/// * `Data`    - A data asset
/// * `Receipt` - A receipt for a payment. The value indicates the number of receipt assets
#[derive(Deserialize, Serialize, Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum Asset {
    Token(TokenAmount),
    ERD(ERDType),
    Receipt(ReceiptAsset),
}

impl Default for Asset {
    fn default() -> Self {
        Asset::Token(Default::default())
    }
}

impl Asset {
    /// Modify `self` of `Asset` struct to obtain `drs_tx_hash`
    /// from either the asset itself or its corresponding `OutPoint`
    pub fn with_fixed_hash(mut self, out_point: &OutPoint) -> Self {
        if let Asset::Receipt(ref mut receipt_asset) = self {
            if receipt_asset.drs_tx_hash.is_none() {
                receipt_asset.drs_tx_hash = Some(&out_point.t_hash).cloned();
            }
        }
        self
    }

    /// Get optional `drs_tx_hash` value for `Asset`
    pub fn get_drs_tx_hash(&self) -> Option<&String> {
        match self {
            Asset::Token(_) => None,
            Asset::ERD(_) => None, /* TODO: This will have to change */
            Asset::Receipt(receipt) => receipt.drs_tx_hash.as_ref(),
        }
    }

    pub fn get_metadata(&self) -> Option<&String> {
        match self {
            Asset::Token(_) => None,
            Asset::ERD(_) => None,
            Asset::Receipt(receipt) => receipt.metadata.as_ref(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Asset::Token(_) => size_of::<TokenAmount>(),
            Asset::ERD(t) => get_erd_len(t),
            Asset::Receipt(_) => size_of::<u64>(),
        }
    }

    pub fn token_u64(amount: u64) -> Self {
        Asset::Token(TokenAmount(amount))
    }

    pub fn receipt(amount: u64, drs_tx_hash: Option<String>, metadata: Option<String>) -> Self {
        Asset::Receipt(ReceiptAsset::new(amount, drs_tx_hash, metadata))
    }

    /// Add an asset of the same variant to `self` asset.
    /// TODO: Add handling for `Data` asset variant. Will return false when `Data` asset is presented.
    ///
    /// ### Note
    ///
    /// This function will return false for `Receipt` assets
    /// getting added together that do not have the same `drs_tx_hash`
    ///
    /// ### Arguments
    ///
    ///* `rhs`          - The right-hand-side (RHS) asset to add to `self`
    pub fn add_assign(&mut self, rhs: &Self) -> bool {
        match (self, rhs) {
            (Asset::Token(lhs_tokens), Asset::Token(rhs_tokens)) => {
                *lhs_tokens += *rhs_tokens;
                true
            }
            (Asset::Receipt(lhs_receipts), Asset::Receipt(rhs_receipts)) => {
                if lhs_receipts.drs_tx_hash != rhs_receipts.drs_tx_hash {
                    return false;
                }
                lhs_receipts.amount += rhs_receipts.amount;
                true
            }
            _ => false,
        }
    }

    /// Determine if `self` asset is greater or equal to another asset of the same variant.
    /// TODO: Add handling for `Data` asset variant. Will return None if `Data` asset is presented.
    ///
    /// ### Arguments
    ///
    ///* `rhs`                  - Reference to right-hand-side (RHS) `Asset`
    pub fn is_greater_or_equal_to(&self, rhs: &Asset) -> Option<bool> {
        match (&self, &rhs) {
            (Asset::Token(lhs_token_amount), Asset::Token(rhs_token_amount)) => {
                Some(lhs_token_amount >= rhs_token_amount)
            }
            (Asset::Receipt(lhs_receipt), Asset::Receipt(rhs_receipt)) => {
                if lhs_receipt.drs_tx_hash != rhs_receipt.drs_tx_hash {
                    return None;
                }
                Some(lhs_receipt.amount >= rhs_receipt.amount)
            }
            _ => None,
        }
    }

    /// Determine if `self` asset is greater than another asset of the same variant.
    /// If `self` asset is greater, return the excess.
    /// TODO: Add handling for `Data` asset variant. Will return None if `Data` asset is presented.
    ///
    /// ### Arguments
    ///
    ///* `rhs`                  - Reference to right-hand-side (RHS) `Asset`
    pub fn get_excess(&self, rhs: &Asset) -> Option<Asset> {
        match (&self, &rhs) {
            (Asset::Token(lhs_tokens), Asset::Token(rhs_tokens)) => {
                if lhs_tokens > rhs_tokens {
                    Some(Asset::Token(*lhs_tokens - *rhs_tokens))
                } else {
                    None
                }
            }
            (Asset::Receipt(lhs_receipts), Asset::Receipt(rhs_receipts)) => {
                if lhs_receipts.amount > rhs_receipts.amount
                    && lhs_receipts.drs_tx_hash == rhs_receipts.drs_tx_hash
                {
                    Some(Asset::receipt(
                        lhs_receipts.amount - rhs_receipts.amount,
                        lhs_receipts.drs_tx_hash.clone(),
                        lhs_receipts.metadata.clone(),
                    ))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Determine if the asset in question is of the same variant as `self`
    ///
    /// ### Arguments
    ///
    ///* `other`  - Reference to other `Asset` to test against
    pub fn is_same_type_as(&self, other: &Asset) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }

    /// Creates a default asset of a given variant.
    /// TODO: Add handling for `Data` asset variant
    ///
    /// ### Arguments
    ///
    ///* `asset_type`          - Default asset variant type
    pub fn default_of_type(asset_type: &Self) -> Self {
        match asset_type {
            Self::Token(_) => Self::Token(Default::default()),
            Self::Receipt(receipt) => Self::receipt(
                Default::default(),
                receipt.drs_tx_hash.clone(),
                receipt.metadata.clone(),
            ),
            _ => panic!("Cannot create default of asset type: {:?}", asset_type),
        }
    }

    pub fn is_token(&self) -> bool {
        matches!(self, Asset::Token(_))
    }

    pub fn is_receipt(&self) -> bool {
        matches!(self, Asset::Receipt(_))
    }

    pub fn token_amount(&self) -> TokenAmount {
        match self {
            Asset::Token(v) => *v,
            _ => TokenAmount(0),
        }
    }

    pub fn receipt_amount(&self) -> u64 {
        match self {
            Asset::Receipt(v) => v.amount,
            _ => 0,
        }
    }
}

/// `AssetValue` struct used to represent the a running total of `Token` and `Receipt` assets
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetValues {
    pub tokens: TokenAmount,
    // Note: Receipts from create transactions will have `drs_tx_hash` = `t_hash`
    pub receipts: BTreeMap<String, u64>, /* `drs_tx_hash` - amount */
    pub data: BTreeMap<String, u64>,     /* `drs_tx_hash` - amount */
}

impl ops::AddAssign for AssetValues {
    fn add_assign(&mut self, rhs: Self) {
        self.tokens += rhs.tokens;
        add_btreemap(&mut self.receipts, rhs.receipts);
    }
}

impl AssetValues {
    pub fn new(
        tokens: TokenAmount,
        receipts: BTreeMap<String, u64>,
        data: BTreeMap<String, u64>,
    ) -> Self {
        Self {
            tokens,
            receipts,
            data,
        }
    }

    pub fn token_u64(tokens: u64) -> Self {
        AssetValues::new(TokenAmount(tokens), Default::default(), Default::default())
    }

    pub fn receipt(receipts: BTreeMap<String, u64>) -> Self {
        AssetValues::new(TokenAmount(0), receipts, Default::default())
    }

    pub fn data(data: BTreeMap<String, u64>) -> Self {
        AssetValues::new(TokenAmount(0), Default::default(), data)
    }

    pub fn is_empty(&self) -> bool {
        self == &AssetValues::default()
    }

    pub fn is_equal(&self, rhs: &AssetValues) -> bool {
        self.tokens == rhs.tokens && self.receipts == rhs.receipts
    }

    // See if the running total is enough for a required `Asset` amount
    pub fn has_enough(&self, asset_required: &Asset) -> bool {
        match asset_required {
            Asset::Token(tokens) => self.tokens >= *tokens,
            Asset::Receipt(receipts) => {
                if let Some(drs_tx_hash) = &receipts.drs_tx_hash {
                    self.receipts
                        .get(drs_tx_hash)
                        .map_or(false, |amount| *amount >= receipts.amount)
                } else {
                    false
                }
            }
            Asset::ERD(erd) => match erd {
                ERDType::SDV1 {
                    amount: _amount,
                    data_hash: _data_hash,
                    data_hash_mr: _data_hash_mr,
                    perm_table: _perm_table,
                    associated_data: _associated_data,
                    drs_tx_hash,
                } => {
                    if let Some(drs_tx_hash) = drs_tx_hash {
                        self.data
                            .get(drs_tx_hash)
                            .map_or(false, |amount| *amount >= *amount)
                    } else {
                        false
                    }
                }
            },
        }
    }

    /// Add the `rhs` parameter to `self`
    pub fn update_add(&mut self, rhs: &Asset) {
        match rhs {
            Asset::Token(tokens) => self.tokens += *tokens,
            Asset::Receipt(receipts) => {
                if let Some(drs_tx_hash) = &receipts.drs_tx_hash {
                    self.receipts
                        .entry(drs_tx_hash.clone())
                        .and_modify(|amount| *amount += receipts.amount)
                        .or_insert(receipts.amount);
                }
            }
            _ => {}
        }
    }

    // Subtract the `rhs` parameter from `self`
    pub fn update_sub(&mut self, rhs: &Asset) {
        match rhs {
            Asset::Token(tokens) => self.tokens -= *tokens,
            Asset::Receipt(receipts) => {
                receipts.drs_tx_hash.as_ref().and_then(|drs_tx_hash| {
                    self.receipts
                        .get_mut(drs_tx_hash)
                        .map(|amount| *amount -= receipts.amount)
                });
            }
            _ => {}
        }
    }
}
