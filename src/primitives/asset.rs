use crate::utils::format_for_display;
use serde::{Deserialize, Serialize};
use std::{fmt, iter, mem::size_of, ops};

/// A structure representing the amount of tokens in an instance
#[derive(Deserialize, Serialize, Default, Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct TokenAmount(pub u64);

impl fmt::Display for TokenAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let format_result = format_for_display(&self.0);
        write!(f, "{}", format_result)
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

/// Data asset struct
#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct DataAsset {
    pub data: Vec<u8>,
    pub amount: u64,
}

/// Asset struct
///
/// * `Token`   - An asset struct representation of the ZNT token
/// * `Data`    - A data asset
/// * `Receipt` - A receipt for a payment. The value indicates the number of receipt assets
#[derive(Deserialize, Serialize, Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum Asset {
    Token(TokenAmount),
    Data(DataAsset),
    Receipt(u64),
}

impl Default for Asset {
    fn default() -> Self {
        Asset::Token(Default::default())
    }
}

impl Asset {
    // Get a string representation of the `Asset` type (e.g. "Receipt")
    pub fn string_name(&self) -> String {
        match self {
            Asset::Token(_) => "Token".to_string(),
            Asset::Data(_) => "Data".to_string(),
            Asset::Receipt(_) => "Receipt".to_string(),
        }
    }

    // Get a u64 representation of the amount for an `Asset`
    pub fn amount(&self) -> u64 {
        match self {
            Asset::Token(amount) => amount.0,
            Asset::Data(data) => data.amount,
            Asset::Receipt(amount) => *amount,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Asset::Token(_) => size_of::<TokenAmount>(),
            Asset::Data(d) => d.data.len(),
            Asset::Receipt(_) => size_of::<u64>(),
        }
    }

    pub fn token_u64(amount: u64) -> Self {
        Asset::Token(TokenAmount(amount))
    }

    /// Add an asset of the same variant to `self` asset.
    /// TODO: Add handling for `Data` asset variant. Will return false when `Data` asset is presented.
    ///
    /// ### Arguments
    ///
    ///* `rhs`          - The right-hand-side (RHS) asset to add to `self`
    pub fn add_assign(&mut self, rhs: &Self) -> bool {
        match (&self, &rhs) {
            (Asset::Token(lhs_tokens), Asset::Token(rhs_tokens)) => {
                *self = Asset::Token(*lhs_tokens + *rhs_tokens);
                true
            }
            (Asset::Receipt(lhs_receipts), Asset::Receipt(rhs_receipts)) => {
                *self = Asset::Receipt(*lhs_receipts + *rhs_receipts);
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
            (Asset::Receipt(lhs_receipt_amount), Asset::Receipt(rhs_receipt_amount)) => {
                Some(lhs_receipt_amount >= rhs_receipt_amount)
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
                if lhs_receipts > rhs_receipts {
                    Some(Asset::Receipt(*lhs_receipts - *rhs_receipts))
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
            Self::Receipt(_) => Self::Receipt(Default::default()),
            _ => panic!("Cannot create default of asset type: {:?}", asset_type),
        }
    }

    pub fn is_token(&self) -> bool {
        matches!(self, Asset::Token(_))
    }

    pub fn is_receipt(&self) -> bool {
        matches!(self, Asset::Receipt(_))
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Asset::Data(d) => d.data.is_empty(),
            _ => false,
        }
    }

    pub fn token_amount(&self) -> TokenAmount {
        match self {
            Asset::Token(v) => *v,
            _ => TokenAmount(0),
        }
    }

    pub fn receipt_amount(&self) -> u64 {
        match self {
            Asset::Receipt(v) => *v,
            _ => 0,
        }
    }
}
