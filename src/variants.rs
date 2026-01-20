use libpep::core::data::{EncryptedAttribute, EncryptedPseudonym};
use libpep::core::json::data::EncryptedPEPJSONValue;
use libpep::core::long::batch::LongEncryptedData;
use libpep::core::long::data::{LongEncryptedAttribute, LongEncryptedPseudonym};
use libpep::core::transcryption::batch::EncryptedData;
use serde::{Deserialize, Serialize};

/// Error when converting variant back to a specific type
#[derive(Debug, Clone, thiserror::Error)]
pub enum VariantConversionError {
    #[error("Expected Normal variant, got Long")]
    ExpectedNormal,
    #[error("Expected Long variant, got Normal")]
    ExpectedLong,
    #[error("Expected EncryptedData variant")]
    ExpectedData,
    #[error("Expected LongEncryptedData variant")]
    ExpectedLongData,
    #[error("Expected EncryptedPEPJSONValue variant")]
    ExpectedJson,
}

/// Variant enum for polymorphic pseudonym handling
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EncryptedPseudonymVariant {
    Normal(EncryptedPseudonym),
    Long(LongEncryptedPseudonym),
}

impl From<EncryptedPseudonym> for EncryptedPseudonymVariant {
    fn from(ep: EncryptedPseudonym) -> Self {
        EncryptedPseudonymVariant::Normal(ep)
    }
}

impl From<LongEncryptedPseudonym> for EncryptedPseudonymVariant {
    fn from(lep: LongEncryptedPseudonym) -> Self {
        EncryptedPseudonymVariant::Long(lep)
    }
}

impl TryFrom<EncryptedPseudonymVariant> for EncryptedPseudonym {
    type Error = VariantConversionError;
    fn try_from(variant: EncryptedPseudonymVariant) -> Result<Self, Self::Error> {
        match variant {
            EncryptedPseudonymVariant::Normal(ep) => Ok(ep),
            EncryptedPseudonymVariant::Long(_) => Err(VariantConversionError::ExpectedNormal),
        }
    }
}

impl TryFrom<EncryptedPseudonymVariant> for LongEncryptedPseudonym {
    type Error = VariantConversionError;
    fn try_from(variant: EncryptedPseudonymVariant) -> Result<Self, Self::Error> {
        match variant {
            EncryptedPseudonymVariant::Long(lep) => Ok(lep),
            EncryptedPseudonymVariant::Normal(_) => Err(VariantConversionError::ExpectedLong),
        }
    }
}

/// Variant enum for polymorphic attribute handling
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EncryptedAttributeVariant {
    Normal(EncryptedAttribute),
    Long(LongEncryptedAttribute),
}

impl From<EncryptedAttribute> for EncryptedAttributeVariant {
    fn from(ea: EncryptedAttribute) -> Self {
        EncryptedAttributeVariant::Normal(ea)
    }
}

impl From<LongEncryptedAttribute> for EncryptedAttributeVariant {
    fn from(lea: LongEncryptedAttribute) -> Self {
        EncryptedAttributeVariant::Long(lea)
    }
}

impl TryFrom<EncryptedAttributeVariant> for EncryptedAttribute {
    type Error = VariantConversionError;
    fn try_from(variant: EncryptedAttributeVariant) -> Result<Self, Self::Error> {
        match variant {
            EncryptedAttributeVariant::Normal(ea) => Ok(ea),
            EncryptedAttributeVariant::Long(_) => Err(VariantConversionError::ExpectedNormal),
        }
    }
}

impl TryFrom<EncryptedAttributeVariant> for LongEncryptedAttribute {
    type Error = VariantConversionError;
    fn try_from(variant: EncryptedAttributeVariant) -> Result<Self, Self::Error> {
        match variant {
            EncryptedAttributeVariant::Long(lea) => Ok(lea),
            EncryptedAttributeVariant::Normal(_) => Err(VariantConversionError::ExpectedLong),
        }
    }
}

/// Variant enum for polymorphic data handling
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EncryptedDataVariant {
    Normal(EncryptedData),
    Long(LongEncryptedData),
    Json(EncryptedPEPJSONValue),
}

impl From<EncryptedData> for EncryptedDataVariant {
    fn from(ed: EncryptedData) -> Self {
        EncryptedDataVariant::Normal(ed)
    }
}

impl From<LongEncryptedData> for EncryptedDataVariant {
    fn from(led: LongEncryptedData) -> Self {
        EncryptedDataVariant::Long(led)
    }
}

impl From<EncryptedPEPJSONValue> for EncryptedDataVariant {
    fn from(ejson: EncryptedPEPJSONValue) -> Self {
        EncryptedDataVariant::Json(ejson)
    }
}

impl TryFrom<EncryptedDataVariant> for EncryptedData {
    type Error = VariantConversionError;
    fn try_from(variant: EncryptedDataVariant) -> Result<Self, Self::Error> {
        match variant {
            EncryptedDataVariant::Normal(ed) => Ok(ed),
            _ => Err(VariantConversionError::ExpectedData),
        }
    }
}

impl TryFrom<EncryptedDataVariant> for LongEncryptedData {
    type Error = VariantConversionError;
    fn try_from(variant: EncryptedDataVariant) -> Result<Self, Self::Error> {
        match variant {
            EncryptedDataVariant::Long(led) => Ok(led),
            _ => Err(VariantConversionError::ExpectedLongData),
        }
    }
}

impl TryFrom<EncryptedDataVariant> for EncryptedPEPJSONValue {
    type Error = VariantConversionError;
    fn try_from(variant: EncryptedDataVariant) -> Result<Self, Self::Error> {
        match variant {
            EncryptedDataVariant::Json(ejson) => Ok(ejson),
            _ => Err(VariantConversionError::ExpectedJson),
        }
    }
}
