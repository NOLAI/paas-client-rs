use libpep::data::json::EncryptedPEPJSONValue;
use libpep::data::long::{LongEncryptedAttribute, LongEncryptedPseudonym};
use libpep::data::records::{EncryptedRecord, LongEncryptedRecord};
use libpep::data::simple::{EncryptedAttribute, EncryptedPseudonym};
use serde::{Deserialize, Serialize};

/// Error when converting variant back to a specific type
#[derive(Debug, Clone, thiserror::Error)]
pub enum VariantConversionError {
    #[error("Expected Normal variant, got Long")]
    ExpectedNormal,
    #[error("Expected Long variant, got Normal")]
    ExpectedLong,
    #[error("Expected EncryptedRecord variant")]
    ExpectedData,
    #[error("Expected LongEncryptedRecord variant")]
    ExpectedLongData,
    #[error("Expected EncryptedPEPJSONValue variant")]
    ExpectedJson,
}

/// Variant enum for polymorphic pseudonym handling
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EncryptedPseudonymVariant {
    Normal(Box<EncryptedPseudonym>),
    Long(LongEncryptedPseudonym),
}

impl From<EncryptedPseudonym> for EncryptedPseudonymVariant {
    fn from(ep: EncryptedPseudonym) -> Self {
        EncryptedPseudonymVariant::Normal(Box::new(ep))
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
            EncryptedPseudonymVariant::Normal(ep) => Ok(*ep),
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
    Normal(Box<EncryptedAttribute>),
    Long(LongEncryptedAttribute),
}

impl From<EncryptedAttribute> for EncryptedAttributeVariant {
    fn from(ea: EncryptedAttribute) -> Self {
        EncryptedAttributeVariant::Normal(Box::new(ea))
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
            EncryptedAttributeVariant::Normal(ea) => Ok(*ea),
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
pub enum EncryptedRecordVariant {
    Normal(EncryptedRecord),
    Long(LongEncryptedRecord),
    Json(Box<EncryptedPEPJSONValue>),
}

impl From<EncryptedRecord> for EncryptedRecordVariant {
    fn from(ed: EncryptedRecord) -> Self {
        EncryptedRecordVariant::Normal(ed)
    }
}

impl From<LongEncryptedRecord> for EncryptedRecordVariant {
    fn from(led: LongEncryptedRecord) -> Self {
        EncryptedRecordVariant::Long(led)
    }
}

impl From<EncryptedPEPJSONValue> for EncryptedRecordVariant {
    fn from(ejson: EncryptedPEPJSONValue) -> Self {
        EncryptedRecordVariant::Json(Box::new(ejson))
    }
}

impl TryFrom<EncryptedRecordVariant> for EncryptedRecord {
    type Error = VariantConversionError;
    fn try_from(variant: EncryptedRecordVariant) -> Result<Self, Self::Error> {
        match variant {
            EncryptedRecordVariant::Normal(ed) => Ok(ed),
            _ => Err(VariantConversionError::ExpectedData),
        }
    }
}

impl TryFrom<EncryptedRecordVariant> for LongEncryptedRecord {
    type Error = VariantConversionError;
    fn try_from(variant: EncryptedRecordVariant) -> Result<Self, Self::Error> {
        match variant {
            EncryptedRecordVariant::Long(led) => Ok(led),
            _ => Err(VariantConversionError::ExpectedLongData),
        }
    }
}

impl TryFrom<EncryptedRecordVariant> for EncryptedPEPJSONValue {
    type Error = VariantConversionError;
    fn try_from(variant: EncryptedRecordVariant) -> Result<Self, Self::Error> {
        match variant {
            EncryptedRecordVariant::Json(ejson) => Ok(*ejson),
            _ => Err(VariantConversionError::ExpectedJson),
        }
    }
}
