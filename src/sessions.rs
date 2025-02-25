use base64::engine::general_purpose;
use base64::Engine;
use libpep::high_level::contexts::EncryptionContext;
use paas_api::status::SystemId;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct EncryptionContexts(pub HashMap<SystemId, EncryptionContext>);
impl EncryptionContexts {
    pub fn get(&self, system_id: &SystemId) -> Option<&EncryptionContext> {
        self.0.get(system_id)
    }
    pub fn encode(&self) -> String {
        let json_string = serde_json::to_string(&self.0).unwrap();
        general_purpose::URL_SAFE.encode(json_string)
    }
    pub fn decode(s: &str) -> Option<Self> {
        let bytes = general_purpose::URL_SAFE.decode(s.as_bytes()).ok()?;
        let json_string = String::from_utf8(bytes).ok()?;
        let map: HashMap<String, EncryptionContext> = serde_json::from_str(&json_string).ok()?;
        Some(Self(map))
    }
}

impl Serialize for EncryptionContexts {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.encode().serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for EncryptionContexts {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::decode(&s).ok_or(Error::custom("Failed to decode EncryptionContexts"))
    }
}
