use crate::storage;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    #[serde(default = "version_one")]
    version: u32,
    pub clients: BTreeMap<String, Client>,
    pub projects: BTreeMap<String, Project>,
}

fn version_one() -> u32 {
    1
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            version: 1,
            clients: BTreeMap::new(),
            projects: BTreeMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub process: String,
    #[serde(default)]
    pub identity: ClientIdentity,
    pub commands: BTreeSet<(String, String)>,
    pub secrets: BTreeSet<(String, String)>,
    #[serde(default)]
    pub exec: BTreeSet<String>,
}

#[derive(Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClientIdentity {
    Signed {
        requirement: String,
    },
    #[default]
    PathOnly,
}

impl ClientIdentity {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Signed { .. } => "signed",
            Self::PathOnly => "path-only",
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    #[serde(default)]
    pub cwd: String,
    pub commands: BTreeMap<String, RegisteredCommand>,
    pub secrets: BTreeMap<String, String>,
    #[serde(default, rename = "env", skip_serializing)]
    pub _legacy_env: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredCommand {
    pub argv: Vec<String>,
    pub cwd: String,
}

impl Registry {
    pub fn load() -> Result<Self, String> {
        let Some(mut bytes) = storage::load_registry()? else {
            return Ok(Self::default());
        };
        let result: Result<Self, String> =
            serde_json::from_slice(&bytes).map_err(|_| "invalid LARP registry".to_string());
        bytes.zeroize();
        let registry = result?;
        if registry.version != 1 {
            return Err("unsupported LARP registry version".into());
        }
        Ok(registry)
    }

    pub fn save(&self) -> Result<(), String> {
        let mut bytes = serde_json::to_vec(self).map_err(|_| "could not encode LARP registry")?;
        let result = storage::save_registry(&bytes);
        bytes.zeroize();
        result
    }

    pub fn client_for_process(&self, path: &str) -> Option<(&str, &Client)> {
        self.clients
            .iter()
            .find(|(_, client)| client.process == path)
            .map(|(name, client)| (name.as_str(), client))
    }
}

pub fn name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        Err("name must be 1–64 ASCII letters, digits, underscores, or hyphens".into())
    } else {
        Ok(())
    }
}

pub fn absolute_path(value: &str) -> Result<(), String> {
    if !Path::new(value).is_absolute() || value.contains('\0') {
        Err("path must be absolute".into())
    } else {
        Ok(())
    }
}

pub fn env_name(value: &str) -> Result<(), String> {
    let mut chars = value.chars();
    if !matches!(chars.next(), Some('A'..='Z' | '_'))
        || !chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        Err("environment variable name must use A-Z, 0-9, and underscores".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Registry;

    #[test]
    fn legacy_environment_bindings_are_ignored_and_removed_on_save() {
        let old = r#"{"version":1,"clients":{},"projects":{"demo":{"cwd":"/tmp","commands":{},"secrets":{"token":"op://Vault/Item/Field"},"env":{"TOKEN":{"secret":"token","optional":false}}}}}"#;
        let registry: Registry = serde_json::from_str(old).unwrap();
        assert_eq!(
            registry.projects["demo"].secrets["token"],
            "op://Vault/Item/Field"
        );
        let saved = serde_json::to_string(&registry).unwrap();
        assert!(!saved.contains("\"env\""));
    }
}
