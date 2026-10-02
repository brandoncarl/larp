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

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

impl Registry {
    pub fn rename_project(&mut self, old: &str, new: &str) -> Result<(), String> {
        name(new)?;
        if !self.projects.contains_key(old) {
            return Err("project does not exist".into());
        }
        if self.projects.contains_key(new) {
            return Err("project name is already in use".into());
        }
        let project = self.projects.remove(old).expect("project checked above");
        self.projects.insert(new.to_owned(), project);
        for client in self.clients.values_mut() {
            rename_grants(&mut client.commands, old, new);
            rename_grants(&mut client.secrets, old, new);
            if client.exec.remove(old) {
                client.exec.insert(new.to_owned());
            }
        }
        Ok(())
    }

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
        let mut matches = self
            .clients
            .iter()
            .filter(|(_, client)| process_matches(&client.process, path));
        let (name, client) = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some((name.as_str(), client))
    }
}

/// Only `*` is special; it never consumes a path separator.
pub(crate) fn process_matches(pattern: &str, path: &str) -> bool {
    let pattern: Vec<_> = pattern.split('/').collect();
    let path: Vec<_> = path.split('/').collect();
    pattern.len() == path.len()
        && pattern
            .iter()
            .zip(path)
            .all(|(pattern, value)| component_matches(pattern, value))
}

pub(crate) fn component_matches(pattern: &str, value: &str) -> bool {
    let (pattern, value) = (pattern.as_bytes(), value.as_bytes());
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if p < pattern.len() && pattern[p] == value[v] {
            p += 1;
            v += 1;
        } else if let Some(index) = star {
            retry += 1;
            v = retry;
            p = index + 1;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn rename_grants(grants: &mut BTreeSet<(String, String)>, old: &str, new: &str) {
    *grants = std::mem::take(grants)
        .into_iter()
        .map(|(project, name)| {
            (
                if project == old {
                    new.to_owned()
                } else {
                    project
                },
                name,
            )
        })
        .collect();
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
    use super::{Client, ClientIdentity, Project, RegisteredCommand, Registry};
    use std::collections::BTreeSet;

    #[test]
    fn client_wildcards_are_confined_to_components() {
        let pattern = "/releases/*/bin/codex";
        assert!(super::process_matches(
            pattern,
            "/releases/0.159.2-arm64/bin/codex"
        ));
        assert!(super::process_matches(
            pattern,
            "/releases/backup/bin/codex"
        ));
        assert!(!super::process_matches(
            pattern,
            "/releases/other/version/bin/codex"
        ));
        assert!(!super::process_matches(
            pattern,
            "/releases/version/bin/other"
        ));
        assert!(super::process_matches(
            "/releases/*-arm64/bin/codex",
            "/releases/1.0-arm64/bin/codex"
        ));
        assert!(!super::process_matches(
            "/releases/*-arm64/bin/codex",
            "/releases/1.0-intel/bin/codex"
        ));
        assert!(super::component_matches("a*b*c", "axybzc"));
        assert!(!super::component_matches("a*b*c", "axybz"));
    }

    #[test]
    fn ambiguous_client_paths_are_not_authorized() {
        let mut registry = Registry::default();
        for (name, process) in [
            ("wide", "/releases/*/bin/codex"),
            ("narrow", "/releases/1.0/bin/codex"),
        ] {
            registry.clients.insert(
                name.into(),
                Client {
                    process: process.into(),
                    identity: ClientIdentity::PathOnly,
                    commands: BTreeSet::new(),
                    secrets: BTreeSet::new(),
                    exec: BTreeSet::new(),
                },
            );
        }
        assert!(registry
            .client_for_process("/releases/1.0/bin/codex")
            .is_none());
        assert_eq!(
            registry
                .client_for_process("/releases/2.0/bin/codex")
                .unwrap()
                .0,
            "wide"
        );
    }

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

    #[test]
    fn rename_project_moves_commands_secrets_and_client_grants() {
        let mut registry = Registry::default();
        let mut project = Project {
            cwd: "/tmp/example".into(),
            ..Project::default()
        };
        project.commands.insert(
            "check".into(),
            RegisteredCommand {
                argv: vec!["/bin/echo".into(), "ok".into()],
                cwd: "/tmp/example".into(),
                env: Default::default(),
            },
        );
        project
            .secrets
            .insert("token".into(), "op://vault/item/field".into());
        registry.projects.insert("old".into(), project);
        registry.projects.insert("other".into(), Project::default());
        registry.clients.insert(
            "agent".into(),
            Client {
                process: "/bin/true".into(),
                identity: ClientIdentity::PathOnly,
                commands: BTreeSet::from([
                    ("old".into(), "check".into()),
                    ("other".into(), "keep".into()),
                ]),
                secrets: BTreeSet::from([("old".into(), "token".into())]),
                exec: BTreeSet::from(["old".into(), "other".into()]),
            },
        );
        registry.rename_project("old", "new").unwrap();
        assert!(!registry.projects.contains_key("old"));
        assert_eq!(registry.projects["new"].cwd, "/tmp/example");
        assert!(registry.projects["new"].commands.contains_key("check"));
        assert_eq!(
            registry.projects["new"].secrets["token"],
            "op://vault/item/field"
        );
        let client = &registry.clients["agent"];
        assert!(client.commands.contains(&("new".into(), "check".into())));
        assert!(client.commands.contains(&("other".into(), "keep".into())));
        assert!(client.secrets.contains(&("new".into(), "token".into())));
        assert_eq!(client.exec, BTreeSet::from(["new".into(), "other".into()]));
    }

    #[test]
    fn rename_project_rejects_invalid_changes_without_mutation() {
        let mut registry = Registry::default();
        registry.projects.insert("old".into(), Project::default());
        registry.projects.insert("taken".into(), Project::default());
        assert!(registry.rename_project("missing", "new").is_err());
        assert!(registry.rename_project("old", "bad name").is_err());
        assert!(registry.rename_project("old", "taken").is_err());
        assert_eq!(registry.projects.len(), 2);
        assert!(registry.projects.contains_key("old"));
        assert!(registry.projects.contains_key("taken"));
    }
}
