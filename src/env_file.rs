use crate::registry;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const MAX_BYTES: u64 = 1024 * 1024;
const MAX_VARIABLES: usize = 256;

pub fn read(path: &str) -> Result<BTreeMap<String, String>, String> {
    registry::absolute_path(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(Path::new(path))
        .map_err(|_| "could not open reference file")?;
    let metadata = file
        .metadata()
        .map_err(|_| "could not inspect reference file")?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return Err("reference file must be a regular file under 1 MiB".into());
    }
    let mut contents = String::new();
    file.take(MAX_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|_| "could not read reference file as UTF-8")?;
    if contents.len() as u64 > MAX_BYTES {
        return Err("reference file exceeds 1 MiB".into());
    }
    parse(&contents)
}

fn parse(contents: &str) -> Result<BTreeMap<String, String>, String> {
    let mut entries = BTreeMap::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (variable, reference) = line
            .split_once('=')
            .ok_or_else(|| format!("reference file line {} must be NAME=op://...", index + 1))?;
        let variable = variable.trim();
        registry::env_name(variable)?;
        if variable == "PATH" || variable.starts_with("DYLD_") || variable.starts_with("LD_") {
            return Err(format!(
                "reference file line {} uses a reserved variable name",
                index + 1
            ));
        }
        let reference = reference.trim();
        let reference = if reference.len() >= 2
            && ((reference.starts_with('"') && reference.ends_with('"'))
                || (reference.starts_with('\'') && reference.ends_with('\'')))
        {
            &reference[1..reference.len() - 1]
        } else {
            reference
        };
        if !reference.starts_with("op://")
            || reference.len() <= 5
            || reference.len() > 1024
            || reference.chars().any(char::is_control)
        {
            return Err(format!(
                "reference file line {} must contain only an op:// reference",
                index + 1
            ));
        }
        if entries
            .insert(variable.to_owned(), reference.to_owned())
            .is_some()
        {
            return Err(format!(
                "duplicate variable on reference file line {}",
                index + 1
            ));
        }
        if entries.len() > MAX_VARIABLES {
            return Err("reference file has too many variables".into());
        }
    }
    if entries.is_empty() {
        return Err("reference file has no variables".into());
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn accepts_only_reference_mappings() {
        let entries = parse("# comment\nexport TOKEN='op://Vault/Item/Field'\n").unwrap();
        assert_eq!(entries["TOKEN"], "op://Vault/Item/Field");
        assert!(parse("TOKEN=plaintext").is_err());
        assert!(parse("TOKEN=op://Vault/Item/Field\nTOKEN=op://Vault/Item/Other").is_err());
        assert!(parse("BAD-NAME=op://Vault/Item/Field").is_err());
        assert!(parse("TOKEN=op://Vault/Item/Field\nOTHER=$(echo value)").is_err());
    }

    #[test]
    fn accepts_spaces_within_1password_reference_components() {
        let entries = parse(
            "API_KEY=op://Project Vault/Admin Credentials/API Key\n\
             OTHER='op://Project Vault/Other Credentials/Secret Value'\n",
        )
        .unwrap();
        assert_eq!(
            entries["API_KEY"],
            "op://Project Vault/Admin Credentials/API Key"
        );
        assert_eq!(
            entries["OTHER"],
            "op://Project Vault/Other Credentials/Secret Value"
        );
    }
}
