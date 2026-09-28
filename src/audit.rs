use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const LOG_LIMIT: u64 = 10 * 1024 * 1024;
const MAX_FILES: usize = 5;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Event<'a> {
    pub time_ms: u128,
    pub request_id: Option<String>,
    pub client: &'a str,
    pub identity: &'a str,
    pub project: Option<&'a str>,
    pub tool: &'a str,
    pub decision: &'a str,
    pub duration_ms: u128,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub executable: Option<&'a str>,
}

impl<'a> Event<'a> {
    pub fn now(
        client: &'a str,
        identity: &'a str,
        project: Option<&'a str>,
        tool: &'a str,
        decision: &'a str,
    ) -> Self {
        let time_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        Self {
            time_ms,
            request_id: None,
            client,
            identity,
            project,
            tool,
            decision,
            duration_ms: 0,
            exit_code: None,
            timed_out: false,
            executable: None,
        }
    }
}

pub struct Audit {
    directory: PathBuf,
    limit: u64,
    lock: Mutex<()>,
}

impl Audit {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            directory: crate::storage::config_dir()?,
            limit: LOG_LIMIT,
            lock: Mutex::new(()),
        })
    }

    #[cfg(test)]
    pub fn in_dir(directory: PathBuf, limit: u64) -> Self {
        Self {
            directory,
            limit,
            lock: Mutex::new(()),
        }
    }

    pub fn record(&self, event: &Event<'_>) -> Result<(), String> {
        assert_private_directory(&self.directory)?;
        let mut bytes = serde_json::to_vec(event).map_err(|_| "could not encode audit event")?;
        bytes.push(b'\n');
        if bytes.len() as u64 > self.limit {
            return Err("audit event exceeds file limit".into());
        }
        let _guard = self.lock.lock().map_err(|_| "audit lock failed")?;
        let current = self.path(0);
        let size = match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                check(&metadata)?;
                metadata.len()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(_) => return Err("could not inspect audit file".into()),
        };
        if size + bytes.len() as u64 > self.limit {
            self.rotate()?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(current)
            .map_err(|_| "could not open audit file")?;
        check(
            &file
                .metadata()
                .map_err(|_| "could not inspect audit file")?,
        )?;
        file.write_all(&bytes)
            .map_err(|_| "could not write audit event")?;
        file.sync_data().map_err(|_| "could not sync audit event")?;
        Ok(())
    }

    fn path(&self, index: usize) -> PathBuf {
        self.directory.join(if index == 0 {
            "audit.jsonl".to_string()
        } else {
            format!("audit.{index}.jsonl")
        })
    }

    fn rotate(&self) -> Result<(), String> {
        for index in (0..MAX_FILES).rev() {
            let path = self.path(index);
            match fs::symlink_metadata(&path) {
                Ok(metadata) => check(&metadata)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err("could not inspect audit rotation file".into()),
            }
            if index == MAX_FILES - 1 {
                fs::remove_file(path).map_err(|_| "could not remove oldest audit file")?;
            } else {
                fs::rename(path, self.path(index + 1))
                    .map_err(|_| "could not rotate audit file")?;
            }
        }
        Ok(())
    }
}

fn check(metadata: &fs::Metadata) -> Result<(), String> {
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err("audit file is not a private regular file".into());
    }
    Ok(())
}

pub fn assert_private_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "could not inspect audit directory")?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err("audit directory is not private".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Audit, Event};
    use rand_core::{OsRng, RngCore};
    use std::fs::{self, DirBuilder};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    #[test]
    fn rotates_and_keeps_five_private_files() {
        let dir = std::env::temp_dir().join(format!(
            "larp-audit-test-{}-{}",
            std::process::id(),
            OsRng.next_u64()
        ));
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let audit = Audit::in_dir(dir.clone(), 512);
        for _ in 0..20 {
            audit
                .record(&Event::now(
                    "dummy",
                    "signed",
                    Some("demo"),
                    "exec",
                    "denied",
                ))
                .unwrap();
        }
        let files: Vec<_> = fs::read_dir(&dir).unwrap().collect();
        assert!(files.len() <= 5);
        assert!(files.len() >= 2);
        for file in files {
            let path = file.unwrap().path();
            let content = fs::read_to_string(&path).unwrap();
            assert!(!content.contains("secret-value"));
            let metadata = fs::metadata(&path).unwrap();
            assert!(metadata.len() <= 512);
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
