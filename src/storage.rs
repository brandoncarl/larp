//! Private local files for registry metadata and the admin password verifier.
use rand_core::{OsRng, RngCore};
use std::ffi::CStr;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const REGISTRY_FILE: &str = "registry.json";
const ADMIN_FILE: &str = "admin.phc";
const MAX_BYTES: usize = 1024 * 1024;

pub(crate) fn home_dir() -> Result<PathBuf, String> {
    let uid = unsafe { libc::geteuid() };
    let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut buffer = vec![0u8; 4096];
    let mut result = std::ptr::null_mut();
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() || entry.pw_dir.is_null() {
        return Err("could not find the current user's home directory".into());
    }
    let path = unsafe { CStr::from_ptr(entry.pw_dir) };
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(path.to_bytes())))
}

fn ensure_private_dir(path: &Path) -> Result<(), String> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err("could not create LARP configuration directory".into()),
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "could not inspect LARP configuration directory")?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err("LARP configuration directory is not private to this user".into());
    }
    Ok(())
}

fn new_dir() -> Result<PathBuf, String> {
    let base = home_dir()?.join(".config");
    match DirBuilder::new().mode(0o700).create(&base) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err("could not create ~/.config".into()),
    }
    let metadata = fs::symlink_metadata(&base).map_err(|_| "could not inspect ~/.config")?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err("~/.config is not a safe user-owned directory".into());
    }
    let path = base.join("larp");
    ensure_private_dir(&path)?;
    Ok(path)
}

fn legacy_dir() -> Result<Option<PathBuf>, String> {
    let path = home_dir()?.join("Library/Application Support/LARP");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.permissions().mode() & 0o777 != 0o700
            {
                return Err("legacy LARP directory is not private to this user".into());
            }
            Ok(Some(path))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("could not inspect legacy LARP directory".into()),
    }
}

fn check_file(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "could not inspect LARP data file")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() > MAX_BYTES as u64
    {
        return Err("LARP data file is not a private regular file".into());
    }
    Ok(())
}

fn read_at(dir: &Path, name: &str) -> Result<Option<Vec<u8>>, String> {
    let path = dir.join(name);
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("could not open LARP data file".into()),
    };
    let metadata = file
        .metadata()
        .map_err(|_| "could not inspect LARP data file")?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() > MAX_BYTES as u64
    {
        return Err("LARP data file is not a private regular file".into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read LARP data file")?;
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err("invalid LARP data file size".into());
    }
    Ok(Some(bytes))
}

fn write_at(dir: &Path, name: &str, bytes: &[u8], replace: bool) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err("invalid LARP data size".into());
    }
    let destination = dir.join(name);
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            if !replace {
                return Err("LARP destination already exists".into());
            }
            check_file(&destination)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("could not inspect LARP destination file".into()),
    }
    let nonce = OsRng.next_u64();
    let temporary = dir.join(format!(".{name}.{}.{}", std::process::id(), nonce));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|_| "could not create temporary LARP data file")?;
        file.write_all(bytes)
            .map_err(|_| "could not write LARP data file")?;
        file.sync_all()
            .map_err(|_| "could not sync LARP data file")?;
        if replace {
            fs::rename(&temporary, &destination).map_err(|_| "could not replace LARP data file")?;
        } else {
            fs::hard_link(&temporary, &destination)
                .map_err(|_| "could not migrate LARP data file")?;
            fs::remove_file(&temporary).map_err(|_| "could not clear LARP migration temp file")?;
        }
        File::open(dir)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "could not sync LARP configuration directory")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn migrate_at(new: &Path, old: &Path) -> Result<(), String> {
    for name in [REGISTRY_FILE, ADMIN_FILE] {
        let Some(mut old_bytes) = read_at(old, name)? else {
            continue;
        };
        match read_at(new, name)? {
            None => write_at(new, name, &old_bytes, false)?,
            Some(new_bytes) if new_bytes == old_bytes => {}
            Some(_) => {
                return Err(format!(
                    "conflicting {name} in legacy and new LARP directories; resolve manually"
                ))
            }
        }
        old_bytes.fill(0);
        fs::remove_file(old.join(name)).map_err(|_| "could not remove migrated LARP data file")?;
        File::open(old)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "could not sync legacy LARP directory")?;
    }
    match fs::remove_dir(old) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::NotFound
            ) => {}
        Err(_) => return Err("could not remove empty legacy LARP directory".into()),
    }
    Ok(())
}

fn private_dir() -> Result<PathBuf, String> {
    let new = new_dir()?;
    if let Some(old) = legacy_dir()? {
        migrate_at(&new, &old)?;
    }
    Ok(new)
}

fn read(name: &str) -> Result<Option<Vec<u8>>, String> {
    read_at(&private_dir()?, name)
}

fn write(name: &str, bytes: &[u8]) -> Result<(), String> {
    write_at(&private_dir()?, name, bytes, true)
}

pub fn load_registry() -> Result<Option<Vec<u8>>, String> {
    read(REGISTRY_FILE)
}
pub fn save_registry(bytes: &[u8]) -> Result<(), String> {
    write(REGISTRY_FILE, bytes)
}
pub fn load_admin() -> Result<Option<Vec<u8>>, String> {
    read(ADMIN_FILE)
}
pub fn save_admin(bytes: &[u8]) -> Result<(), String> {
    write(ADMIN_FILE, bytes)
}

pub fn config_dir() -> Result<PathBuf, String> {
    private_dir()
}

#[cfg(test)]
mod tests {
    use super::{migrate_at, read_at, write_at, ADMIN_FILE, REGISTRY_FILE};
    use rand_core::{OsRng, RngCore};
    use std::fs::{self, DirBuilder};
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::DirBuilderExt;

    fn dirs() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "larp-storage-test-{}-{}",
            std::process::id(),
            OsRng.next_u64()
        ));
        let old = root.join("old");
        let new = root.join("new");
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        DirBuilder::new().mode(0o700).create(&old).unwrap();
        DirBuilder::new().mode(0o700).create(&new).unwrap();
        (root, old, new)
    }

    #[test]
    fn migrates_both_files_without_overwriting() {
        let (root, old, new) = dirs();
        write_at(&old, REGISTRY_FILE, b"registry", false).unwrap();
        write_at(&old, ADMIN_FILE, b"verifier", false).unwrap();
        migrate_at(&new, &old).unwrap();
        assert_eq!(read_at(&new, REGISTRY_FILE).unwrap().unwrap(), b"registry");
        assert_eq!(read_at(&new, ADMIN_FILE).unwrap().unwrap(), b"verifier");
        assert!(read_at(&old, REGISTRY_FILE).unwrap().is_none());
        assert!(read_at(&old, ADMIN_FILE).unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_conflicting_destination() {
        let (root, old, new) = dirs();
        write_at(&old, REGISTRY_FILE, b"old", false).unwrap();
        write_at(&new, REGISTRY_FILE, b"new", false).unwrap();
        assert!(migrate_at(&new, &old).is_err());
        assert_eq!(read_at(&old, REGISTRY_FILE).unwrap().unwrap(), b"old");
        assert_eq!(read_at(&new, REGISTRY_FILE).unwrap().unwrap(), b"new");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_symlink_destination() {
        let (root, _old, new) = dirs();
        let target = root.join("target");
        fs::write(&target, b"untouched").unwrap();
        symlink(&target, new.join(REGISTRY_FILE)).unwrap();
        assert!(write_at(&new, REGISTRY_FILE, b"replacement", true).is_err());
        assert_eq!(fs::read(target).unwrap(), b"untouched");
        fs::remove_dir_all(root).unwrap();
    }
}
