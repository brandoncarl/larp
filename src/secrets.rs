use std::process::{Command, Stdio};
use zeroize::{Zeroize, Zeroizing};

pub fn read(reference: &str) -> Result<Zeroizing<String>, String> {
    let output = Command::new("op")
        .args(["read", "--no-newline", reference])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "could not start the 1Password CLI")?;
    let mut bytes = output.stdout;
    if !output.status.success() {
        bytes.zeroize();
        return Err("1Password CLI could not load an approved key".into());
    }
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        bytes.zeroize();
        return Err("1Password returned an empty or oversized key".into());
    }
    let value = String::from_utf8(bytes).map_err(|error| {
        error.into_bytes().zeroize();
        "1Password returned a key that is not UTF-8"
    })?;
    Ok(Zeroizing::new(value))
}
