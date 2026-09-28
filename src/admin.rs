use crate::{cli, storage};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use zeroize::{Zeroize, Zeroizing};

const MIN_PASSWORD_CHARS: usize = 12;
const MAX_PASSWORD_BYTES: usize = 4096;
const IDLE_SECONDS: i32 = 15 * 60;

pub struct AdminSession {
    _private: (),
}

fn hasher() -> Result<Argon2<'static>, String> {
    let params = Params::new(19 * 1024, 2, 1, None)
        .map_err(|_| "invalid admin password hashing parameters")?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    hasher()?
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| "could not hash admin password".into())
}

fn verify(password: &str, encoded: &[u8]) -> Result<bool, String> {
    let encoded = std::str::from_utf8(encoded).map_err(|_| "invalid admin verifier")?;
    let parsed = PasswordHash::new(encoded).map_err(|_| "invalid admin verifier")?;
    Ok(hasher()?
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

pub fn authenticate_existing() -> Result<AdminSession, String> {
    let Some(mut encoded) = storage::load_admin()? else {
        return Err("admin password is not set; run 'larp admin' first".into());
    };
    let password = read_password("Password: ")?;
    let valid = verify(&password, &encoded)?;
    encoded.zeroize();
    if !valid {
        return Err("incorrect admin password".into());
    }
    Ok(AdminSession { _private: () })
}

fn unlock_or_setup() -> Result<AdminSession, String> {
    if storage::load_admin()?.is_some() {
        return authenticate_existing();
    }
    println!("Set a LARP admin password. It will protect registry management.");
    let first = read_password("New password: ")?;
    validate_new_password(&first)?;
    let second = read_password("Confirm new password: ")?;
    if first != second {
        return Err("passwords did not match".into());
    }
    let mut encoded = hash_password(&first)?;
    let result = storage::save_admin(encoded.as_bytes());
    encoded.zeroize();
    result?;
    Ok(AdminSession { _private: () })
}

fn validate_new_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!(
            "admin password must be at least {MIN_PASSWORD_CHARS} characters"
        ));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err("admin password is too long".into());
    }
    Ok(())
}

fn change_password(_: &AdminSession) -> Result<(), String> {
    let Some(mut encoded) = storage::load_admin()? else {
        return Err("admin password is not set".into());
    };
    let current = read_password("Current password: ")?;
    let valid = verify(&current, &encoded)?;
    encoded.zeroize();
    if !valid {
        return Err("incorrect admin password".into());
    }
    let first = read_password("New password: ")?;
    validate_new_password(&first)?;
    let second = read_password("Confirm new password: ")?;
    if first != second {
        return Err("passwords did not match".into());
    }
    let mut replacement = hash_password(&first)?;
    let result = storage::save_admin(replacement.as_bytes());
    replacement.zeroize();
    result?;
    println!("Admin password changed.");
    Ok(())
}

fn read_password(label: &str) -> Result<Zeroizing<String>, String> {
    let password = Zeroizing::new(
        rpassword::prompt_password(label)
            .map_err(|_| "admin password requires an interactive terminal")?,
    );
    if password.len() > MAX_PASSWORD_BYTES {
        return Err("admin password is too long".into());
    }
    Ok(password)
}

pub fn repl() -> Result<(), String> {
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return Err("admin REPL requires an interactive terminal".into());
    }
    let session = unlock_or_setup()?;
    crate::ui::success("Admin unlocked");
    crate::ui::note("Type help for commands. Type exit when done.");
    let mut editor = crate::line_editor::Editor::new(libc::STDIN_FILENO, libc::STDOUT_FILENO)?;
    loop {
        let line = match editor.read_line(IDLE_SECONDS * 1000)? {
            crate::line_editor::ReadLine::Line(line) => line,
            crate::line_editor::ReadLine::End => return Ok(()),
            crate::line_editor::ReadLine::Interrupted => continue,
            crate::line_editor::ReadLine::TimedOut => {
                crate::ui::note("Session locked after inactivity.");
                return Ok(());
            }
        };
        let words = match parse_repl_line(&line) {
            Ok(words) => words,
            Err(message) => {
                crate::ui::error(&message);
                continue;
            }
        };
        if words.is_empty() {
            continue;
        }
        let word_refs: Vec<&str> = words.iter().map(String::as_str).collect();
        match crate::help::maybe_print(&word_refs, crate::help::Context::Admin) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(message) => {
                crate::ui::error(&message);
                continue;
            }
        }
        match word_refs.as_slice() {
            ["exit"] => return Ok(()),
            ["password", "change"] => {
                if let Err(message) = change_password(&session) {
                    crate::ui::error(&message);
                }
            }
            ["?"] => crate::help::print(None, crate::help::Context::Admin)?,
            ["?", topic] => crate::help::print(Some(topic), crate::help::Context::Admin)?,
            ["admin"] => crate::ui::note("Already in admin. Type help or list."),
            ["start" | "mcp" | "auth", ..] => {
                crate::ui::error("Run this outside admin. Type help for available commands.")
            }
            _ => {
                if let Err(message) = cli::run(&words, &session) {
                    crate::ui::error(&message);
                }
            }
        }
    }
}

fn parse_repl_line(line: &str) -> Result<Vec<String>, String> {
    let mut words = shlex::split(line).ok_or("invalid command quoting")?;
    if words.first().is_some_and(|word| word == "larp") {
        words.remove(0);
        if words.is_empty() {
            words.push("help".into());
        }
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::{hash_password, parse_repl_line, validate_new_password, verify};

    #[test]
    fn accepts_pasted_cli_commands_and_plain_repl_commands() {
        assert_eq!(
            parse_repl_line("larp client list").unwrap(),
            ["client", "list"]
        );
        assert_eq!(parse_repl_line("client list").unwrap(), ["client", "list"]);
        assert_eq!(
            parse_repl_line("larp command add demo check \"cargo test\"").unwrap(),
            ["command", "add", "demo", "check", "cargo test"]
        );
        assert!(parse_repl_line("larp command add '").is_err());
    }

    #[test]
    fn verifier_accepts_only_the_original_password() {
        let encoded = hash_password("correct horse battery staple").unwrap();
        assert!(verify("correct horse battery staple", encoded.as_bytes()).unwrap());
        assert!(!verify("wrong horse battery staple", encoded.as_bytes()).unwrap());
        assert!(validate_new_password("correct horse battery staple").is_ok());
        assert!(validate_new_password("short").is_err());
    }

    #[test]
    fn changed_password_replaces_the_old_verifier() {
        let old = hash_password("original long password").unwrap();
        let new = hash_password("replacement long password").unwrap();
        assert!(verify("original long password", old.as_bytes()).unwrap());
        assert!(!verify("original long password", new.as_bytes()).unwrap());
        assert!(verify("replacement long password", new.as_bytes()).unwrap());
    }
}
