use crate::env_file;
use crate::limits::{self, Counter};
use crate::redaction::Redactor;
use crate::registry::{Client, Registry};
use crate::secrets;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroize;
use zeroize::Zeroizing;

const OUTPUT_LIMIT: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(120);

pub struct Runner {
    pub registry: Registry,
    values: Option<Arc<SecretValues>>,
    secrets: Arc<Mutex<SecretCache>>,
    commands: Arc<Counter>,
    path: Arc<Vec<PathBuf>>,
}

type SecretKey = (String, String);
type SecretValues = BTreeMap<SecretKey, Arc<Zeroizing<String>>>;

struct SecretCache {
    references: BTreeMap<SecretKey, String>,
    values: Arc<SecretValues>,
}

fn references(registry: &Registry) -> BTreeMap<SecretKey, String> {
    registry
        .projects
        .iter()
        .flat_map(|(project, item)| {
            item.secrets
                .iter()
                .map(move |(name, reference)| ((project.clone(), name.clone()), reference.clone()))
        })
        .collect()
}

pub struct RunResult {
    pub executable: String,
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
}

impl Runner {
    pub fn secret_count(&self) -> usize {
        self.secrets
            .lock()
            .map(|cache| cache.values.len())
            .unwrap_or(0)
    }

    fn values(&self) -> Result<Arc<SecretValues>, String> {
        match &self.values {
            Some(values) => Ok(Arc::clone(values)),
            None => self
                .secrets
                .lock()
                .map(|cache| Arc::clone(&cache.values))
                .map_err(|_| "Secret cache unavailable".into()),
        }
    }

    pub fn load(registry: Registry) -> Result<Self, String> {
        let max_commands = limits::configured("LARP_MAX_COMMANDS", 32, 1024)?;
        let path = runtime_path()?;
        let references = references(&registry);
        let mut values = SecretValues::new();
        for ((project, name), reference) in &references {
            let value = secrets::read(reference)
                .map_err(|_| format!("Could not load secret {project}/{name} from 1Password"))?;
            values.insert((project.clone(), name.clone()), Arc::new(value));
        }
        let values = Arc::new(values);
        Ok(Self {
            registry,
            values: None,
            secrets: Arc::new(Mutex::new(SecretCache { references, values })),
            commands: Counter::new(max_commands),
            path: Arc::new(path),
        })
    }

    pub fn with_registry(&self, registry: Registry) -> Result<Self, String> {
        self.with_registry_using(registry, secrets::read)
    }

    fn with_registry_using(
        &self,
        registry: Registry,
        mut read: impl FnMut(&str) -> Result<Zeroizing<String>, String>,
    ) -> Result<Self, String> {
        let desired = references(&registry);
        let mut cache = self
            .secrets
            .lock()
            .map_err(|_| "Secret cache unavailable")?;
        if cache.references != desired {
            let by_reference: BTreeMap<&str, Arc<Zeroizing<String>>> = cache
                .references
                .iter()
                .filter_map(|(key, reference)| {
                    cache
                        .values
                        .get(key)
                        .map(|value| (reference.as_str(), Arc::clone(value)))
                })
                .collect();
            let mut values = SecretValues::new();
            for (key, reference) in &desired {
                let value = if cache.references.get(key) == Some(reference) {
                    Arc::clone(
                        cache
                            .values
                            .get(key)
                            .ok_or("Registered secret was not loaded")?,
                    )
                } else if let Some(value) = by_reference.get(reference.as_str()) {
                    Arc::clone(value)
                } else {
                    Arc::new(read(reference).map_err(|_| {
                        format!("Could not load secret {}/{} from 1Password", key.0, key.1)
                    })?)
                };
                values.insert(key.clone(), value);
            }
            cache.values = Arc::new(values);
            cache.references = desired;
        }
        Ok(Self {
            registry,
            values: Some(Arc::clone(&cache.values)),
            secrets: Arc::clone(&self.secrets),
            commands: Arc::clone(&self.commands),
            path: Arc::clone(&self.path),
        })
    }

    pub fn run(
        &self,
        client: &Client,
        project: &str,
        name: &str,
        env: Option<&str>,
    ) -> Result<RunResult, String> {
        let project_item = self
            .registry
            .projects
            .get(project)
            .ok_or("project does not exist")?;
        let command = project_item
            .commands
            .get(name)
            .ok_or("command does not exist")?;
        if !client
            .commands
            .contains(&(project.to_string(), name.to_string()))
        {
            return Err("client is not permitted to run this command".into());
        }
        self.run_argv(client, project, &command.argv, &command.cwd, env)
    }

    pub fn exec(
        &self,
        client: &Client,
        project: &str,
        argv: &[String],
        env: Option<&str>,
    ) -> Result<RunResult, String> {
        let project_item = self
            .registry
            .projects
            .get(project)
            .ok_or("project does not exist")?;
        if !client.exec.contains(project) {
            return Err("client is not permitted to exec in this project".into());
        }
        if project_item.cwd.is_empty() {
            return Err("project cwd is not set; use 'project cwd <name> <path>'".into());
        }
        if argv.is_empty()
            || argv.len() > 128
            || argv
                .iter()
                .any(|part| part.len() > 8192 || part.contains('\0'))
        {
            return Err("exec argv is empty or exceeds limits".into());
        }
        let bytes: usize = argv.iter().map(String::len).sum();
        if bytes > 32 * 1024 || argv[0].is_empty() {
            return Err("exec argv exceeds limits".into());
        }
        self.run_argv(client, project, argv, &project_item.cwd, env)
    }

    fn run_argv(
        &self,
        client: &Client,
        project: &str,
        argv: &[String],
        cwd: &str,
        env: Option<&str>,
    ) -> Result<RunResult, String> {
        let values = self.values()?;
        let project_item = self
            .registry
            .projects
            .get(project)
            .ok_or("project does not exist")?;
        let mut injected = Vec::new();
        let mappings = match env {
            Some(path) => Some(env_file::read(path)?),
            None => None,
        };
        if let Some(mappings) = &mappings {
            for (variable, reference) in mappings {
                let secret_name = project_item
                    .secrets
                    .iter()
                    .find(|(name, registered)| {
                        *registered == reference
                            && client
                                .secrets
                                .contains(&(project.to_owned(), (*name).to_owned()))
                    })
                    .map(|(name, _)| name)
                    .ok_or("reference file includes an unregistered or ungranted secret")?;
                let value = values
                    .get(&(project.to_owned(), secret_name.to_owned()))
                    .ok_or("registered secret was not loaded")?;
                injected.push((variable.as_str(), value.as_str()));
            }
        }
        let executable = resolve_with_path(&argv[0], cwd, &self.path)?;
        let path = execution_path(&executable, cwd, &self.path)?;
        let _permit = self.commands.acquire().ok_or(limits::BUSY)?;
        let mut child_command = Command::new(&executable);
        child_command
            .args(&argv[1..])
            .current_dir(cwd)
            .env_clear()
            .env("PATH", path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (variable, value) in &injected {
            child_command.env(variable, value);
        }
        unsafe {
            child_command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let redactor = Redactor::new(values.values().map(|value| value.as_str()));
        let capture_limit = OUTPUT_LIMIT + redactor.max_pattern_len();
        let mut child = child_command
            .spawn()
            .map_err(|_| "could not start registered command")?;
        let captured = match capture_process(&mut child, capture_limit, TIMEOUT, true) {
            Ok(captured) => captured,
            Err(message) => {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                return Err(message);
            }
        };
        let (status, timed_out, mut out_bytes, mut err_bytes, out_truncated, err_truncated) =
            captured;
        let mut stdout = String::from_utf8_lossy(&out_bytes).into_owned();
        let mut stderr = String::from_utf8_lossy(&err_bytes).into_owned();
        out_bytes.zeroize();
        err_bytes.zeroize();
        redactor.redact(&mut stdout);
        redactor.redact(&mut stderr);
        let stdout_truncated = truncate_utf8(&mut stdout, OUTPUT_LIMIT);
        let stderr_truncated = truncate_utf8(&mut stderr, OUTPUT_LIMIT);
        Ok(RunResult {
            executable: executable.to_string_lossy().into_owned(),
            status,
            stdout,
            stderr,
            truncated: out_truncated || err_truncated || stdout_truncated || stderr_truncated,
            timed_out,
        })
    }
}

fn runtime_path() -> Result<Vec<PathBuf>, String> {
    let value = std::env::var_os("PATH").ok_or("PATH is not set for LARP")?;
    let dirs: Vec<PathBuf> = std::env::split_paths(&value).collect();
    if dirs.is_empty() || dirs.iter().any(|dir| !dir.is_absolute()) {
        return Err("LARP PATH must contain only absolute directories".into());
    }
    Ok(dirs)
}

fn search_dirs(cwd: &str, path: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs = vec![Path::new(cwd).join("node_modules/.bin")];
    dirs.extend_from_slice(path);
    dirs
}

fn execution_path(executable: &Path, cwd: &str, path: &[PathBuf]) -> Result<OsString, String> {
    let mut dirs = search_dirs(cwd, path);
    if let Some(parent) = executable.parent() {
        dirs.insert(0, parent.to_path_buf());
    }
    std::env::join_paths(dirs).map_err(|_| "could not build command PATH".into())
}

pub(crate) fn resolve_executable(program: &str, cwd: &str) -> Result<PathBuf, String> {
    resolve_with_path(program, cwd, &runtime_path()?)
}

fn resolve_with_path(program: &str, cwd: &str, path: &[PathBuf]) -> Result<PathBuf, String> {
    let input = Path::new(program);
    let candidate = if input.is_absolute() {
        input.to_path_buf()
    } else if program.contains('/') {
        Path::new(cwd).join(input)
    } else {
        search_dirs(cwd, path)
            .into_iter()
            .map(|directory| directory.join(program))
            .find(|path| {
                path.is_file()
                    && path
                        .metadata()
                        .is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0)
            })
            .ok_or("executable was not found in LARP's startup PATH")?
    };
    let resolved = candidate
        .canonicalize()
        .map_err(|_| "could not resolve executable")?;
    let metadata = resolved
        .metadata()
        .map_err(|_| "could not inspect executable")?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("executable is not an executable file".into());
    }
    Ok(resolved)
}

struct PipeCapture<T> {
    input: T,
    bytes: Vec<u8>,
    truncated: bool,
    open: bool,
}

impl<T: Read + AsRawFd> PipeCapture<T> {
    fn new(input: T) -> Result<Self, String> {
        let fd = input.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err("could not set command pipe nonblocking".into());
        }
        Ok(Self {
            input,
            bytes: Vec::new(),
            truncated: false,
            open: true,
        })
    }

    fn drain(&mut self, limit: usize) -> Result<(), String> {
        for _ in 0..16 {
            let mut chunk = [0u8; 8192];
            match self.input.read(&mut chunk) {
                Ok(0) => {
                    self.open = false;
                    break;
                }
                Ok(read) => {
                    let remaining = limit.saturating_sub(self.bytes.len());
                    self.bytes.extend_from_slice(&chunk[..read.min(remaining)]);
                    self.truncated |= read > remaining;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("could not read command output".into()),
            }
        }
        Ok(())
    }
}

type Captured = (Option<i32>, bool, Vec<u8>, Vec<u8>, bool, bool);

fn capture_process(
    child: &mut std::process::Child,
    limit: usize,
    timeout: Duration,
    owns_process_group: bool,
) -> Result<Captured, String> {
    let mut stdout = PipeCapture::new(child.stdout.take().ok_or("command stdout unavailable")?)?;
    let mut stderr = PipeCapture::new(child.stderr.take().ok_or("command stderr unavailable")?)?;
    let deadline = Instant::now() + timeout;
    let mut status = None;
    let mut timed_out = false;
    let mut drain_deadline = None;
    loop {
        if status.is_none() {
            if let Some(done) = child.try_wait().map_err(|_| "could not wait for command")? {
                status = Some(done.code());
                drain_deadline = Some(Instant::now() + Duration::from_millis(500));
            } else if Instant::now() >= deadline {
                if owns_process_group {
                    unsafe {
                        libc::kill(-(child.id() as i32), libc::SIGKILL);
                    }
                }
                let _ = child.kill();
                let done = child
                    .wait()
                    .map_err(|_| "could not stop timed-out command")?;
                status = Some(done.code());
                timed_out = true;
                drain_deadline = Some(Instant::now() + Duration::from_millis(500));
            }
        }
        stdout.drain(limit)?;
        stderr.drain(limit)?;
        if status.is_some()
            && (!stdout.open && !stderr.open
                || drain_deadline.is_some_and(|end| Instant::now() >= end))
        {
            if stdout.open {
                stdout.truncated = true;
            }
            if stderr.open {
                stderr.truncated = true;
            }
            break;
        }
        let mut descriptors = [
            libc::pollfd {
                fd: stdout.input.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stderr.input.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        for (descriptor, open) in descriptors.iter_mut().zip([stdout.open, stderr.open]) {
            if !open {
                descriptor.fd = -1;
            }
        }
        let polled = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                20,
            )
        };
        if polled < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err("could not poll command output".into());
        }
    }
    Ok((
        status.unwrap_or(None),
        timed_out,
        stdout.bytes,
        stderr.bytes,
        stdout.truncated,
        stderr.truncated,
    ))
}

fn truncate_utf8(value: &mut String, limit: usize) -> bool {
    if value.len() <= limit {
        return false;
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    true
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{capture_process, references, resolve_executable, Counter, Runner, SecretCache};
    use crate::registry::{Client, ClientIdentity, Project, RegisteredCommand, Registry};
    use rand_core::{OsRng, RngCore};
    use std::collections::{BTreeMap, BTreeSet};
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    #[test]
    fn descendant_holding_pipe_does_not_block_result() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 2 &"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        let (_, timed_out, _, _, _, _) =
            capture_process(&mut child, 1024, Duration::from_secs(3), false).unwrap();
        assert!(!timed_out);
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn changed_secret_reference_refreshes_once_and_drops_old_snapshot() {
        let runner = dummy();
        let old_values = runner.values().unwrap();
        let old_weak = Arc::downgrade(&old_values);
        let mut registry: Registry =
            serde_json::from_value(serde_json::to_value(&runner.registry).unwrap()).unwrap();
        registry
            .projects
            .get_mut("demo")
            .unwrap()
            .secrets
            .insert("api_key".into(), "op://other/item/field".into());
        let refreshed = runner
            .with_registry_using(registry, |_| Ok(Zeroizing::new("new-value".into())))
            .unwrap();
        assert_eq!(
            old_values[&("demo".into(), "api_key".into())].as_str(),
            "dummy-secret-value"
        );
        assert_eq!(
            refreshed.values().unwrap()[&("demo".into(), "api_key".into())].as_str(),
            "new-value"
        );
        let unchanged: Registry =
            serde_json::from_value(serde_json::to_value(&refreshed.registry).unwrap()).unwrap();
        refreshed
            .with_registry_using(unchanged, |_| panic!("Unchanged reference was reloaded"))
            .unwrap();
        drop(old_values);
        assert!(old_weak.upgrade().is_none());
    }

    #[test]
    fn project_rename_reuses_loaded_reference() {
        let runner = dummy();
        let mut registry: Registry =
            serde_json::from_value(serde_json::to_value(&runner.registry).unwrap()).unwrap();
        registry.rename_project("demo", "renamed").unwrap();
        let refreshed = runner
            .with_registry_using(registry, |_| panic!("Renaming should not reread 1Password"))
            .unwrap();
        assert_eq!(
            refreshed.values().unwrap()[&("renamed".into(), "api_key".into())].as_str(),
            "dummy-secret-value"
        );
        let client = &refreshed.registry.clients["test"];
        assert!(client
            .secrets
            .contains(&("renamed".into(), "api_key".into())));
    }

    #[test]
    fn partial_secret_refresh_is_not_published() {
        let runner = dummy();
        let mut registry: Registry =
            serde_json::from_value(serde_json::to_value(&runner.registry).unwrap()).unwrap();
        let secrets = &mut registry.projects.get_mut("demo").unwrap().secrets;
        secrets.insert("api_key".into(), "op://other/item/field".into());
        secrets.insert("second".into(), "op://other/item/second".into());
        let mut reads = 0;
        assert!(runner
            .with_registry_using(registry, |_| {
                reads += 1;
                if reads == 1 {
                    Ok(Zeroizing::new("new-value".into()))
                } else {
                    Err("Unavailable".into())
                }
            })
            .is_err());
        assert_eq!(reads, 2);
        let cache = runner.secrets.lock().unwrap();
        assert_eq!(cache.references, references(&runner.registry));
        assert_eq!(cache.values.len(), 1);
        assert_eq!(
            cache.values[&("demo".into(), "api_key".into())].as_str(),
            "dummy-secret-value"
        );
    }

    #[test]
    fn oversized_output_is_bounded_and_timeout_stops_child() {
        let mut child = Command::new("/usr/bin/yes")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (_, timed_out, out, _, truncated, _) =
            capture_process(&mut child, 256, Duration::from_millis(100), false).unwrap();
        assert!(timed_out);
        assert_eq!(out.len(), 256);
        assert!(truncated);
    }

    #[test]
    fn exec_resolves_relative_project_program() {
        let directory = std::env::temp_dir().join(format!("larp-exec-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let relative = directory.join("tool");
        std::os::unix::fs::symlink("/bin/echo", &relative).unwrap();
        let resolved = resolve_executable("./tool", directory.to_str().unwrap()).unwrap();
        assert_eq!(resolved, std::fs::canonicalize("/bin/echo").unwrap());
        std::fs::remove_file(relative).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn registered_local_tool_is_found_from_cwd_and_child_path() {
        use std::os::unix::fs::PermissionsExt;
        let directory = std::env::temp_dir().join(format!(
            "larp-command-path-{}-{}",
            std::process::id(),
            OsRng.next_u64()
        ));
        let bin = directory.join("node_modules/.bin");
        std::fs::create_dir_all(&bin).unwrap();
        for (name, script) in [
            ("tool", "#!/bin/sh\ntool-helper\n"),
            ("tool-helper", "#!/bin/sh\necho nested-tool-found\n"),
        ] {
            let path = bin.join(name);
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut runner = dummy();
        let project = runner.registry.projects.get_mut("demo").unwrap();
        project.cwd = directory.to_string_lossy().into_owned();
        project.commands.insert(
            "inspect".into(),
            RegisteredCommand {
                argv: vec!["tool".into()],
                cwd: directory.to_string_lossy().into_owned(),
            },
        );
        let client = &runner.registry.clients["test"];
        let result = runner.run(client, "demo", "inspect", None).unwrap();
        assert_eq!(result.status, Some(0));
        assert_eq!(result.stdout.trim(), "nested-tool-found");
        assert_eq!(
            runner.registry.projects["demo"].commands["inspect"].argv[0],
            "tool"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn child_uses_server_path_for_nested_tools() {
        use std::os::unix::fs::PermissionsExt;
        let directory = std::env::temp_dir().join(format!(
            "larp-runtime-path-{}-{}",
            std::process::id(),
            OsRng.next_u64()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let cargo = directory.join("cargo");
        std::fs::write(&cargo, "#!/bin/sh\necho cargo-found\n").unwrap();
        std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut runner = dummy();
        runner.path = Arc::new(vec![directory.clone(), "/usr/bin".into(), "/bin".into()]);
        runner
            .registry
            .projects
            .get_mut("demo")
            .unwrap()
            .commands
            .insert(
                "inspect".into(),
                RegisteredCommand {
                    argv: vec!["/bin/sh".into(), "-c".into(), "cargo".into()],
                    cwd: "/private/tmp".into(),
                },
            );
        let result = runner
            .run(&runner.registry.clients["test"], "demo", "inspect", None)
            .unwrap();
        assert_eq!(result.status, Some(0));
        assert_eq!(result.stdout.trim(), "cargo-found");
        std::fs::remove_dir_all(directory).unwrap();
    }

    pub(crate) fn dummy() -> Runner {
        let mut registry = Registry::default();
        let mut project = Project {
            cwd: "/private/tmp".into(),
            ..Project::default()
        };
        project.commands.insert(
            "inspect".into(),
            RegisteredCommand {
                argv: vec!["/usr/bin/env".into()],
                cwd: "/private/tmp".into(),
            },
        );
        project
            .secrets
            .insert("api_key".into(), "op://dummy/item/field".into());
        registry.projects.insert("demo".into(), project);
        registry.clients.insert(
            "test".into(),
            Client {
                process: "/bin/test".into(),
                identity: ClientIdentity::PathOnly,
                commands: BTreeSet::from([("demo".into(), "inspect".into())]),
                secrets: BTreeSet::from([("demo".into(), "api_key".into())]),
                exec: BTreeSet::new(),
            },
        );
        let values = Arc::new(BTreeMap::from([(
            ("demo".into(), "api_key".into()),
            Arc::new(Zeroizing::new("dummy-secret-value".into())),
        )]));
        Runner {
            secrets: Arc::new(Mutex::new(SecretCache {
                references: references(&registry),
                values,
            })),
            registry,
            values: None,
            commands: Counter::new(32),
            path: Arc::new(super::runtime_path().unwrap()),
        }
    }

    #[test]
    fn injects_and_redacts_approved_secret() {
        let runner = dummy();
        let client = &runner.registry.clients["test"];
        let path = reference_file("API_KEY=op://dummy/item/field\n");
        let result = runner
            .run(client, "demo", "inspect", Some(path.to_str().unwrap()))
            .unwrap();
        assert_eq!(result.status, Some(0));
        assert!(result.stdout.contains("API_KEY=REDACTED"));
        assert!(!result.stdout.contains("dummy-secret-value"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_missing_command_or_secret_grants() {
        let mut runner = dummy();
        let path = reference_file("API_KEY=op://dummy/item/field\n");
        let env = Some(path.to_str().unwrap());
        runner
            .registry
            .clients
            .get_mut("test")
            .unwrap()
            .commands
            .clear();
        let client = &runner.registry.clients["test"];
        assert!(runner.run(client, "demo", "inspect", env).is_err());
        runner
            .registry
            .clients
            .get_mut("test")
            .unwrap()
            .commands
            .insert(("demo".into(), "inspect".into()));
        runner
            .registry
            .clients
            .get_mut("test")
            .unwrap()
            .secrets
            .clear();
        let client = &runner.registry.clients["test"];
        assert!(runner.run(client, "demo", "inspect", env).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn reference_file_rejects_unknown_reference_and_is_optional() {
        let mut runner = dummy();
        let client = &runner.registry.clients["test"];
        let without = runner.run(client, "demo", "inspect", None).unwrap();
        assert!(!without.stdout.contains("API_KEY="));
        let path = reference_file("API_KEY=op://dummy/item/field\n");
        let with = runner
            .run(client, "demo", "inspect", Some(path.to_str().unwrap()))
            .unwrap();
        assert!(with.stdout.contains("API_KEY=REDACTED"));
        std::fs::remove_file(&path).unwrap();
        let unknown = reference_file("API_KEY=op://other/item/field\n");
        assert!(runner
            .run(client, "demo", "inspect", Some(unknown.to_str().unwrap()))
            .is_err());
        std::fs::remove_file(unknown).unwrap();
        runner
            .registry
            .clients
            .get_mut("test")
            .unwrap()
            .secrets
            .clear();
        let client = &runner.registry.clients["test"];
        let path = reference_file("API_KEY=op://dummy/item/field\n");
        assert!(runner
            .run(client, "demo", "inspect", Some(path.to_str().unwrap()))
            .is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn exec_requires_its_own_grant_and_redacts_output() {
        let mut runner = dummy();
        let argv = vec!["/usr/bin/env".to_string()];
        let client = &runner.registry.clients["test"];
        assert!(runner.exec(client, "demo", &argv, None).is_err());
        runner
            .registry
            .clients
            .get_mut("test")
            .unwrap()
            .exec
            .insert("demo".into());
        let client = &runner.registry.clients["test"];
        let path = reference_file("API_KEY=op://dummy/item/field\n");
        let result = runner
            .exec(client, "demo", &argv, Some(path.to_str().unwrap()))
            .unwrap();
        assert_eq!(result.status, Some(0));
        assert!(result.stdout.contains("API_KEY=REDACTED"));
        assert!(!result.stdout.contains("dummy-secret-value"));
        assert!(runner.exec(client, "demo", &[], None).is_err());
        std::fs::remove_file(path).unwrap();
    }

    pub(crate) fn reference_file(contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "larp-reference-test-{}-{}",
            std::process::id(),
            OsRng.next_u64()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }
}
