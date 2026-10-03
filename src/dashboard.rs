//! A terminal-authenticated, loopback-only administration dashboard.
use crate::{admin, cli, registry::Registry};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

const IDLE: Duration = Duration::from_secs(15 * 60);
const MAX_BODY: usize = 16 * 1024;

pub fn start() -> Result<(), String> {
    let _session = admin::authenticate_existing()?;
    Registry::load()?;
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| "could not start dashboard")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "could not configure dashboard")?;
    let host = listener
        .local_addr()
        .map_err(|_| "could not read dashboard address")?
        .to_string();
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let url = format!("http://{host}/#{token}");
    println!("Dashboard unlocked. Close with Ctrl+C; locks after 15 minutes of inactivity.");
    println!("Open {url}");
    if let Err(error) = std::process::Command::new("open").arg(&url).spawn() {
        eprintln!("Could not open browser ({error}); use the URL above.");
    }
    let mut activity = Instant::now();
    while activity.elapsed() < IDLE {
        match listener.accept() {
            Ok((mut stream, _)) => {
                configure_stream(&stream)?;
                let result = read_request(&stream).and_then(|request| {
                    authorize(&request, &host, &token)?;
                    if request.path.starts_with("/api/") {
                        activity = Instant::now();
                    }
                    route(&request)
                });
                let (status, kind, body) = match result {
                    Ok(reply) => reply,
                    Err(message) => (
                        400,
                        "application/json",
                        json!({"error":message}).to_string(),
                    ),
                };
                let _ = respond(&mut stream, status, kind, &body);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => return Err("dashboard connection failed".into()),
        }
    }
    println!("Dashboard locked after inactivity. Run 'larp dash' to reopen.");
    Ok(())
}

struct Request {
    method: String,
    path: String,
    headers: std::collections::BTreeMap<String, String>,
    body: Vec<u8>,
}

fn configure_stream(stream: &TcpStream) -> Result<(), String> {
    // macOS inherits the listener's nonblocking mode on accepted sockets.
    // Request parsing needs to wait for headers and bodies to arrive.
    stream
        .set_nonblocking(false)
        .map_err(|_| "could not configure dashboard connection")?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| "could not configure dashboard read timeout")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| "could not configure dashboard write timeout")?;
    Ok(())
}

fn read_request(stream: &TcpStream) -> Result<Request, String> {
    parse_request(BufReader::new(stream))
}

fn parse_request(mut reader: impl BufRead) -> Result<Request, String> {
    let mut lines = Vec::new();
    let mut total = 0;
    loop {
        let mut line = Vec::new();
        reader
            .by_ref()
            .take(8193)
            .read_until(b'\n', &mut line)
            .map_err(|_| "could not read request")?;
        total += line.len();
        if line.is_empty() || total > 8192 || !line.ends_with(b"\r\n") {
            return Err("invalid or oversized request headers".into());
        }
        if line == b"\r\n" {
            break;
        }
        lines.push(String::from_utf8(line).map_err(|_| "invalid request headers")?);
    }
    let first: Vec<_> = lines
        .first()
        .ok_or("missing request line")?
        .split_whitespace()
        .collect();
    if first.len() != 3 || first[2] != "HTTP/1.1" {
        return Err("invalid request".into());
    }
    let (method, path) = (first[0].to_owned(), first[1].to_owned());
    let mut headers = std::collections::BTreeMap::new();
    for line in &lines[1..] {
        let (key, value) = line.trim_end().split_once(':').ok_or("invalid header")?;
        if headers
            .insert(key.to_ascii_lowercase(), value.trim().to_owned())
            .is_some()
        {
            return Err("duplicate request header".into());
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err("transfer encoding is unsupported".into());
    }
    let length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| "invalid content length")?
        .unwrap_or(0);
    if length > MAX_BODY {
        return Err("request body is too large".into());
    }
    let mut body = vec![0; length];
    reader
        .read_exact(&mut body)
        .map_err(|_| "incomplete request body")?;
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn authorize(request: &Request, host: &str, token: &str) -> Result<(), String> {
    if request.headers.get("host").map(String::as_str) != Some(host) {
        return Err("invalid dashboard host".into());
    }
    if let Some(origin) = request.headers.get("origin") {
        if origin != &format!("http://{host}") {
            return Err("invalid dashboard origin".into());
        }
    }
    if request.path.starts_with("/api/") {
        if request.headers.get("authorization") != Some(&format!("Bearer {token}")) {
            return Err("dashboard session is unavailable; reopen with 'larp dash'".into());
        }
        if request.method == "POST"
            && request.headers.get("content-type").map(String::as_str) != Some("application/json")
        {
            return Err("expected JSON request".into());
        }
    }
    Ok(())
}

fn route(request: &Request) -> Result<(u16, &'static str, String), String> {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => Ok((
            200,
            "text/html; charset=utf-8",
            include_str!("dashboard.html").into(),
        )),
        ("GET", "/api/state") => Ok((
            200,
            "application/json",
            state(&Registry::load()?).to_string(),
        )),
        ("POST", "/api/change") => {
            let change: Change =
                serde_json::from_slice(&request.body).map_err(|_| "invalid dashboard change")?;
            let mut registry = Registry::load()?;
            apply(&mut registry, change)?;
            registry.save()?;
            Ok((200, "application/json", state(&registry).to_string()))
        }
        _ => Ok((
            404,
            "application/json",
            json!({"error":"not found"}).to_string(),
        )),
    }
}

fn respond(stream: &mut impl Write, status: u16, kind: &str, body: &str) -> std::io::Result<()> {
    write!(stream, "HTTP/1.1 {status} Response\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'\r\n\r\n{body}", body.len())
}

fn state(registry: &Registry) -> Value {
    json!({
        "clients": registry.clients.iter().map(|(name, client)| json!({
            "name":name, "process":client.process, "identity":client.identity.label(),
            "commands":client.commands, "secrets":client.secrets, "exec":client.exec
        })).collect::<Vec<_>>(),
        "projects": registry.projects.iter().map(|(name, project)| json!({
            "name":name, "commands":project.commands.iter().map(|(name, command)| json!({"name":name,"bindings":command.env.keys().collect::<Vec<_>>()})).collect::<Vec<_>>(),
            "secrets":project.secrets.keys().collect::<Vec<_>>()
        })).collect::<Vec<_>>()
    })
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Change {
    Permission {
        client: String,
        project: String,
        kind: String,
        name: String,
        enabled: bool,
    },
    AddClient {
        name: String,
        process: String,
    },
    UpdateClient {
        name: String,
        process: String,
    },
    RemoveClient {
        name: String,
    },
}

fn apply(registry: &mut Registry, change: Change) -> Result<(), String> {
    match change {
        Change::AddClient { name, process } => cli::add_client(registry, &name, &process),
        Change::UpdateClient { name, process } => cli::update_client(registry, &name, &process),
        Change::RemoveClient { name } => registry
            .clients
            .remove(&name)
            .map(|_| ())
            .ok_or("client does not exist".into()),
        Change::Permission {
            client,
            project,
            kind,
            name,
            enabled,
        } => {
            let target = registry
                .projects
                .get(&project)
                .ok_or("project does not exist")?;
            match kind.as_str() {
                "exec" if name.is_empty() => {}
                "command" if target.commands.contains_key(&name) => {}
                "secret" if target.secrets.contains_key(&name) => {}
                _ => return Err("permission target does not exist".into()),
            }
            let client = registry
                .clients
                .get_mut(&client)
                .ok_or("client does not exist")?;
            if kind == "exec" {
                if enabled {
                    client.exec.insert(project);
                } else {
                    client.exec.remove(&project);
                }
            } else {
                let grants = if kind == "command" {
                    &mut client.commands
                } else {
                    &mut client.secrets
                };
                let grant = (project, name);
                if enabled {
                    grants.insert(grant);
                } else {
                    grants.remove(&grant);
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{Client, ClientIdentity, Project, RegisteredCommand};

    fn fixture() -> Registry {
        let mut registry = Registry::default();
        let mut project = Project::default();
        project
            .secrets
            .insert("TOKEN".into(), "op://private/item/field".into());
        project.commands.insert(
            "check".into(),
            RegisteredCommand {
                argv: vec!["true".into()],
                cwd: "/tmp".into(),
                env: std::collections::BTreeMap::from([("TOKEN".into(), "TOKEN".into())]),
            },
        );
        registry.projects.insert("demo".into(), project);
        registry.clients.insert(
            "agent".into(),
            Client {
                process: "/bin/true".into(),
                identity: ClientIdentity::PathOnly,
                commands: Default::default(),
                secrets: Default::default(),
                exec: Default::default(),
            },
        );
        registry
    }

    fn permission(kind: &str, name: &str, enabled: bool) -> Change {
        Change::Permission {
            client: "agent".into(),
            project: "demo".into(),
            kind: kind.into(),
            name: name.into(),
            enabled,
        }
    }

    #[test]
    fn accepted_connection_waits_for_delayed_headers_and_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        // Explicitly model macOS inheritance on every test platform.
        stream.set_nonblocking(true).unwrap();
        configure_stream(&stream).unwrap();
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            client.write_all(b"POST /api/change HTTP/1.1\r\nHost: 127.0.0.1:1234\r\nContent-Length: 2\r\n\r\n").unwrap();
            std::thread::sleep(Duration::from_millis(50));
            client.write_all(b"{}").unwrap();
        });
        let request = read_request(&stream).unwrap();
        assert_eq!(request.path, "/api/change");
        assert_eq!(request.body, b"{}");
        sender.join().unwrap();
    }

    #[test]
    fn permissions_are_idempotent_and_validate_targets_before_mutating() {
        let mut registry = fixture();
        for (kind, name) in [("command", "check"), ("secret", "TOKEN"), ("exec", "")] {
            apply(&mut registry, permission(kind, name, true)).unwrap();
            let granted = state(&registry);
            apply(&mut registry, permission(kind, name, true)).unwrap();
            assert_eq!(state(&registry), granted);
            apply(&mut registry, permission(kind, name, false)).unwrap();
            apply(&mut registry, permission(kind, name, false)).unwrap();
        }
        let before = state(&registry);
        for (kind, name) in [
            ("command", "missing"),
            ("secret", "check"),
            ("exec", "check"),
            ("unknown", ""),
        ] {
            assert!(apply(&mut registry, permission(kind, name, true)).is_err());
            assert_eq!(state(&registry), before);
        }
    }

    #[test]
    fn projection_includes_bindings_but_not_secret_references_or_signing_requirements() {
        let mut registry = fixture();
        registry.clients.get_mut("agent").unwrap().identity = ClientIdentity::Signed {
            requirement: "private signing requirement".into(),
        };
        let projected = state(&registry).to_string();
        assert!(projected.contains("TOKEN"));
        assert!(projected.contains("bindings"));
        assert!(!projected.contains("op://"));
        assert!(!projected.contains("private signing"));
    }

    #[test]
    fn api_requires_session_and_rejects_foreign_hosts_and_origins() {
        let mut request =
            parse_request(&b"GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:1234\r\n\r\n"[..]).unwrap();
        assert!(authorize(&request, "127.0.0.1:1234", "secret").is_err());
        request
            .headers
            .insert("authorization".into(), "Bearer secret".into());
        assert!(authorize(&request, "127.0.0.1:1234", "secret").is_ok());
        request
            .headers
            .insert("origin".into(), "https://example.com".into());
        assert!(authorize(&request, "127.0.0.1:1234", "secret").is_err());
        request.headers.remove("origin");
        request.headers.insert("host".into(), "example.com".into());
        assert!(authorize(&request, "127.0.0.1:1234", "secret").is_err());
    }

    #[test]
    fn parser_rejects_ambiguous_oversized_and_incomplete_requests() {
        for request in [
            "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 16385\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nx",
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "\r\n",
        ] {
            assert!(parse_request(request.as_bytes()).is_err());
        }
    }
}
