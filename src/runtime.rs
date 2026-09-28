use crate::{
    audit::Audit,
    identity,
    limits::{self, Counter},
    registry::Registry,
    registry_mcp,
    runner::Runner,
};
use serde_json::{json, Value};
use std::fs::{self, DirBuilder, Permissions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn runtime_dir() -> PathBuf {
    let uid = unsafe { libc::geteuid() };
    PathBuf::from(format!("/private/tmp/larp-{uid}"))
}

fn socket_path() -> PathBuf {
    runtime_dir().join("mcp.sock")
}

fn check_runtime_dir() -> Result<(), String> {
    let path = runtime_dir();
    match DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| "could not inspect LARP runtime directory")?;
            let uid = unsafe { libc::geteuid() };
            if metadata.file_type().is_dir()
                && metadata.uid() == uid
                && metadata.permissions().mode() & 0o777 == 0o700
            {
                Ok(())
            } else {
                Err("LARP runtime directory is not private to this user".into())
            }
        }
        Err(_) => Err("could not create LARP runtime directory".into()),
    }
}

fn check_socket(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "LARP is not running; start it first")?;
    let uid = unsafe { libc::geteuid() };
    if metadata.file_type().is_socket()
        && metadata.uid() == uid
        && metadata.permissions().mode() & 0o777 == 0o600
    {
        Ok(())
    } else {
        Err("LARP socket is not private to this user".into())
    }
}

struct SocketCleanup(PathBuf);

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_dir(runtime_dir());
    }
}

pub fn start() -> Result<(), String> {
    let max_connections = limits::configured("LARP_MAX_CONNECTIONS", 128, 4096)?;
    let connections = Counter::new(max_connections);
    check_runtime_dir()?;
    let path = socket_path();
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            if UnixStream::connect(&path).is_ok() {
                return Err("LARP is already running".into());
            }
            fs::remove_file(&path).map_err(|_| "could not clear stale LARP socket")?;
        }
        Ok(_) => return Err("unexpected file at LARP socket path".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("could not inspect LARP socket path".into()),
    }
    let listener = UnixListener::bind(&path).map_err(|_| "could not bind LARP socket")?;
    let _cleanup = SocketCleanup(path.clone());
    fs::set_permissions(&path, Permissions::from_mode(0o600))
        .map_err(|_| "could not protect LARP socket")?;
    let registry = Registry::load()?;
    if registry.clients.is_empty() && registry.projects.is_empty() {
        return Err(
            "registry is empty; use 'larp admin' to register a client and project before starting"
                .into(),
        );
    }
    crate::ui::start_banner();
    crate::ui::start_waiting();
    let _ = io::stdout().flush();
    let runner = Arc::new(Runner::load(registry)?);
    let audit = Arc::new(Audit::new()?);
    crate::ui::start_ready(runner.secret_count());
    for connection in listener.incoming() {
        let mut stream = connection.map_err(|_| "LARP socket accept failed")?;
        let Some(permit) = connections.acquire() else {
            let _ = serde_json::to_writer(
                &mut stream,
                &json!({"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":limits::BUSY,"data":{"retryable":true}}}),
            );
            let _ = stream.write_all(b"\n");
            continue;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let runner = Arc::clone(&runner);
        let audit = Arc::clone(&audit);
        thread::spawn(move || {
            let _permit = permit;
            match serve_connection(stream, &runner, &audit) {
                Ok(()) => {}
                Err(error) => crate::ui::error(&error),
            }
        });
    }
    Ok(())
}

fn serve_connection(stream: UnixStream, runner: &Runner, audit: &Audit) -> Result<(), String> {
    let uid = peer_uid(&stream)?;
    if uid != unsafe { libc::geteuid() } {
        return Err("LARP socket peer is not this user".into());
    }
    let pid = peer_pid(&stream);
    let reader = stream
        .try_clone()
        .map_err(|_| "could not clone LARP socket")?;
    let mut reader = BufReader::new(reader);
    if !read_bridge_preface(&mut reader)? {
        return Ok(());
    }
    stream
        .set_read_timeout(None)
        .map_err(|_| "could not clear MCP handshake timeout")?;
    let bridge_pid = pid.ok_or("could not verify bridge process PID")?;
    let current_registry = Registry::load().map_err(|_| "Could not load client registrations")?;
    let (client_name, identity_label, _) = match identity::identify(
        bridge_pid,
        uid,
        &current_registry,
    ) {
        Ok(client) => client,
        Err(_) => {
            let mut stream = stream;
            let _ = stream.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":0,\"error\":{\"code\":-32004,\"message\":\"LARP client not authorized\"}}\n");
            return Err("Client not authorized".into());
        }
    };
    let current_runner = match runner.with_registry(current_registry) {
        Ok(current) => current,
        Err(_) => {
            let mut stream = stream;
            let _ = stream.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":0,\"error\":{\"code\":-32005,\"message\":\"Secret registrations changed; restart LARP\"}}\n");
            return Err("Secret registrations changed; restart LARP".into());
        }
    };
    registry_mcp::serve_live(
        reader,
        stream,
        &current_runner,
        &client_name,
        Some(audit),
        identity_label,
    )
    .map_err(|error| match error.as_str() {
        "invalid MCP request" | "MCP request exceeded size limit" => "Invalid MCP request".into(),
        "failed to read MCP request" => "MCP request interrupted".into(),
        "failed to write MCP response" => "MCP reply could not be delivered".into(),
        "client disappeared" => "Client registration changed".into(),
        _ => "MCP session ended unexpectedly".into(),
    })
}

fn read_bridge_preface(reader: &mut impl BufRead) -> Result<bool, String> {
    let mut preface = Vec::new();
    reader
        .by_ref()
        .take(4097)
        .read_until(b'\n', &mut preface)
        .map_err(|_| "could not read LARP bridge identity")?;
    if preface.is_empty() {
        return Ok(false);
    }
    if preface.len() > 4096 || !preface.ends_with(b"\n") {
        return Err("Invalid LARP bridge identity".into());
    }
    let _: Value = serde_json::from_slice(&preface).map_err(|_| "Invalid LARP bridge identity")?;
    Ok(true)
}

fn peer_uid(stream: &UnixStream) -> Result<libc::uid_t, String> {
    let mut uid = 0;
    let mut gid = 0;
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0 {
        Ok(uid)
    } else {
        Err("could not verify LARP socket peer".into())
    }
}

#[cfg(target_os = "macos")]
fn peer_pid(stream: &UnixStream) -> Option<i32> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of_val(&pid) as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    (status == 0 && len as usize == std::mem::size_of_val(&pid)).then_some(pid)
}

#[cfg(not(target_os = "macos"))]
fn peer_pid(_: &UnixStream) -> Option<i32> {
    None
}

pub fn bridge() -> Result<(), String> {
    bridge_io(
        || {
            check_runtime_dir()?;
            let path = socket_path();
            check_socket(&path)?;
            UnixStream::connect(path).map_err(|error| match error.kind() {
                io::ErrorKind::PermissionDenied => "LARP socket access denied".into(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound => {
                    "LARP socket is stale or unavailable".into()
                }
                _ => "Could not connect to LARP socket".into(),
            })
        },
        io::stdin().lock(),
        io::stdout(),
    )
}

fn bridge_io<R: BufRead, W: Write + Send + 'static>(
    connect: impl Fn() -> Result<UnixStream, String> + Send + Sync + 'static,
    mut input: R,
    output: W,
) -> Result<(), String> {
    const MAX_BRIDGE_REQUEST: u64 = 64 * 1024;
    let output = Arc::new(Mutex::new(output));
    let connect = Arc::new(connect);
    let calls = limits::Counter::new(128);
    let mut workers = Vec::new();
    loop {
        let mut line = Vec::new();
        (&mut input)
            .take(MAX_BRIDGE_REQUEST + 1)
            .read_until(b'\n', &mut line)
            .map_err(|_| "could not read MCP client request")?;
        if line.is_empty() {
            break;
        }
        if line.len() as u64 > MAX_BRIDGE_REQUEST || !line.ends_with(b"\n") {
            return Err("MCP client request exceeded size limit".into());
        }
        let request: Value =
            serde_json::from_slice(&line).map_err(|_| "invalid MCP client request")?;
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let Some(id) = request.get("id").cloned() else {
            continue;
        };
        let local_response = match method {
            "initialize" => Some(registry_mcp::initialization(&id)),
            "tools/list" => {
                Some(json!({"jsonrpc":"2.0","id":id,"result":registry_mcp::tool_catalog()}))
            }
            "ping" => Some(json!({"jsonrpc":"2.0","id":id,"result":{}})),
            _ => None,
        };
        if let Some(response) = local_response {
            let mut writer = output.lock().map_err(|_| "MCP output lock failed")?;
            serde_json::to_writer(&mut *writer, &response)
                .map_err(|_| "could not write MCP response")?;
            writer
                .write_all(b"\n")
                .map_err(|_| "could not write MCP response")?;
            writer.flush().map_err(|_| "could not flush MCP response")?;
            continue;
        }
        let Some(permit) = calls.acquire() else {
            bridge_error(&output, &id, limits::BUSY, true)?;
            continue;
        };
        let output = Arc::clone(&output);
        let connect = Arc::clone(&connect);
        workers.push(thread::spawn(move || {
            let _permit = permit;
            let response = bridge_request(&*connect, &line, false);
            match response {
                Ok(response) => {
                    if let Ok(mut writer) = output.lock() {
                        let _ = writer.write_all(&response);
                        let _ = writer.flush();
                    }
                }
                Err(error) => {
                    let _ = bridge_error(&output, &id, error.message, error.retryable);
                }
            }
        }));
        workers.retain(|worker| !worker.is_finished());
    }
    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

#[derive(Debug)]
struct BridgeError {
    message: &'static str,
    retryable: bool,
}

fn bridge_error<W: Write>(
    output: &Mutex<W>,
    id: &Value,
    message: &str,
    retryable: bool,
) -> Result<(), String> {
    let mut output = output.lock().map_err(|_| "MCP output lock failed")?;
    serde_json::to_writer(
        &mut *output,
        &json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":crate::ui::error_text(message),"data":{"retryable":retryable}}}),
    )
    .map_err(|_| "could not write MCP error")?;
    output
        .write_all(b"\n")
        .map_err(|_| "could not write MCP error")?;
    output
        .flush()
        .map_err(|_| "could not flush MCP error".into())
}

fn bridge_request(
    connect: &impl Fn() -> Result<UnixStream, String>,
    request: &[u8],
    initialize: bool,
) -> Result<Vec<u8>, BridgeError> {
    let mut socket = connect().map_err(|error| BridgeError {
        message: match error.as_str() {
            "LARP is not running; start it first" => "LARP is not running; start it and retry",
            "LARP socket access denied" => {
                "LARP socket access denied; check the MCP client's local permissions"
            }
            "LARP socket is stale or unavailable" => {
                "LARP socket is stale or unavailable; restart LARP"
            }
            "LARP runtime directory is not private to this user"
            | "LARP socket is not private to this user" => "LARP socket permissions are invalid",
            _ => "Could not connect to LARP; check its server status and local permissions",
        },
        retryable: true,
    })?;
    // The server verifies the bridge PID and its parent through the socket and OS.
    let preface: &[u8] = if initialize {
        b"{}\n"
    } else {
        b"{}\n{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{\"clientInfo\":{\"name\":\"larp-bridge\",\"version\":\"1\"}}\n"
    };
    socket.write_all(preface).map_err(|_| BridgeError {
        message: "LARP connection closed before the request",
        retryable: true,
    })?;
    let mut reader = BufReader::new(socket.try_clone().map_err(|_| BridgeError {
        message: "LARP connection failed before the request",
        retryable: true,
    })?);
    if !initialize {
        let mut handshake = Vec::new();
        reader
            .read_until(b'\n', &mut handshake)
            .map_err(|_| BridgeError {
                message: "LARP connection closed before the request",
                retryable: true,
            })?;
        if handshake.is_empty() {
            return Err(BridgeError {
                message: "LARP connection closed before the request",
                retryable: true,
            });
        }
        let handshake_error = serde_json::from_slice::<Value>(&handshake)
            .ok()
            .and_then(|message| message["error"]["code"].as_i64());
        if handshake_error == Some(-32004) {
            return Err(BridgeError {
                message: "LARP client not authorized; check its registration",
                retryable: false,
            });
        }
        if handshake_error == Some(-32005) {
            return Err(BridgeError {
                message: "Secret registrations changed; restart LARP",
                retryable: false,
            });
        }
        socket
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
            .map_err(|_| BridgeError {
                message: "LARP connection closed before the request",
                retryable: true,
            })?;
    }
    socket.write_all(request).map_err(|_| BridgeError {
        message: "LARP connection closed while sending the request; outcome unknown",
        retryable: false,
    })?;
    let mut response = Vec::new();
    reader
        .read_until(b'\n', &mut response)
        .map_err(|_| BridgeError {
            message: "LARP connection closed during the request; outcome unknown",
            retryable: false,
        })?;
    if response.is_empty() {
        return Err(BridgeError {
            message: "LARP connection closed during the request; outcome unknown",
            retryable: false,
        });
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::{bridge_io, bridge_request, read_bridge_preface};
    use std::io::{BufRead, BufReader, Cursor, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[derive(Clone)]
    struct Output(Arc<Mutex<Vec<u8>>>);

    impl Write for Output {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn empty_bridge_connection_is_a_normal_disconnect() {
        assert!(!read_bridge_preface(&mut Cursor::new(b"")).unwrap());
        assert!(read_bridge_preface(&mut Cursor::new(b"{}\n")).unwrap());
        assert_eq!(
            read_bridge_preface(&mut Cursor::new(b"broken\n")).unwrap_err(),
            "Invalid LARP bridge identity"
        );
    }

    #[test]
    fn unavailable_server_returns_errors_without_closing_client_session() {
        let output = Output(Arc::new(Mutex::new(Vec::new())));
        let captured = output.clone();
        let requests = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"commands\"}}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"commands\"}}\n";
        bridge_io(
            || Err("server unavailable".into()),
            Cursor::new(requests),
            output,
        )
        .unwrap();
        let captured = captured.0.lock().unwrap();
        let replies: Vec<serde_json::Value> = captured
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert_eq!(replies.len(), 2);
        assert!(replies
            .iter()
            .all(|reply| reply["error"]["data"]["retryable"] == true));
    }

    #[test]
    fn denied_socket_does_not_claim_the_server_is_stopped() {
        let failure = bridge_request(
            &|| Err("LARP socket access denied".into()),
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n",
            true,
        )
        .unwrap_err();
        assert_eq!(
            failure.message,
            "LARP socket access denied; check the MCP client's local permissions"
        );
        assert!(failure.retryable);
    }

    #[test]
    fn rejected_client_gets_a_clear_bridge_error() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let server_task = thread::spawn(move || {
            let mut reader = BufReader::new(server.try_clone().unwrap());
            let mut preface = String::new();
            reader.read_line(&mut preface).unwrap();
            server
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":0,\"error\":{\"code\":-32004,\"message\":\"LARP client not authorized\"}}\n")
                .unwrap();
        });
        let socket = Mutex::new(Some(client));
        let failure = bridge_request(
            &|| Ok(socket.lock().unwrap().take().unwrap()),
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}\n",
            false,
        )
        .unwrap_err();
        server_task.join().unwrap();
        assert_eq!(
            failure.message,
            "LARP client not authorized; check its registration"
        );
        assert!(!failure.retryable);
    }

    #[test]
    fn bridge_initializes_and_lists_tools_while_server_is_down() {
        let output = Output(Arc::new(Mutex::new(Vec::new())));
        let captured = output.clone();
        let requests = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"commands\"}}\n";
        bridge_io(
            || Err("LARP is not running; start it first".into()),
            Cursor::new(requests),
            output,
        )
        .unwrap();
        let captured = captured.0.lock().unwrap();
        let replies: Vec<serde_json::Value> = captured
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert_eq!(replies.len(), 3);
        assert_eq!(replies[0]["result"]["serverInfo"]["name"], "larp");
        assert_eq!(replies[1]["result"]["tools"].as_array().unwrap().len(), 3);
        assert_eq!(
            replies[2]["error"]["message"],
            "LARP is not running; start it and retry"
        );
    }

    #[test]
    fn each_call_opens_and_initializes_a_fresh_server_connection() {
        let (client, server) = UnixStream::pair().unwrap();
        let server_task = thread::spawn(move || {
            let mut reader = BufReader::new(server);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap(); // bridge identity
            line.clear();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains("\"initialize\""));
            reader
                .get_mut()
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{}}\n")
                .unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains("notifications/initialized"));
            line.clear();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains("tools/list"));
            reader
                .get_mut()
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[]}}\n")
                .unwrap();
        });
        let socket = Mutex::new(Some(client));
        let response = bridge_request(
            &|| Ok(socket.lock().unwrap().take().unwrap()),
            b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/list\"}\n",
            false,
        )
        .unwrap();
        server_task.join().unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response).unwrap()["id"],
            7
        );
    }

    #[test]
    fn lost_connection_after_dispatch_does_not_mark_a_command_safe_to_retry() {
        let (client, server) = UnixStream::pair().unwrap();
        let server_task = thread::spawn(move || {
            let mut reader = BufReader::new(server);
            let mut line = String::new();
            for _ in 0..4 {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line.contains("\"id\":0") {
                    reader
                        .get_mut()
                        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{}}\n")
                        .unwrap();
                }
            }
        });
        let socket = Mutex::new(Some(client));
        let failure = bridge_request(
            &|| Ok(socket.lock().unwrap().take().unwrap()),
            b"{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\"}\n",
            false,
        )
        .unwrap_err();
        server_task.join().unwrap();
        assert!(!failure.retryable);
        assert!(failure.message.contains("outcome unknown"));
    }
}
