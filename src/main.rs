mod admin;
mod audit;
mod cli;
mod dashboard;
mod env_file;
mod help;
mod identity;
mod limits;
mod line_editor;
mod redaction;
mod registration;
mod registry;
mod registry_mcp;
mod runner;
mod runtime;
mod secrets;
mod storage;
mod ui;

use serde_json::{json, Value};
use std::env;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

fn main() {
    if let Err(message) = run() {
        eprintln!("LARP: {}", ui::error_text(&message));
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let all_args: Vec<String> = env::args().skip(1).collect();
    let words: Vec<&str> = all_args.iter().map(String::as_str).collect();
    if help::maybe_print(&words, help::Context::Cli)? {
        return Ok(());
    }
    if matches!(words.as_slice(), ["--version" | "-V"]) {
        println!("larp {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if matches!(
        all_args.first().map(String::as_str),
        Some("client" | "project" | "command" | "secret" | "permission" | "list")
    ) {
        let session = admin::authenticate_existing()?;
        return cli::run(&all_args, &session);
    }
    match words.as_slice() {
        ["auth"] => {
            let mut client = Client::start()?;
            client.authenticate()?;
            println!("1Password access approved");
            Ok(())
        }
        ["start"] => runtime::start(),
        ["admin"] => admin::repl(),
        ["dash"] => dashboard::start(),
        ["mcp"] => runtime::bridge(),
        _ => Err("unknown command or extra arguments; run 'larp help'".into()),
    }
}

struct Client {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    next_id: u64,
}

impl Client {
    fn start() -> Result<Self, String> {
        let mut child = Command::new("1password-mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| {
                "could not start 1password-mcp; check the 1Password desktop app and PATH"
            })?;
        let input = child
            .stdin
            .take()
            .ok_or("1Password MCP stdin unavailable")?;
        let output = child
            .stdout
            .take()
            .ok_or("1Password MCP stdout unavailable")?;
        let mut client = Self {
            child,
            input,
            output: BufReader::new(output),
            next_id: 1,
        };
        let initialized = client.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "larp", "version": env!("CARGO_PKG_VERSION") }
            }),
        )?;
        let version = initialized.get("protocolVersion").and_then(Value::as_str);
        if !matches!(
            version,
            Some("2025-06-18" | "2025-03-26" | "2024-11-05" | "2025-11-25")
        ) {
            return Err("unsupported MCP protocol version".into());
        }
        client.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))?;
        Ok(client)
    }

    fn authenticate(&mut self) -> Result<String, String> {
        let result = self.call("authenticate", json!({}))?;
        result
            .get("account_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| "invalid authentication response from 1Password".into())
    }

    fn call(&mut self, name: &str, arguments: Value) -> Result<Value, String> {
        let response = self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )?;
        if response.get("isError").and_then(Value::as_bool) == Some(true) {
            return Err(format!(
                "1Password rejected {name}; check its approval prompt"
            ));
        }
        if let Some(structured) = response.get("structuredContent") {
            return Ok(structured.clone());
        }
        let text = response
            .get("content")
            .and_then(Value::as_array)
            .and_then(|items| {
                items
                    .iter()
                    .find(|item| item.get("type").and_then(Value::as_str) == Some("text"))
            })
            .and_then(|item| item.get("text"))
            .and_then(Value::as_str)
            .ok_or("missing 1Password tool response")?;
        serde_json::from_str(text).map_err(|_| "invalid JSON from 1Password tool".into())
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))?;
        loop {
            let mut line = Vec::new();
            self.output
                .by_ref()
                .take((MAX_MESSAGE_BYTES + 1) as u64)
                .read_until(b'\n', &mut line)
                .map_err(|_| "failed to read 1Password MCP response")?;
            if line.is_empty() {
                return Err("1Password MCP closed the connection".into());
            }
            if line.len() > MAX_MESSAGE_BYTES || !line.ends_with(b"\n") {
                return Err("1Password MCP response exceeded the size limit".into());
            }
            let message: Value = serde_json::from_slice(&line)
                .map_err(|_| "invalid 1Password MCP message".to_string())?;
            if message.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(error) = message.get("error") {
                let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
                return Err(format!(
                    "1Password MCP rejected {method} (code {code}); check its approval prompt"
                ));
            }
            return message
                .get("result")
                .cloned()
                .ok_or("missing 1Password MCP result".into());
        }
    }

    fn send(&mut self, message: &Value) -> Result<(), String> {
        serde_json::to_writer(&mut self.input, message)
            .map_err(|_| "failed to send 1Password MCP request")?;
        self.input
            .write_all(b"\n")
            .map_err(|_| "failed to send 1Password MCP request")?;
        self.input
            .flush()
            .map_err(|_| "failed to send 1Password MCP request".into())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
