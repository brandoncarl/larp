use crate::{
    audit::{Audit, Event},
    limits,
    registry::Registry,
    runner::Runner,
};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};
use std::time::Instant;

const MAX_REQUEST_BYTES: usize = 64 * 1024;

fn request_id() -> String {
    format!("{:016x}", OsRng.next_u64())
}

enum ProtocolFailure {
    Oversized,
    Incomplete,
    MalformedJson { column: usize },
}

impl ProtocolFailure {
    fn details(&self) -> (&'static str, String, i32) {
        match self {
            Self::Oversized => (
                "oversized_request",
                "MCP request exceeded 64 KiB".into(),
                -32600,
            ),
            Self::Incomplete => (
                "incomplete_request",
                "MCP request ended before the newline".into(),
                -32600,
            ),
            Self::MalformedJson { column } => (
                "malformed_json",
                format!("Invalid MCP JSON at column {column}"),
                -32700,
            ),
        }
    }
}

fn protocol_failure(
    output: &mut impl Write,
    audit: Option<&Audit>,
    client_name: &str,
    identity: &str,
    request_id: &str,
    failure: ProtocolFailure,
) -> Result<(), String> {
    let (decision, message, code) = failure.details();
    if let Some(audit) = audit {
        let mut event = Event::now(client_name, identity, None, "mcp", decision);
        event.request_id = Some(request_id.to_owned());
        audit.record(&event)?;
        crate::ui::error(&format!("{message} · request {request_id}"));
    }
    respond(
        output,
        &json!({
            "jsonrpc":"2.0", "id":null,
            "error":{"code":code,"message":message,"data":{"requestId":request_id}}
        }),
    )
}

pub fn initialization(id: &Value) -> Value {
    json!({"jsonrpc":"2.0", "id":id,
        "result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},
            "serverInfo":{"name":"larp","version":env!("CARGO_PKG_VERSION")}}})
}

pub fn tool_catalog() -> Value {
    json!({"tools":[{
        "name":"commands",
        "title":"Available commands",
        "description":"List this client's permitted projects, commands, exec access, and secret names. Omit project to discover all permitted projects, or pass a project to narrow the list. Returns no secret values or references.",
        "annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false},
        "inputSchema":{"type":"object","properties":{"project":{"type":"string","description":"Optional project name. Omit to list all permitted projects."}},"additionalProperties":false}
    },{
        "name":"command",
        "title":"Run registered command",
        "description":"Run a registered command in its saved working directory. Optional env is an absolute path to a regular reference-only file containing NAME=op://... entries. Every reference must match a registered 1Password secret granted to this client. The file supplies variable names; secret values never appear in the request. Returns redacted stdout and stderr after exit.",
        "inputSchema":{"type":"object","properties":{
            "project":{"type":"string","description":"Registered project name from commands."},
            "name":{"type":"string","description":"Registered command name from commands."},
            "env":{"type":"string","description":"Optional absolute path to a reference-only .env.op file. No values or arbitrary 1Password references are accepted."}
        },"required":["project","name"],"additionalProperties":false}
    },{
        "name":"exec",
        "title":"Execute arguments",
        "description":"Run caller-supplied arguments in the project's fixed working directory. Requires an exec grant. Direct calls to the 1Password CLI (op) are rejected; use env to inject granted secrets. Optional env has the same reference-only rules as command and requires a grant for every referenced secret. Scripts can still invoke op. Stdout and stderr are returned after exit with known secret values redacted.",
        "inputSchema":{"type":"object","properties":{
            "project":{"type":"string","description":"Registered project with an exec grant."},
            "argv":{"type":"array","items":{"type":"string"},"minItems":1,"description":"Executable followed by individual arguments; no implicit shell."},
            "env":{"type":"string","description":"Optional absolute path to a reference-only .env.op file."}
        },"required":["project","argv"],"additionalProperties":false}
    },{
        "name":"register",
        "title":"Request client registration",
        "description":"Ask the user to register this MCP caller. LARP verifies the executable through the OS and prompts in the larp start terminal for confirmation and the admin password. Registration grants no permissions. Already registered callers return their existing client name. Do not retry a declined request unless the user asks.",
        "annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false},
        "inputSchema":{"type":"object","properties":{"name":{"type":"string","description":"Proposed client name: 1–64 ASCII letters, digits, underscores, or hyphens.","minLength":1,"maxLength":64,"pattern":"^[A-Za-z0-9_-]+$"}},"required":["name"],"additionalProperties":false}
    }]})
}

#[cfg(test)]
pub fn serve<R: BufRead, W: Write>(
    input: R,
    output: W,
    runner: &Runner,
    client_name: &str,
    audit: Option<&Audit>,
    identity: &str,
) -> Result<(), String> {
    serve_inner(input, output, runner, client_name, audit, identity, || {
        Ok(None)
    })
}

pub fn serve_live<R: BufRead, W: Write>(
    input: R,
    output: W,
    runner: &Runner,
    client_name: &str,
    audit: Option<&Audit>,
    identity: &str,
) -> Result<(), String> {
    serve_inner(input, output, runner, client_name, audit, identity, || {
        Registry::load().map(Some)
    })
}

fn serve_inner<R: BufRead, W: Write>(
    mut input: R,
    mut output: W,
    runner: &Runner,
    client_name: &str,
    audit: Option<&Audit>,
    identity: &str,
    mut refresh: impl FnMut() -> Result<Option<Registry>, String>,
) -> Result<(), String> {
    let original_client = runner
        .registry
        .clients
        .get(client_name)
        .ok_or("client disappeared")?;
    let mut initialized = false;
    let mut initialize_seen = false;
    loop {
        let request_id = request_id();
        let mut line = Vec::new();
        input
            .by_ref()
            .take((MAX_REQUEST_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| "failed to read MCP request")?;
        if line.is_empty() {
            return Ok(());
        }
        if line.len() > MAX_REQUEST_BYTES {
            protocol_failure(
                &mut output,
                audit,
                client_name,
                identity,
                &request_id,
                ProtocolFailure::Oversized,
            )?;
            return Ok(());
        }
        if !line.ends_with(b"\n") {
            protocol_failure(
                &mut output,
                audit,
                client_name,
                identity,
                &request_id,
                ProtocolFailure::Incomplete,
            )?;
            return Ok(());
        }
        let request: Value = match serde_json::from_slice(&line) {
            Ok(request) => request,
            Err(error) => {
                protocol_failure(
                    &mut output,
                    audit,
                    client_name,
                    identity,
                    &request_id,
                    ProtocolFailure::MalformedJson {
                        column: error.column(),
                    },
                )?;
                continue;
            }
        };
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let Some(id) = request.get("id") else {
            if method == "notifications/initialized" && initialize_seen {
                initialized = true;
            }
            continue;
        };
        if method == "initialize" {
            initialize_seen = true;
            initialized = false;
            respond(&mut output, &initialization(id))?;
            continue;
        }
        if !initialized {
            error(&mut output, id, -32000, "Server not initialized")?;
            continue;
        }
        match method {
            "ping" => respond(&mut output, &json!({"jsonrpc":"2.0","id":id,"result":{}}))?,
            "tools/list" => respond(
                &mut output,
                &json!({"jsonrpc":"2.0","id":id,"result":tool_catalog()}),
            )?,
            "tools/call" => {
                let refreshed = match refresh().and_then(|registry| {
                    registry
                        .map(|registry| runner.with_registry(registry))
                        .transpose()
                }) {
                    Ok(refreshed) => refreshed,
                    Err(_) => {
                        error(
                            &mut output,
                            id,
                            -32003,
                            "Could not refresh registry or secrets; check LARP and retry",
                        )?;
                        continue;
                    }
                };
                let active_runner = refreshed.as_ref().unwrap_or(runner);
                let Some(client) = active_runner.registry.clients.get(client_name) else {
                    error(&mut output, id, -32004, "Client registration was removed")?;
                    continue;
                };
                if client.process != original_client.process
                    || client.identity != original_client.identity
                {
                    error(
                        &mut output,
                        id,
                        -32004,
                        "Client registration changed; reconnect MCP",
                    )?;
                    continue;
                }
                let runner = active_runner;
                let params = request.get("params");
                let tool = params.and_then(|p| p.get("name")).and_then(Value::as_str);
                if !matches!(tool, Some("commands" | "command" | "exec")) {
                    error(&mut output, id, -32601, "Unknown tool")?;
                    continue;
                }
                let args = params.and_then(|p| p.get("arguments"));
                if tool == Some("commands") {
                    let project_filter = match args {
                        None => None,
                        Some(Value::Object(map)) if map.is_empty() => None,
                        Some(Value::Object(map)) if map.len() == 1 => {
                            match map
                                .get("project")
                                .and_then(Value::as_str)
                                .filter(|value| !value.is_empty())
                            {
                                Some(project) => Some(project),
                                None => {
                                    error(&mut output, id, -32602, "Invalid commands arguments")?;
                                    continue;
                                }
                            }
                        }
                        _ => {
                            error(&mut output, id, -32602, "Invalid commands arguments")?;
                            continue;
                        }
                    };
                    let projects: Vec<Value> = runner.registry.projects.iter().filter_map(|(project_name, project)| {
                        if project_filter.is_some_and(|filter| filter != project_name) { return None; }
                        let names: Vec<&str> = project.commands.keys().filter(|name| client.commands.contains(&(project_name.clone(), (*name).clone()))).map(String::as_str).collect();
                        let exec = client.exec.contains(project_name);
                        let secrets: Vec<&str> = project.secrets.keys().filter(|name| client.secrets.contains(&(project_name.clone(), (*name).clone()))).map(String::as_str).collect();
                        if names.is_empty() && !exec && secrets.is_empty() { return None; }
                        Some(json!({"project":project_name,"commands":names,"exec":exec,"secrets":secrets}))
                    }).collect();
                    let summary = if projects.is_empty() {
                        if project_filter.is_some() {
                            "No access to this project."
                        } else {
                            "No projects granted to this client."
                        }
                        .to_owned()
                    } else {
                        serde_json::to_string(&projects).unwrap_or_default()
                    };
                    if let Some(audit) = audit {
                        let mut event = Event::now(
                            client_name,
                            identity,
                            project_filter,
                            "commands",
                            "allowed",
                        );
                        event.request_id = Some(request_id.clone());
                        if audit.record(&event).is_err() {
                            error(
                                &mut output,
                                id,
                                -32002,
                                "Audit unavailable; catalog withheld",
                            )?;
                            continue;
                        }
                    }
                    respond(
                        &mut output,
                        &json!({"jsonrpc":"2.0","id":id,"result":{
                            "content":[{"type":"text","text":summary}],
                            "structuredContent":{"projects":projects,"requestId":request_id}
                        }}),
                    )?;
                    continue;
                }
                let project = args.and_then(|a| a.get("project")).and_then(Value::as_str);
                let name = args.and_then(|a| a.get("name")).and_then(Value::as_str);
                let env = match args.and_then(|a| a.get("env")) {
                    None => Some(None),
                    Some(Value::String(path)) if !path.is_empty() => Some(Some(path.as_str())),
                    _ => None,
                };
                let argv: Option<Vec<String>> = args
                    .and_then(|a| a.get("argv"))
                    .and_then(Value::as_array)
                    .and_then(|items| {
                        items
                            .iter()
                            .map(|item| item.as_str().map(str::to_owned))
                            .collect()
                    });
                let allowed_keys: &[&str] = if tool == Some("exec") {
                    &["project", "argv", "env"]
                } else {
                    &["project", "name", "env"]
                };
                let valid_keys = args
                    .and_then(Value::as_object)
                    .is_some_and(|map| map.keys().all(|key| allowed_keys.contains(&key.as_str())));
                if let (Some(project), Some(env)) = (project, env) {
                    if !valid_keys
                        || (tool == Some("command") && name.is_none())
                        || (tool == Some("exec") && argv.is_none())
                    {
                        error(&mut output, id, -32602, "Invalid command arguments")?;
                        continue;
                    }
                    let known_project = runner
                        .registry
                        .projects
                        .get_key_value(project)
                        .map(|(name, _)| name.as_str());
                    if let Some(audit) = audit {
                        let attempt = Event::now(
                            client_name,
                            identity,
                            known_project,
                            tool.unwrap(),
                            "attempt",
                        );
                        let mut attempt = attempt;
                        attempt.request_id = Some(request_id.clone());
                        attempt.command = name.filter(|_| tool == Some("command"));
                        if audit.record(&attempt).is_err() {
                            error(
                                &mut output,
                                id,
                                -32002,
                                "Audit unavailable; command was not started",
                            )?;
                            continue;
                        }
                    }
                    let action = if tool == Some("command") {
                        name.unwrap_or("command")
                    } else {
                        "exec"
                    };
                    if audit.is_some() {
                        eprintln!("→ {client_name} · {project} / {action}");
                    }
                    let started = Instant::now();
                    let result = if tool == Some("exec") {
                        runner.exec(client, project, argv.as_ref().unwrap(), env)
                    } else {
                        runner.run(client, project, name.unwrap(), env)
                    };
                    if let Some(audit) = audit {
                        let decision = if result.is_ok() {
                            "allowed"
                        } else if result
                            .as_ref()
                            .err()
                            .is_some_and(|message| message == limits::BUSY)
                        {
                            "busy"
                        } else {
                            "denied"
                        };
                        let mut event = Event::now(
                            client_name,
                            identity,
                            known_project,
                            tool.unwrap(),
                            decision,
                        );
                        event.request_id = Some(request_id.clone());
                        event.command = name.filter(|_| tool == Some("command"));
                        if let Err(message) = &result {
                            event.error_code = Some(run_error_code(message));
                            event.reason = Some(message);
                        }
                        event.duration_ms = started.elapsed().as_millis();
                        if let Ok(outcome) = &result {
                            event.exit_code = outcome.status;
                            event.timed_out = outcome.timed_out;
                            event.executable = Some(&outcome.executable);
                        }
                        if audit.record(&event).is_err() {
                            error(
                                &mut output,
                                id,
                                -32002,
                                "Audit unavailable; command result withheld",
                            )?;
                            continue;
                        }
                        let duration = started.elapsed().as_secs_f64();
                        match &result {
                            Ok(outcome) if outcome.timed_out => {
                                eprintln!("✗ {client_name} · {project} / {action} · timed out ({duration:.1}s)")
                            }
                            Ok(outcome) if outcome.status == Some(0) => {
                                eprintln!("✓ {client_name} · {project} / {action} · done ({duration:.1}s)")
                            }
                            Ok(outcome) => eprintln!(
                                "✗ {client_name} · {project} / {action} · exit {} ({duration:.1}s)",
                                outcome
                                    .status
                                    .map_or_else(|| "unknown".to_owned(), |code| code.to_string())
                            ),
                            Err(message) if message == limits::BUSY => {
                                eprintln!("! {client_name} · {project} / {action} · busy")
                            }
                            Err(message) => {
                                eprintln!("✗ {client_name} · {project} / {action} · rejected · {} · {message} · request {request_id}", run_error_code(message))
                            }
                        }
                    }
                    let response = match result {
                        Ok(result) => json!({"jsonrpc":"2.0","id":id,"result":{
                            "content":[{"type":"text","text":format!("exit status: {:?}\nstdout:\n{}\nstderr:\n{}",result.status,result.stdout,result.stderr)}],
                            "structuredContent":{"requestId":request_id,"exitCode":result.status,"stdout":result.stdout,"stderr":result.stderr,"truncated":result.truncated,"timedOut":result.timed_out},
                            "isError":result.timed_out || result.status != Some(0)
                        }}),
                        Err(message) => json!({"jsonrpc":"2.0","id":id,"result":{
                            "content":[{"type":"text","text":crate::ui::error_text(&message)}],
                            "structuredContent":{"requestId":request_id,"retryable":message == limits::BUSY,"errorCode":run_error_code(&message)},
                            "isError":true
                        }}),
                    };
                    respond(&mut output, &response)?;
                } else {
                    error(&mut output, id, -32602, "Invalid command arguments")?;
                }
            }
            _ => error(&mut output, id, -32601, "Method not found")?,
        }
    }
}

fn run_error_code(message: &str) -> &'static str {
    if message.starts_with("command environment includes an unregistered secret:") {
        "COMMAND_SECRET_UNREGISTERED"
    } else if message == limits::BUSY {
        "BUSY"
    } else {
        "COMMAND_REJECTED"
    }
}

fn respond(output: &mut impl Write, response: &Value) -> Result<(), String> {
    serde_json::to_writer(&mut *output, response).map_err(|_| "failed to write MCP response")?;
    output
        .write_all(b"\n")
        .map_err(|_| "failed to write MCP response")?;
    output
        .flush()
        .map_err(|_| "failed to write MCP response".into())
}

fn error(output: &mut impl Write, id: &Value, code: i32, message: &str) -> Result<(), String> {
    respond(
        output,
        &json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":crate::ui::error_text(message)}}),
    )
}

#[cfg(test)]
mod tests {
    use super::{serve, serve_inner};
    use crate::audit::Audit;
    use crate::runner::tests::{dummy, reference_file};
    use rand_core::{OsRng, RngCore};
    use serde_json::{json, Value};
    use std::fs::{self, DirBuilder};
    use std::io::Cursor;
    use std::os::unix::fs::DirBuilderExt;

    #[test]
    fn returns_redacted_command_logs_over_mcp() {
        let path = reference_file("API_KEY=op://dummy/item/field\n");
        let input = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"test","version":"1"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"command","arguments":{"project":"demo","name":"inspect","env":path}}}),
        ].iter().map(Value::to_string).collect::<Vec<_>>().join("\n") + "\n";
        let mut output = Vec::new();
        serve(
            Cursor::new(input),
            &mut output,
            &dummy(),
            "test",
            None,
            "path-only",
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("API_KEY=REDACTED"));
        assert!(!text.contains("dummy-secret-value"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn never_exposes_direct_secret_tools() {
        let input = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_secret","arguments":{}}}),
        ].iter().map(Value::to_string).collect::<Vec<_>>().join("\n") + "\n";
        let mut output = Vec::new();
        serve(
            Cursor::new(input),
            &mut output,
            &dummy(),
            "test",
            None,
            "path-only",
        )
        .unwrap();
        let responses: Vec<Value> = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        let tools = &responses[1]["result"]["tools"];
        assert_eq!(tools.as_array().unwrap().len(), 4);
        assert_eq!(tools[0]["name"], "commands");
        assert_eq!(tools[1]["name"], "command");
        assert_eq!(tools[2]["name"], "exec");
        assert_eq!(responses[2]["error"]["code"], -32601);
    }

    #[test]
    fn commands_discloses_only_granted_names() {
        let input = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"commands","arguments":{}}}),
        ].iter().map(Value::to_string).collect::<Vec<_>>().join("\n") + "\n";
        let mut runner = dummy();
        runner
            .registry
            .projects
            .get_mut("demo")
            .unwrap()
            .commands
            .insert(
                "private".into(),
                crate::registry::RegisteredCommand {
                    argv: vec!["/bin/true".into()],
                    cwd: "/private/tmp".into(),
                    env: Default::default(),
                },
            );
        runner
            .registry
            .projects
            .get_mut("demo")
            .unwrap()
            .secrets
            .insert("private_key".into(), "op://private/item/field".into());
        let mut output = Vec::new();
        serve(
            Cursor::new(input),
            &mut output,
            &runner,
            "test",
            None,
            "path-only",
        )
        .unwrap();
        let responses: Vec<Value> = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        let project = &responses[1]["result"]["structuredContent"]["projects"][0];
        assert_eq!(
            responses[1]["result"]["structuredContent"]["requestId"]
                .as_str()
                .unwrap()
                .len(),
            16
        );
        assert_eq!(project["project"], "demo");
        assert_eq!(project["commands"], json!(["inspect"]));
        assert_eq!(project["secrets"], json!(["api_key"]));
        assert_eq!(project["exec"], false);
        assert!(!String::from_utf8(output).unwrap().contains("op://"));
    }

    #[test]
    fn commands_can_filter_project_and_show_secret_only_grants() {
        let input = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"commands","arguments":{}}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"commands","arguments":{"project":"secrets_only"}}}),
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"commands","arguments":{"project":"hidden"}}}),
            json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"commands","arguments":{"project":42}}}),
        ].iter().map(Value::to_string).collect::<Vec<_>>().join("\n") + "\n";
        let mut runner = dummy();
        let mut secret_project = crate::registry::Project::default();
        secret_project
            .secrets
            .insert("token".into(), "op://vault/item/field".into());
        runner
            .registry
            .projects
            .insert("secrets_only".into(), secret_project);
        runner
            .registry
            .projects
            .insert("hidden".into(), crate::registry::Project::default());
        runner
            .registry
            .clients
            .get_mut("test")
            .unwrap()
            .secrets
            .insert(("secrets_only".into(), "token".into()));
        let mut output = Vec::new();
        serve(
            Cursor::new(input),
            &mut output,
            &runner,
            "test",
            None,
            "path-only",
        )
        .unwrap();
        let responses: Vec<Value> = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        let all = responses[1]["result"]["structuredContent"]["projects"]
            .as_array()
            .unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(
            responses[2]["result"]["structuredContent"]["projects"],
            json!([{"project":"secrets_only","commands":[],"exec":false,"secrets":["token"]}])
        );
        assert_eq!(
            responses[3]["result"]["structuredContent"]["projects"],
            json!([])
        );
        assert_eq!(
            responses[3]["result"]["content"][0]["text"],
            "No access to this project."
        );
        assert_eq!(responses[4]["error"]["code"], -32602);
    }

    #[test]
    fn commands_uses_current_grants_on_each_call() {
        let input = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"commands","arguments":{}}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"commands","arguments":{}}}),
        ].iter().map(Value::to_string).collect::<Vec<_>>().join("\n") + "\n";
        let runner = dummy();
        let mut updated: crate::registry::Registry =
            serde_json::from_value(serde_json::to_value(&runner.registry).unwrap()).unwrap();
        updated.clients.get_mut("test").unwrap().commands.clear();
        updated.clients.get_mut("test").unwrap().secrets.clear();
        let initial: crate::registry::Registry =
            serde_json::from_value(serde_json::to_value(&updated).unwrap()).unwrap();
        let mut snapshots = [initial, {
            updated
                .clients
                .get_mut("test")
                .unwrap()
                .commands
                .insert(("demo".into(), "inspect".into()));
            updated
        }]
        .into_iter();
        let mut output = Vec::new();
        serve_inner(
            Cursor::new(input),
            &mut output,
            &runner,
            "test",
            None,
            "path-only",
            || Ok(snapshots.next()),
        )
        .unwrap();
        let responses: Vec<Value> = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert_eq!(
            responses[1]["result"]["structuredContent"]["projects"],
            json!([])
        );
        assert_eq!(
            responses[2]["result"]["structuredContent"]["projects"][0]["commands"],
            json!(["inspect"])
        );
    }

    #[test]
    fn exec_returns_captured_logs_after_grants() {
        let path = reference_file("API_KEY=op://dummy/item/field\n");
        let input = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec","arguments":{"project":"demo","argv":["/usr/bin/env"],"env":path}}}),
        ].iter().map(Value::to_string).collect::<Vec<_>>().join("\n") + "\n";
        let mut runner = dummy();
        let mut denied = Vec::new();
        serve(
            Cursor::new(input.as_bytes()),
            &mut denied,
            &runner,
            "test",
            None,
            "path-only",
        )
        .unwrap();
        assert!(String::from_utf8(denied)
            .unwrap()
            .contains("not permitted to exec"));
        runner
            .registry
            .clients
            .get_mut("test")
            .unwrap()
            .exec
            .insert("demo".into());
        let mut allowed = Vec::new();
        serve(
            Cursor::new(input),
            &mut allowed,
            &runner,
            "test",
            None,
            "path-only",
        )
        .unwrap();
        let text = String::from_utf8(allowed).unwrap();
        assert!(text.contains("API_KEY=REDACTED"));
        assert!(!text.contains("dummy-secret-value"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn audit_records_decisions_without_arguments_or_secret_values() {
        let directory = std::env::temp_dir().join(format!(
            "larp-mcp-audit-{}-{}",
            std::process::id(),
            OsRng.next_u64()
        ));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let audit = Audit::in_dir(directory.clone(), 10 * 1024);
        let input = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":"sensitive-request-id","method":"tools/call","params":{"name":"exec","arguments":{"project":"demo","argv":["/bin/echo","sensitive-argument"]}}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"command","arguments":{"project":"demo","name":"inspect"}}}),
        ]
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n") + "\n";
        let mut output = Vec::new();
        serve(
            Cursor::new(input),
            &mut output,
            &dummy(),
            "test",
            Some(&audit),
            "path-only",
        )
        .unwrap();
        let records = fs::read_to_string(directory.join("audit.jsonl")).unwrap();
        assert_eq!(records.lines().count(), 4);
        assert!(records.contains("\"decision\":\"denied\""));
        assert!(records.contains("\"decision\":\"allowed\""));
        assert!(records.contains("\"exitCode\":0"));
        assert!(records.lines().all(|line| {
            serde_json::from_str::<Value>(line).unwrap()["requestId"]
                .as_str()
                .is_some_and(|id| id.len() == 16 && id.chars().all(|ch| ch.is_ascii_hexdigit()))
        }));
        assert!(!records.contains("dummy-secret-value"));
        assert!(!records.contains("sensitive-argument"));
        assert!(!records.contains("sensitive-request-id"));
        assert!(!records.contains("op://"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn missing_command_secret_is_identified_and_audited() {
        let directory = std::env::temp_dir().join(format!(
            "larp-missing-secret-{}-{}",
            std::process::id(),
            OsRng.next_u64()
        ));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let audit = Audit::in_dir(directory.clone(), 10 * 1024);
        let mut runner = dummy();
        runner
            .registry
            .projects
            .get_mut("demo")
            .unwrap()
            .commands
            .get_mut("inspect")
            .unwrap()
            .env
            .insert("TURNSTILE_SECRET".into(), "TURNSTILE_SECRET".into());
        let input = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"command","arguments":{"project":"demo","name":"inspect"}}}),
        ].iter().map(Value::to_string).collect::<Vec<_>>().join("\n") + "\n";
        let mut output = Vec::new();
        serve(
            Cursor::new(input),
            &mut output,
            &runner,
            "test",
            Some(&audit),
            "path-only",
        )
        .unwrap();
        let responses: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let result = &responses.last().unwrap()["result"];
        assert_eq!(result["isError"], true);
        assert_eq!(result["structuredContent"]["retryable"], false);
        assert_eq!(
            result["structuredContent"]["errorCode"],
            "COMMAND_SECRET_UNREGISTERED"
        );
        let records = fs::read_to_string(directory.join("audit.jsonl")).unwrap();
        let event: Value = serde_json::from_str(records.lines().last().unwrap()).unwrap();
        assert_eq!(event["command"], "inspect");
        assert_eq!(event["decision"], "denied");
        assert_eq!(event["errorCode"], "COMMAND_SECRET_UNREGISTERED");
        assert_eq!(event["requestId"], result["structuredContent"]["requestId"]);
        assert!(event["reason"]
            .as_str()
            .unwrap()
            .contains("TURNSTILE_SECRET"));
        assert!(event["executable"].is_null());
        assert!(!records.contains("dummy-secret-value"));
        assert!(!records.contains("op://"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn malformed_request_does_not_start_command() {
        let directory = std::env::temp_dir().join(format!(
            "larp-mcp-invalid-{}-{}",
            std::process::id(),
            OsRng.next_u64()
        ));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let audit = Audit::in_dir(directory.clone(), 10 * 1024);
        let mut output = Vec::new();
        serve(
            Cursor::new(b"{invalid}\n"),
            &mut output,
            &dummy(),
            "test",
            Some(&audit),
            "path-only",
        )
        .unwrap();
        let response: Value = serde_json::from_slice(&output[..output.len() - 1]).unwrap();
        assert_eq!(response["error"]["code"], -32700);
        assert!(response["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("Invalid MCP JSON at column "));
        let request_id = response["error"]["data"]["requestId"].as_str().unwrap();
        assert_eq!(request_id.len(), 16);
        let record: Value = serde_json::from_str(
            fs::read_to_string(directory.join("audit.jsonl"))
                .unwrap()
                .trim(),
        )
        .unwrap();
        assert_eq!(record["requestId"], request_id);
        assert_eq!(record["decision"], "malformed_json");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn oversized_request_is_reported_once() {
        let input = format!(
            "{}\n{{invalid}}\n",
            "x".repeat(super::MAX_REQUEST_BYTES + 1)
        );
        let mut output = Vec::new();
        serve(
            Cursor::new(input),
            &mut output,
            &dummy(),
            "test",
            None,
            "path-only",
        )
        .unwrap();
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 1);
        let response: Value = serde_json::from_slice(&output[..output.len() - 1]).unwrap();
        assert_eq!(response["error"]["message"], "MCP request exceeded 64 KiB");
    }
}
