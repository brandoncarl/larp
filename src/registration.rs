//! User-approved registration, isolated from the execution protocol.
use crate::{
    admin,
    audit::{Audit, Event},
    cli, identity,
    registry::{self, Registry},
    registry_mcp,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};
use std::sync::Mutex;

static APPROVAL: Mutex<()> = Mutex::new(());
const MAX_REQUEST: u64 = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    name: String,
}

fn arguments(value: &Value) -> Result<Arguments, String> {
    let args: Arguments = serde_json::from_value(value.clone())
        .map_err(|_| "register requires only a proposed client name")?;
    registry::name(&args.name)?;
    Ok(args)
}

pub fn serve(
    input: impl BufRead,
    output: impl Write,
    pid: i32,
    uid: u32,
    audit: &Audit,
) -> Result<(), String> {
    serve_with(input, output, |args| register(&args.name, pid, uid, audit))
}

fn serve_with(
    mut input: impl BufRead,
    mut output: impl Write,
    mut register: impl FnMut(Arguments) -> Result<Value, String>,
) -> Result<(), String> {
    let mut initialized = false;
    let mut seen_initialize = false;
    loop {
        let mut line = Vec::new();
        input
            .by_ref()
            .take(MAX_REQUEST + 1)
            .read_until(b'\n', &mut line)
            .map_err(|_| "could not read registration request")?;
        if line.is_empty() {
            return Ok(());
        }
        if line.len() as u64 > MAX_REQUEST || !line.ends_with(b"\n") {
            return Err("invalid or oversized registration request".into());
        }
        let request: Value =
            serde_json::from_slice(&line).map_err(|_| "invalid registration request")?;
        let method = request["method"].as_str().unwrap_or("");
        let Some(id) = request.get("id") else {
            if method == "notifications/initialized" && seen_initialize {
                initialized = true;
            }
            continue;
        };
        let response = match method {
            "initialize" => {
                seen_initialize = true;
                initialized = false;
                registry_mcp::initialization(id)
            }
            "ping" => json!({"jsonrpc":"2.0","id":id,"result":{}}),
            "tools/call" if initialized && request["params"]["name"] == "register" => {
                let result = arguments(&request["params"]["arguments"]).and_then(&mut register);
                let result = match result {
                    Ok(state) => {
                        json!({"content":[{"type":"text","text":format!("Client {} is registered. Registration grants no additional permissions; ask the user to manage access in larp dash, then call commands.", state["client"].as_str().unwrap_or(""))}],"structuredContent":state})
                    }
                    Err(message) => {
                        json!({"isError":true,"content":[{"type":"text","text":message}]})
                    }
                };
                write_response(
                    &mut output,
                    &json!({"jsonrpc":"2.0","id":id,"result":result}),
                )?;
                return Ok(());
            }
            _ => {
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32004,"message":"Registration connection permits only register; other tools require a registered client"}})
            }
        };
        write_response(&mut output, &response)?;
    }
}

fn write_response(output: &mut impl Write, response: &Value) -> Result<(), String> {
    serde_json::to_writer(&mut *output, response)
        .map_err(|_| "could not write registration response")?;
    output
        .write_all(b"\n")
        .map_err(|_| "could not write registration response")?;
    output
        .flush()
        .map_err(|_| "could not flush registration response".into())
}

fn register(name: &str, pid: i32, uid: u32, audit: &Audit) -> Result<Value, String> {
    let registry = Registry::load()?;
    if let Ok((client, _, _)) = identity::identify(pid, uid, &registry) {
        return Ok(json!({"status":"already_registered","client":client}));
    }
    let path = identity::unregistered_process(pid, uid, &registry).ok_or(
        "Could not verify an unregistered caller; existing registrations cannot be bypassed",
    )?;
    let _guard = APPROVAL
        .try_lock()
        .map_err(|_| "Another registration approval is active; ask the user before retrying")?;
    let mut prepared = registry;
    cli::add_client(&mut prepared, name, &path)?;
    let approved_identity = prepared.clients[name].identity.clone();
    // Verify the captured on-disk identity against the running executable before approval.
    identity::identify(pid, uid, &prepared)?;
    let result = (|| {
        if !confirm(name, &path, approved_identity.label())? {
            return Err(
                "Registration declined or timed out. Ask the user before requesting again".into(),
            );
        }
        let _session = admin::authenticate_existing()?;
        let mut current = Registry::load()?;
        if identity::unregistered_process(pid, uid, &current).as_deref() != Some(path.as_str()) {
            return Err("Caller or registration changed during approval; nothing was saved".into());
        }
        cli::add_client(&mut current, name, &path)?;
        if current.clients[name].identity != approved_identity {
            return Err(
                "Executable signing identity changed during approval; nothing was saved".into(),
            );
        }
        identity::identify(pid, uid, &current)?;
        current.save()?;
        crate::ui::success(&format!(
            "Registered {name} with no permissions. Manage access in larp dash."
        ));
        Ok(json!({"status":"registered","client":name}))
    })();
    let mut event = Event::now(
        name,
        approved_identity.label(),
        None,
        "register",
        if result.is_ok() { "approved" } else { "denied" },
    );
    event.executable = Some(&path);
    audit.record(&event)?;
    result
}

fn confirm(name: &str, path: &str, identity: &str) -> Result<bool, String> {
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return Err("Registration needs confirmation in an interactive larp start terminal".into());
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    println!();
    loop {
        print!("Register {name} ({identity})? [yes/no/details]: ");
        io::stdout()
            .flush()
            .map_err(|_| "could not show registration prompt")?;
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            println!();
            return Ok(false);
        }
        let mut poll = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe {
            libc::poll(
                &mut poll,
                1,
                remaining.as_millis().min(i32::MAX as u128) as i32,
            )
        };
        if ready <= 0 || poll.revents & libc::POLLIN == 0 {
            println!();
            return Ok(false);
        }
        let mut reply = String::new();
        io::stdin()
            .lock()
            .take(64)
            .read_line(&mut reply)
            .map_err(|_| "could not read registration approval")?;
        match reply.trim().to_ascii_lowercase().as_str() {
            "yes" => return Ok(true),
            "details" => println!(
                "Executable: {path:?}\nNo permissions granted. Approval expires after 60 seconds."
            ),
            _ => return Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn requests(tool: &str, args: Value) -> String {
        [json!({"jsonrpc":"2.0","id":0,"method":"initialize"}),json!({"jsonrpc":"2.0","method":"notifications/initialized"}),json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":tool,"arguments":args}})].iter().map(Value::to_string).collect::<Vec<_>>().join("\n")+"\n"
    }

    #[test]
    fn registration_mode_does_not_execute_other_tools() {
        for tool in ["commands", "command", "exec"] {
            let mut output = Vec::new();
            serve_with(Cursor::new(requests(tool, json!({}))), &mut output, |_| {
                panic!("approval must not run")
            })
            .unwrap();
            assert!(String::from_utf8(output)
                .unwrap()
                .contains("permits only register"));
        }
    }

    #[test]
    fn registration_requires_completed_initialization() {
        let request=json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"register","arguments":{"name":"claude"}}}).to_string()+"\n";
        let mut output = Vec::new();
        serve_with(Cursor::new(request), &mut output, |_| {
            panic!("uninitialized caller cannot prompt")
        })
        .unwrap();
        let response: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(response["error"]["code"], -32004);
    }

    #[test]
    fn only_a_valid_name_can_reach_approval() {
        for args in [
            json!({}),
            json!({"name":"bad name"}),
            json!({"name":"claude","process":"/bin/true"}),
            json!({"name":"claude","permissions":["exec"]}),
        ] {
            let mut output = Vec::new();
            serve_with(Cursor::new(requests("register", args)), &mut output, |_| {
                panic!("invalid arguments must not prompt")
            })
            .unwrap();
            assert!(String::from_utf8(output).unwrap().contains("isError"));
        }
    }

    #[test]
    fn declined_registration_returns_a_tool_error_with_original_id() {
        let mut output = Vec::new();
        serve_with(
            Cursor::new(requests("register", json!({"name":"claude"}))),
            &mut output,
            |_| Err("Registration declined".into()),
        )
        .unwrap();
        let response: Value = serde_json::from_slice(
            output
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .last()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response["id"], 7);
        assert_eq!(response["result"]["isError"], true);
    }

    #[test]
    fn approved_registration_returns_structured_client_identity() {
        let mut output = Vec::new();
        serve_with(
            Cursor::new(requests("register", json!({"name":"claude"}))),
            &mut output,
            |args| Ok(json!({"status":"registered","client":args.name})),
        )
        .unwrap();
        let response: Value = serde_json::from_slice(
            output
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .last()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response["result"]["structuredContent"]["client"], "claude");
    }
}
