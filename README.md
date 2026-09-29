# LARP

LARP is a local Rust action runner for commands that need 1Password secrets. An administrator registers clients, projects, commands, and secret references. `larp start` obtains registered secret values from 1Password and keeps them in memory. MCP callers may execute only commands and secrets granted to their verified client.

For a short setup walkthrough, see [QUICKSTART.md](QUICKSTART.md).

Install the macOS binary with `brew install brandoncarl/tap/larp`. Homebrew installs a prebuilt archive for Apple Silicon or Intel; users do not need Rust or LLVM. See the [Homebrew release guide](packaging/homebrew/README.md) for publishing.

## Start

```sh
larp admin
```

The first admin session sets a password of at least 12 characters. At the `larp>` prompt, short commands and pasted `larp ...` commands both work:

```text
larp> client add codex /absolute/path/to/codex
larp> project add demo --cwd /path/to/project
larp> command add demo check "pwd" --cwd /path/to/project
larp> secret add demo API_TOKEN "op://Project Vault/Credentials/API_TOKEN"
larp> permission add codex command demo check
larp> permission add codex secret demo API_TOKEN
larp> exit
```

Start the server in another terminal and approve 1Password access:

```sh
larp start
```

Configure Codex to launch the bridge using the absolute path reported by `command -v larp`:

```toml
[mcp_servers.larp]
command = "/absolute/path/to/larp"
args = ["mcp"]
```

Windsurf Cascade uses a JSON `mcpServers` entry instead. See the [Cascade example in the quick start](QUICKSTART.md) and keep `larp start` running separately.

The server and bridge must run the same LARP version. Start the server from a shell whose `PATH` includes the tools your commands need; restart it after changing that `PATH`. Permission, command, project, and secret registration changes take effect on the next MCP call. LARP loads only new or changed secret references from 1Password and updates its in-memory set after every read succeeds. A failed read leaves the prior set intact and returns an error you can retry. Client registration changes take effect on the next connection; reconnect the MCP client after a client change. `start` does not ask for the LARP admin password. The bridge opens a fresh local connection for each request, so restarting `larp start` does not leave an existing MCP chat attached to a dead socket. A call made while the server is unavailable returns a retryable error. LARP never automatically retries a command whose outcome is unknown.

## Use a reference file

Create a file containing **only 1Password references**. `.env.op` is ignored by default because its vault, item, and field names may be sensitive. If you want to share a template, commit `.env.op.example`:

```dotenv
# /path/to/project/.env.op
API_TOKEN=op://Project Vault/Credentials/API_TOKEN
```

Register all its references in one step from the admin console:

```text
larp> secret import demo .env.op
```

For a relative path, LARP resolves it from the admin console's current directory and shows the absolute directory and file for confirmation before reading. Absolute paths also work. LARP validates the whole file before changing its registry. It skips identical registrations. For each name whose registered reference differs, choose **Yes** to overwrite it, **No** to keep it, or **Abort** to save nothing from the import. A non-interactive import with conflicts fails without changes. The import does not grant any client access; use `permission add <client> secret <project> <name>` for each secret the client may receive. **Existing grants by name continue to apply after an overwrite**, so review the new reference before choosing Yes. LARP loads added or replaced references on the next MCP call.

The file is read for each MCP call. LARP uses its variable names, matches each `op://` reference to a secret registered under that project, checks the calling client's secret grant, and injects the value already held in memory. It rejects the whole call if any reference is unregistered or ungranted. Changing the file needs no restart when all its references are already registered and loaded. Registering a new reference loads it on the next MCP call. To pick up a changed value at an unchanged reference, restart `larp start`.

The `env` parameter is an **absolute path** to a regular reference-only file. It is optional; without it, LARP injects no secrets. The file is limited to 1 MiB and 256 variables. Plaintext values, duplicate names, and reserved execution variables such as `PATH` are rejected. LARP does not save the file path or resolved values in its registry.

## MCP tools

LARP exposes three tools:

| Tool | Parameters | What it does |
| --- | --- | --- |
| `commands` | Optional `project` | Lists this client's granted commands, `exec` access, and secret names across projects, or filters to one project. It returns no values or 1Password references. |
| `command` | `project`, `name`, optional `env` | Runs a registered command with its saved arguments and working directory. |
| `exec` | `project`, `argv`, optional `env` | Runs caller-supplied argument array in the project's fixed working directory. Requires a separate `exec` grant. |

Call `commands` first if you do not know what this client can run. To run the registered `check` command with the file above:

```json
{"project":"demo","name":"check","env":"/path/to/project/.env.op"}
```

For an ad hoc command, first grant `exec` to the client for that project. It still needs a grant for every secret named by the file:

```text
larp> permission add codex exec demo
```

```json
{"project":"demo","argv":["pwd"],"env":"/path/to/project/.env.op"}
```

An `exec` grant plus a secret grant permits arbitrary code to use that secret. Grant this combination only to clients trusted with that ability. LARP executes argument arrays directly; a shell runs only if explicitly named in `argv`.

## Admin commands

```text
client add [name process-path]       client remove <name>       client list
project add <name> [--cwd <path>]    project cwd <name> <path>
project rename <old> <new>
project remove <name>                project list
command add <project> <name> <command> [--cwd <path>]
command update <project> <name> <command> [--cwd <path>]
command remove <project> <name>      command list <project>
secret add <project> <name> <op://reference>
secret import <project> <file>
secret remove <project> <name>       secret list <project>
permission add <client> command|secret <project> <name>
permission remove <client> command|secret <project> <name>
permission add <client> exec <project>
permission remove <client> exec <project>
permission list <client>
password change                     help      exit
```

`larp` and `larp help` show the launcher commands. In the console, `help` shows management commands. Up and Down browse history; Option+Left and Option+Right move by word. `larp help mcp`, `larp client --help`, and `larp client add --help` work without admin authentication; `client add --help` works in the console. Standalone management commands ask for the admin password each time; the console asks once and locks after 15 minutes of inactivity. `password change` asks for the current password. Passwords are read without terminal echo and are not accepted as arguments or environment variables.

`command update` replaces a saved command without removing its client grants. Use it to replace older commands whose executable was saved as an absolute path.
For `command add` and `command update`, `--cwd` may be relative to the directory where you launched the admin console. LARP shows the resolved absolute directory for confirmation, then saves it. Without `--cwd`, it saves the console's current directory.

## Security and storage

LARP stores the registry in `~/.config/larp/registry.json` and a salted Argon2id admin password verifier in `~/.config/larp/admin.phc`. The directory is `0700`; files are `0600`. The registry holds references and grants, not resolved values. Existing registry files with legacy environment bindings still load; those bindings are ignored and removed on the next save. Valid files from the former macOS location migrate automatically without overwriting conflicts.

MCP captures stdout and stderr and returns them after the command ends, with exit code, timeout, and truncation status. Each stream is limited to 64 KiB; commands time out after 120 seconds. LARP replaces loaded secret values and common Base64, hex, URL, and JSON encodings in returned logs with `REDACTED`. Partial values, hashes, and custom transformations can still leak. Commands run as your macOS user and are not sandboxed. LARP snapshots the `PATH` of `larp start`, adds the project's `node_modules/.bin`, and passes that PATH to child processes. MCP callers cannot override it. The launched executable's directory is also included so its scripts can find it.

The private socket is `/private/tmp/larp-<user ID>/mcp.sock`. LARP checks its peer user and PID and resolves the bridge's parent from macOS. Signed client registrations use a captured code-signing requirement; unsigned and older registrations are explicitly **path-only**. Remove and re-add an older signed client to capture its signature. MCP `clientInfo` is not used as identity.

The `larp start` terminal shows short, readable client and command activity. It does not print process paths, PIDs, command arguments, environment values, or secret references. The private rotating audit file remains JSON Lines for structured review and records decisions without command output or secret values.

Audit records go to private `~/.config/larp/audit.jsonl`, rotate at 10 MiB, and retain five files. They include a LARP-generated `requestId`, client, project, tool, permission decision, duration, exit status, timeout, and resolved executable. The same `requestId` appears in tool results and malformed or oversized request errors, so those calls can be matched to their audit records. LARP does not log the client-supplied JSON-RPC ID, arguments, file contents, references, environment values, or command output. Defaults are 32 concurrent commands and 128 MCP connections; `LARP_MAX_COMMANDS` and `LARP_MAX_CONNECTIONS` configure them on the server process.

`larp auth` checks 1Password approval without printing secret values.
