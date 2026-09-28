# LARP quick start

Build with `sh scripts/build-release.sh` from the LARP source directory. It removes builder-specific paths from the release binary.

1. **Prepare 1Password.** Install and unlock the 1Password desktop app. In **Settings → Labs → MCP Server**, enable the local server; then open **Settings → Developer → Integrate with MCP clients**. Install the 1Password CLI too. Check that both `1password-mcp` and `op` are on your `PATH`, then run `larp auth`. LARP uses the MCP server for approval and `op read` to load vault references at startup. [1Password MCP setup](https://www.1password.dev/environments/mcp-server) · [1Password CLI](https://developer.1password.com/docs/cli/secrets-scripts)

2. **Create a vault and item.** In 1Password, make a vault for this project and put its API keys in an item named **Credentials**. Give each field the environment variable's name. Copy each field's `op://vault/item/field` reference; never copy its value into LARP.

3. **Make `.env.op` in the project directory.** It contains references only, for example:

   ```dotenv
   API_TOKEN=op://Project Dev/Credentials/API_TOKEN
   SERVICE_PASSWORD=op://Project Dev/Credentials/SERVICE_PASSWORD
   ```

4. **Register the project, client, secrets, and command.** From the project directory, run `larp admin`. The first run asks you to set an admin password. At `larp>` enter:

   ```text
   project add demo --cwd .
   client add
   secret import demo .env.op
   command add demo check "pwd" --cwd .
   permission add codex command demo check
   permission add codex secret demo API_TOKEN
   permission add codex secret demo SERVICE_PASSWORD
   permission list codex
   exit
   ```

   At the `client add` prompts, enter `codex` and the absolute path to Codex's executable. For an import from a relative path, confirm the absolute file path LARP displays. Importing secrets does not grant access; the `permission` lines do.

   If you do not know the client's executable path, start LARP and connect the client once. The `larp start` terminal shows the path for an unregistered caller and a `client add` command to copy into the admin console. The MCP caller sees only an authorization error.

5. **Connect to secrets.** Run `larp start` in a terminal. Approve the 1Password CLI request and wait for **LARP ready**. Keep this terminal open. LARP loads the registered values into memory; an unreadable reference stops startup and names the project and secret that need attention.

6. **Connect the MCP client.** Configure your client to launch the absolute path to `larp mcp`. For Codex:

   ```toml
   [mcp_servers.larp]
   command = "/absolute/path/to/larp"
   args = ["mcp"]
   ```

   For Windsurf Cascade, put this entry in `~/.config/devin/mcp_config.json` (the file shown in Cascade's MCP settings):

   ```json
   {
     "mcpServers": {
       "larp": {
         "command": "/usr/local/bin/larp",
         "args": ["mcp"]
       }
     }
   }
   ```

   Replace `/usr/local/bin/larp` with your installed LARP path if different. Keep any other entries already in `mcpServers`. Start `larp start` separately, then connect Cascade. If Cascade is not registered, the `larp start` terminal shows its executable path; add it as a client and grant it the project permissions it needs.

7. **Test without exposing values.** Ask the client to call `commands(project="demo")`, then `command(project="demo", name="check", env="/absolute/path/to/project/.env.op")`. The `env` path must be absolute. LARP injects only registered references granted to that client and returns redacted command output. Without `env`, it injects no secrets. Replace `pwd` with a useful project command once the connection works.

If LARP is stopped, the MCP connection stays open and tool calls return a retryable error. Start LARP and retry the call in the same chat. A bridge launched directly from a terminal has that terminal's caller identity; test client permissions through the registered MCP application.

An `exec` grant is separate and allows arbitrary commands in the project. Add it only if that client needs it: `permission add codex exec demo`.
