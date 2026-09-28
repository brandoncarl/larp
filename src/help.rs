#[derive(Clone, Copy)]
pub enum Context {
    Cli,
    Admin,
}

pub fn print(topic: Option<&str>, context: Context) -> Result<(), String> {
    let help = text(topic, context)?;
    for (index, line) in help.lines().enumerate() {
        let category = matches!(context, Context::Admin)
            && topic.is_none()
            && matches!(
                line.split_whitespace().next(),
                Some(
                    "client"
                        | "project"
                        | "command"
                        | "secret"
                        | "permission"
                        | "password"
                        | "exit"
                )
            )
            && !line.starts_with(' ');
        if index == 0 || category {
            println!("{}", crate::ui::heading(line));
        } else {
            println!("{line}");
        }
    }
    Ok(())
}

fn text(topic: Option<&str>, context: Context) -> Result<&'static str, String> {
    let help = match topic {
        None if matches!(context, Context::Cli) => r#"LARP: run local commands with 1Password secrets

  larp admin                  Manage clients, projects, and access
  larp start                  Approve 1Password and start the server
  larp mcp                    Connect an MCP client
  larp auth                   Check 1Password access
  larp help [topic]           Show help

Run `larp admin`, then `help`, to see management commands."#,
        None => r#"Admin commands

list                                                        Show clients and projects

client                                                      MCP callers
  add [<name> <path>]                                       Register a client; prompts if omitted
  remove <name>                                             Remove a client and its grants
  list                                                      Show clients

project                                                     Commands and secrets
  add <name> [--cwd <path>]                                 Create a project
  cwd <name> <path>                                         Set the working directory
  rename <old> <new>                                        Rename a project and its grants
  remove <name>                                             Remove a project and its grants
  list                                                      Show projects

command                                                     Saved commands
  add <project> <name> "<command>" [--cwd <path>]           Save a command
  update <project> <name> "<command>" [--cwd <path>]        Replace a command; keep grants
  remove <project> <name>                                   Remove a command
  list <project>                                            Show saved commands

secret                                                      1Password references
  add <project> <name> <op://reference>                     Register a reference
  import <project> <file>                                   Import references from a file
  remove <project> <name>                                   Remove a reference and its grants
  list <project>                                            Show references

permission                                                  Client access
  add <client> command <project> <name>                     Allow a saved command
  add <client> secret <project> <name>                      Allow a secret
  add <client> exec <project>                               Allow arbitrary commands
  remove <client> command|secret <project> <name>           Revoke a command or secret
  remove <client> exec <project>                            Revoke arbitrary commands
  list <client>                                             Show grants

password                                                    Admin password
  change                                                    Set a new password

exit                                                        End this session

Use `help <topic>` for details. Full `larp ...` commands also work here.
Option+Left/Right moves by word; Up/Down browses history."#,
        Some("client") => r#"Register the executable that calls LARP through MCP.
  client add <name> <absolute-process-path>
  client add                 Prompt for name and path
  client list
  client remove <name>"#,
        Some("project") => r#"Group commands and secret references.
  project add <name> [--cwd <absolute-directory>]
  project cwd <name> <absolute-directory>
  project rename <old> <new>
  project list
  project remove <name>"#,
        Some("command") => r#"Save a command and its working directory.
  command add <project> <name> "<command and arguments>" [--cwd <directory>]
  command update <project> <name> "<command and arguments>" [--cwd <directory>]
  command list <project>
  command remove <project> <name>
Relative --cwd paths are shown as absolute paths for confirmation before saving."#,
        Some("secret") => r#"Register 1Password references, not secret values.
  secret add <project> <name> <op://vault/item/field>
  secret import <project> <file>
  secret list <project>
  secret remove <project> <name>
Import reads NAME=op://... lines. It skips matches and asks about conflicts:
Yes replaces, No keeps, Abort cancels the import. Grants stay in place.
For a relative path, LARP shows the absolute path before reading."#,
        Some("mcp") => r#"MCP tools for verified clients:
  commands(project?)             List access across projects, or filter by project
  command(project, name, env?)   Run a saved command
  exec(project, argv, env?)      Run an argument array; requires exec access

env is an optional absolute path to a NAME=op://... file.
Each reference must be registered and granted to the client."#,
        Some("permission") => r#"Clients start with no access.
  permission add <client> command <project> <command-name>
  permission add <client> secret <project> <secret-name>
  permission add <client> exec <project>
  permission list <client>
  permission remove <client> command|secret <project> <name>
  permission remove <client> exec <project>
An exec grant and a secret grant let a client use that secret in any command."#,
        Some("password") => r#"In the admin console:
  password change             Set a new password
  exit                        End the session"#,
        Some("list") => "list                         Show clients and projects",
        Some(other) => return Err(format!("unknown help topic '{other}'. Try client, project, command, secret, mcp, permission, or password")),
    };
    Ok(help)
}

pub fn maybe_print(words: &[&str], context: Context) -> Result<bool, String> {
    if words.len() >= 2 && matches!(words.last(), Some(&("--help" | "-h"))) && is_topic(words[0]) {
        if words.len() == 2 {
            print(Some(words[0]), context)?;
        } else {
            print_action(words[0], words[1])?;
        }
        return Ok(true);
    }
    match words {
        [] | ["help" | "--help" | "-h"] => print(None, context)?,
        ["help", topic] => print(Some(topic), context)?,
        ["mcp", "--help" | "-h"] => print(Some("mcp"), context)?,
        ["help", topic, action] => print_action(topic, action)?,
        ["list", "--help" | "-h"] => print(Some("list"), context)?,
        [topic] if is_topic(topic) => print(Some(topic), context)?,
        [topic, "--help" | "-h"] if is_topic(topic) => print(Some(topic), context)?,
        [topic, action, "--help" | "-h"] if is_topic(topic) => print_action(topic, action)?,
        _ => return Ok(false),
    }
    Ok(true)
}

fn is_topic(value: &str) -> bool {
    matches!(
        value,
        "client" | "project" | "command" | "secret" | "permission" | "password"
    )
}

pub(crate) fn print_action(topic: &str, action: &str) -> Result<(), String> {
    let usage = match (topic, action) {
        ("client", "add") => "client add [<name> <absolute-process-path>]\nRegister an MCP client. With no arguments, LARP prompts for both fields.",
        ("client", "remove") => "client remove <name>\nRemove a client and all its grants.",
        ("client", "list") => "client list\nShow registered clients and their process paths.",
        ("project", "add") => "project add <name> [--cwd <absolute-directory>]\nCreate a project. Without --cwd, use the current directory.",
        ("project", "cwd") => "project cwd <name> <absolute-directory>\nSet the fixed working directory used by MCP exec.",
        ("project", "rename") => "project rename <old> <new>\nRename a project, keeping its commands, secrets, and client grants.",
        ("project", "remove") => "project remove <name>\nRemove the project and its client grants.",
        ("project", "list") => "project list\nShow projects and their exec working directories.",
        ("command", "add") => "command add <project> <name> \"<command and arguments>\" [--cwd <directory>]\nSave a command. Relative --cwd paths are confirmed and saved as absolute paths.",
        ("command", "update") => "command update <project> <name> \"<command and arguments>\" [--cwd <directory>]\nReplace a saved command and keep its grants. Relative --cwd paths are confirmed.",
        ("command", "remove") => "command remove <project> <name>\nRemove a fixed command and related grants.",
        ("command", "list") => "command list <project>\nShow fixed commands and their working directories.",
        ("secret", "add") => "secret add <project> <name> <op://vault/item/field>\nRegister a 1Password reference, not its value.",
        ("secret", "import") => "secret import <project> <file>\nRegister NAME=op://... entries. Relative paths are resolved from the current directory and confirmed before reading. Validate the whole file first, skip identical entries, then resolve conflicts with Yes, No, or Abort before saving anything. Existing grants are unchanged.",
        ("secret", "remove") => "secret remove <project> <name>\nRemove a reference and its grants.",
        ("secret", "list") => "secret list <project>\nShow registered names and 1Password references.",
        ("permission", "add" | "grant") => "permission add <client> command|secret <project> <name>\npermission add <client> exec <project>\nGrant one capability. Exec plus a secret grant permits arbitrary code with the secret.",
        ("permission", "remove" | "revoke") => "permission remove <client> command|secret <project> <name>\npermission remove <client> exec <project>\nRevoke one capability.",
        ("permission", "list") => "permission list <client>\nShow all command, secret, and exec grants.",
        ("password", "change") => "password change\nIn the admin console, enter the current password and set a new one.",
        _ => return Err(format!("unknown help topic '{topic} {action}'")),
    };
    println!("Usage: {usage}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{maybe_print, text, Context};

    #[test]
    fn help_is_contextual_without_admin_authentication() {
        assert!(maybe_print(&["client"], Context::Cli).unwrap());
        assert!(maybe_print(&["client", "--help"], Context::Cli).unwrap());
        assert!(maybe_print(&["client", "add", "--help"], Context::Cli).unwrap());
        assert!(maybe_print(&["client", "add", "example", "--help"], Context::Cli).unwrap());
        assert!(maybe_print(&["help", "secret", "add"], Context::Cli).unwrap());
        assert!(maybe_print(&["help", "mcp"], Context::Cli).unwrap());
        assert!(!maybe_print(&["mcp"], Context::Cli).unwrap());
        assert!(!maybe_print(&["client", "list"], Context::Cli).unwrap());
        assert!(!maybe_print(&["list"], Context::Cli).unwrap());
    }

    #[test]
    fn overview_matches_the_surface() {
        let cli = text(None, Context::Cli).unwrap();
        assert!(cli.contains("larp start"));
        assert!(!cli.contains("larp test"));
        assert!(!cli.contains("larp config"));
        let admin = text(None, Context::Admin).unwrap();
        assert!(admin.contains("  add [<name> <path>]"));
        assert!(admin.contains("exit"));
        assert!(!admin.contains("lock                                                        "));
        assert!(admin.contains("  change"));
        assert!(!admin.contains("larp start"));
        assert!(!admin.contains("Example:"));
        let rows = admin
            .split_once("Admin commands\n\n")
            .unwrap()
            .1
            .split_once("\n\nUse `help")
            .unwrap()
            .0;
        for line in rows.lines().filter(|line| !line.is_empty()) {
            assert!(line.len() <= 100, "help row exceeds 100 columns: {line}");
            assert!(
                !line[60..].is_empty(),
                "help row lacks a description: {line}"
            );
            assert!(
                line[..60].ends_with(' '),
                "description is not aligned: {line}"
            );
        }
    }
}
