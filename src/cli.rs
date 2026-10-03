use crate::admin::AdminSession;
use crate::registry::{self, Client, Project, RegisteredCommand, Registry};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub fn run(args: &[String], _: &AdminSession) -> Result<(), String> {
    let mut registry = Registry::load()?;
    let mut changed = false;
    let mut import_report = None;
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["list"] => {
            println!("Clients ({}):", registry.clients.len());
            if registry.clients.is_empty() {
                println!("  None. Use 'client add'.");
            }
            for name in registry.clients.keys() {
                println!("  {name}");
            }
            println!("Projects ({}):", registry.projects.len());
            if registry.projects.is_empty() {
                println!("  None. Use 'project add <name> --cwd <path>'.");
            }
            for name in registry.projects.keys() {
                println!("  {name}");
            }
        }
        ["client", "add"] => {
            let name = prompt("Client name: ")?;
            let process = prompt("Absolute process path: ")?;
            add_client(&mut registry, &name, &process)?;
            changed = true;
        }
        ["client", "add", name, process] => {
            add_client(&mut registry, name, process)?;
            changed = true;
        }
        ["client", "update", name] => {
            let process = prompt("Absolute process path (supports *): ")?;
            update_client(&mut registry, name, &process)?;
            changed = true;
        }
        ["client", "update", name, process] => {
            update_client(&mut registry, name, process)?;
            changed = true;
        }
        ["client", "remove", name] => {
            required_remove(registry.clients.remove(*name), "client")?;
            changed = true;
        }
        ["client", "list"] => {
            if registry.clients.is_empty() {
                println!("No clients. Use 'client add' to register one.");
            }
            for (name, client) in &registry.clients {
                println!("{name}\t{}\t{}", client.identity.label(), client.process);
            }
        }
        ["project", "add", name] | ["project", "add", name, "--cwd", _] => {
            registry::name(name)?;
            if registry.projects.contains_key(*name) {
                return Err("project already exists".into());
            }
            let cwd = if words.len() == 5 {
                canonical_cwd(words[4])?
            } else {
                canonical_cwd(
                    &std::env::current_dir()
                        .map_err(|_| "could not read cwd")?
                        .to_string_lossy(),
                )?
            };
            registry.projects.insert(
                name.to_string(),
                Project {
                    cwd,
                    ..Project::default()
                },
            );
            changed = true;
        }
        ["project", "cwd", name, path] => {
            let cwd = canonical_cwd(path)?;
            project_mut(&mut registry, name)?.cwd = cwd;
            changed = true;
        }
        ["project", "rename", old, new] => {
            registry.rename_project(old, new)?;
            changed = true;
        }
        ["project", "remove", name] => {
            required_remove(registry.projects.remove(*name), "project")?;
            for client in registry.clients.values_mut() {
                client.commands.retain(|(project, _)| project != name);
                client.secrets.retain(|(project, _)| project != name);
                client.exec.remove(*name);
            }
            changed = true;
        }
        ["project", "list"] => {
            if registry.projects.is_empty() {
                println!("No projects. Use 'project add <name> --cwd <path>'.");
            }
            for (name, project) in &registry.projects {
                println!("{name}\t{}", project.cwd);
            }
        }
        ["command", action @ ("add" | "update"), project, name, command]
        | ["command", action @ ("add" | "update"), project, name, command, "--cwd", _] => {
            registry::name(name)?;
            let existing = project_ref(&registry, project)?.commands.get(*name);
            if *action == "add" && existing.is_some() {
                return Err("command already exists; use 'command update' to replace it".into());
            }
            if *action == "update" && existing.is_none() {
                return Err("command does not exist; use 'command add' to create it".into());
            }
            let argv = shlex::split(command).ok_or("invalid command quoting")?;
            if argv.is_empty() {
                return Err("command is empty".into());
            }
            let current = std::env::current_dir().map_err(|_| "could not read cwd")?;
            let (cwd, relative) = match words.as_slice() {
                [.., "--cwd", path] => resolve_command_cwd(path, &current)?,
                _ if *action == "update" => (existing.unwrap().cwd.clone(), false),
                _ => resolve_command_cwd(&current.to_string_lossy(), &current)?,
            };
            if relative {
                confirm_command_cwd(&cwd)?;
            }
            crate::runner::resolve_executable(&argv[0], &cwd)?;
            let env = existing
                .map(|command| command.env.clone())
                .unwrap_or_default();
            let item = project_mut(&mut registry, project)?;
            item.commands
                .insert(name.to_string(), RegisteredCommand { argv, cwd, env });
            changed = true;
        }
        ["command", "env", project, name, "--clear"] => {
            project_mut(&mut registry, project)?
                .commands
                .get_mut(*name)
                .ok_or("command does not exist")?
                .env
                .clear();
            changed = true;
        }
        ["command", "env", project, name, path] => {
            if !project_ref(&registry, project)?
                .commands
                .contains_key(*name)
            {
                return Err("command does not exist".into());
            }
            let current = std::env::current_dir().map_err(|_| "could not read cwd")?;
            let (resolved, relative) = resolve_import_path(path, &current)?;
            if relative {
                confirm_reference_path(&resolved, "command environment")?;
            }
            let mappings = crate::env_file::read(&resolved.to_string_lossy())?;
            let env = command_env_bindings(project_ref(&registry, project)?, &mappings)?;
            project_mut(&mut registry, project)?
                .commands
                .get_mut(*name)
                .expect("command checked above")
                .env = env;
            changed = true;
        }
        ["command", "remove", project, name] => {
            required_remove(
                project_mut(&mut registry, project)?.commands.remove(*name),
                "command",
            )?;
            for client in registry.clients.values_mut() {
                client
                    .commands
                    .remove(&(project.to_string(), name.to_string()));
            }
            changed = true;
        }
        ["command", "list", project] => {
            let commands = &project_ref(&registry, project)?.commands;
            if commands.is_empty() {
                println!("No commands in {project}. Use 'command add {project} <name> <command>'.");
            }
            for (name, command) in commands {
                println!(
                    "{name}\t{}\t{}\t{}",
                    command.cwd,
                    shlex::try_join(command.argv.iter().map(String::as_str)).unwrap_or_default(),
                    command.env.keys().cloned().collect::<Vec<_>>().join(",")
                );
            }
        }
        ["secret", "add", project, name, reference] => {
            registry::name(name)?;
            if !reference.starts_with("op://")
                || reference.len() <= 5
                || reference.len() > 1024
                || reference.chars().any(char::is_control)
            {
                return Err("secret must be an op:// reference".into());
            }
            let item = project_mut(&mut registry, project)?;
            if item.secrets.contains_key(*name) {
                return Err("secret already exists".into());
            }
            item.secrets.insert(name.to_string(), reference.to_string());
            changed = true;
        }
        ["secret", "import", project, path] => {
            let existing = &project_ref(&registry, project)?.secrets;
            let (resolved, relative) = resolve_import_path(
                path,
                &std::env::current_dir().map_err(|_| "could not read cwd")?,
            )?;
            if relative {
                confirm_import_path(&resolved)?;
            }
            let incoming = crate::env_file::read(&resolved.to_string_lossy())?;
            let plan = plan_secret_import(existing, &incoming, confirm_secret_overwrite)?;
            let item = project_mut(&mut registry, project)?;
            for (name, reference) in plan.changes.iter().cloned() {
                item.secrets.insert(name, reference);
            }
            changed = !plan.changes.is_empty();
            import_report = Some(plan);
        }
        ["secret", "remove", project, name] => {
            let item = project_mut(&mut registry, project)?;
            required_remove(item.secrets.remove(*name), "secret")?;
            for client in registry.clients.values_mut() {
                client
                    .secrets
                    .remove(&(project.to_string(), name.to_string()));
            }
            changed = true;
        }
        ["secret", "list", project] => {
            let secrets = &project_ref(&registry, project)?.secrets;
            if secrets.is_empty() {
                println!("No secrets in {project}. Use 'secret add'.");
            }
            for (name, reference) in secrets {
                println!("{name}\t{reference}");
            }
        }
        ["permission", "add" | "grant", client, kind, project, name] => {
            let record = registry
                .clients
                .get_mut(*client)
                .ok_or("client does not exist")?;
            let target = registry
                .projects
                .get(*project)
                .ok_or("project does not exist")?;
            let grant = (project.to_string(), name.to_string());
            match *kind {
                "command" if target.commands.contains_key(*name) => {
                    if !record.commands.insert(grant) {
                        return Err("permission already exists".into());
                    }
                }
                "secret" if target.secrets.contains_key(*name) => {
                    if !record.secrets.insert(grant) {
                        return Err("permission already exists".into());
                    }
                }
                "command" if target.secrets.contains_key(*name) => {
                    return Err(format!(
                        "{name} is a secret; use 'permission add {client} secret {project} {name}'"
                    ));
                }
                "secret" if target.commands.contains_key(*name) => {
                    return Err(format!(
                        "{name} is a command; use 'permission add {client} command {project} {name}'"
                    ));
                }
                _ => return Err("command or secret does not exist in this project".into()),
            }
            changed = true;
        }
        ["permission", "add" | "grant", client, "exec", project] => {
            if !registry.projects.contains_key(*project) {
                return Err("project does not exist".into());
            }
            let record = registry
                .clients
                .get_mut(*client)
                .ok_or("client does not exist")?;
            if !record.exec.insert(project.to_string()) {
                return Err("permission already exists".into());
            }
            changed = true;
        }
        ["permission", "remove" | "revoke", client, "exec", project] => {
            let record = registry
                .clients
                .get_mut(*client)
                .ok_or("client does not exist")?;
            if !record.exec.remove(*project) {
                return Err("permission does not exist".into());
            }
            changed = true;
        }
        ["permission", "remove" | "revoke", client, kind, project, name] => {
            let record = registry
                .clients
                .get_mut(*client)
                .ok_or("client does not exist")?;
            let grant = (project.to_string(), name.to_string());
            let removed = match *kind {
                "command" => record.commands.remove(&grant),
                "secret" => record.secrets.remove(&grant),
                _ => return Err("permission kind must be command or secret".into()),
            };
            if !removed {
                return Err("permission does not exist".into());
            }
            changed = true;
        }
        ["permission", "list", client] => {
            let record = registry
                .clients
                .get(*client)
                .ok_or("client does not exist")?;
            if record.commands.is_empty() && record.secrets.is_empty() && record.exec.is_empty() {
                println!("No permissions for {client}. Use 'permission add'.");
            }
            for (project, name) in &record.commands {
                println!("command\t{project}\t{name}");
            }
            for (project, name) in &record.secrets {
                println!("secret\t{project}\t{name}");
            }
            for project in &record.exec {
                println!("exec\t{project}");
            }
        }
        _ => {
            let topic = words.first().copied().unwrap_or("help");
            if words.len() >= 2 && crate::help::print_action(topic, words[1]).is_ok() {
                return Ok(());
            }
            return Err(format!("invalid {topic} command. Try '{topic} --help'"));
        }
    }
    if changed {
        registry.save()?;
        if words.first() != Some(&"secret") || words.get(1) != Some(&"import") {
            crate::ui::success(&success_message(&words));
        }
    }
    if let Some(report) = import_report {
        println!(
            "Secrets: {} added, {} overwritten, {} identical skipped, {} conflicts kept.",
            report.added, report.overwritten, report.identical, report.kept
        );
        if changed {
            println!("Updated references load on the next MCP call.");
        }
    }
    Ok(())
}

fn success_message(words: &[&str]) -> String {
    match words {
        ["permission", "add" | "grant", client, kind, project, name] => {
            format!("Granted {client} access to {kind} {name} in {project}.")
        }
        ["permission", "add" | "grant", client, "exec", project] => {
            format!("Granted {client} exec access in {project}.")
        }
        ["permission", "remove" | "revoke", client, kind, project, name] => {
            format!("Revoked {client} access to {kind} {name} in {project}.")
        }
        ["permission", "remove" | "revoke", client, "exec", project] => {
            format!("Revoked {client} exec access in {project}.")
        }
        [kind @ ("command" | "secret"), "add" | "update", project, name, ..] => {
            format!("Saved {kind} {name} in {project}.")
        }
        ["command", "env", project, name, ..] => {
            format!("Updated command environment for {name} in {project}.")
        }
        [kind @ ("command" | "secret"), "remove", project, name] => {
            format!("Removed {kind} {name} from {project}.")
        }
        [kind, "add", name, ..] | [kind, "update", name, ..] => {
            format!("Saved {kind} {name}.")
        }
        [kind, "remove", name, ..] => format!("Removed {kind} {name}."),
        ["project", "cwd", name, ..] => format!("Updated working directory for {name}."),
        ["project", "rename", old, new] => format!("Renamed project {old} to {new}."),
        _ => "Saved.".into(),
    }
}

fn command_env_bindings(
    project: &Project,
    mappings: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, String> {
    mappings
        .iter()
        .map(|(variable, reference)| {
            if project.secrets.get(variable) != Some(reference) {
                return Err(format!(
                    "command environment {variable} must match a registered secret of the same name"
                ));
            }
            Ok((variable.clone(), variable.clone()))
        })
        .collect()
}

fn resolve_import_path(path: &str, cwd: &Path) -> Result<(PathBuf, bool), String> {
    let input = Path::new(path);
    if input.is_absolute() {
        return Ok((input.to_path_buf(), false));
    }
    let joined = cwd.join(input);
    let parent = joined
        .parent()
        .ok_or("import file has no parent directory")?;
    let directory =
        std::fs::canonicalize(parent).map_err(|_| "could not resolve import directory")?;
    let filename = joined.file_name().ok_or("import path must name a file")?;
    Ok((directory.join(filename), true))
}

fn resolve_command_cwd(path: &str, current: &Path) -> Result<(String, bool), String> {
    let input = Path::new(path);
    let relative = !input.is_absolute();
    let chosen = if relative {
        current.join(input)
    } else {
        input.to_path_buf()
    };
    let directory = std::fs::canonicalize(chosen).map_err(|_| "command cwd does not exist")?;
    if !directory.is_dir() {
        return Err("command cwd is not a directory".into());
    }
    Ok((directory.to_string_lossy().into_owned(), relative))
}

fn confirm_command_cwd(path: &str) -> Result<(), String> {
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return Err("relative command cwd needs an interactive terminal; no changes saved".into());
    }
    println!("Command directory: {path}");
    loop {
        print!("Use this directory? [y]es / [n]o: ");
        io::stdout()
            .flush()
            .map_err(|_| "could not write cwd prompt")?;
        let mut answer = String::new();
        if io::stdin()
            .read_line(&mut answer)
            .map_err(|_| "could not read cwd response")?
            == 0
        {
            return Err("command cancelled; no changes saved".into());
        }
        match answer.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(()),
            "n" | "no" => return Err("command cancelled; no changes saved".into()),
            _ => println!("Choose Yes or No."),
        }
    }
}

fn confirm_import_path(path: &Path) -> Result<(), String> {
    confirm_reference_path(path, "secret import")
}

fn confirm_reference_path(path: &Path, purpose: &str) -> Result<(), String> {
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return Err(format!(
            "relative {purpose} paths need an interactive terminal; no changes saved"
        ));
    }
    println!(
        "{purpose} directory: {}",
        path.parent().unwrap_or(path).display()
    );
    println!("{purpose} file: {}", path.display());
    loop {
        print!("Use this file? [y]es / [n]o: ");
        io::stdout()
            .flush()
            .map_err(|_| "could not write import prompt")?;
        let mut answer = String::new();
        if io::stdin()
            .read_line(&mut answer)
            .map_err(|_| "could not read import response")?
            == 0
        {
            return Err(format!("{purpose} cancelled; no changes saved"));
        }
        match answer.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(()),
            "n" | "no" => return Err(format!("{purpose} cancelled; no changes saved")),
            _ => println!("Choose Yes or No."),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImportDecision {
    Yes,
    No,
    Abort,
}

#[derive(Default)]
struct ImportPlan {
    changes: Vec<(String, String)>,
    added: usize,
    overwritten: usize,
    identical: usize,
    kept: usize,
}

fn plan_secret_import(
    existing: &BTreeMap<String, String>,
    incoming: &BTreeMap<String, String>,
    mut decide: impl FnMut(&str, &str, &str) -> Result<ImportDecision, String>,
) -> Result<ImportPlan, String> {
    let mut plan = ImportPlan::default();
    for (name, reference) in incoming {
        match existing.get(name) {
            None => {
                plan.changes.push((name.clone(), reference.clone()));
                plan.added += 1;
            }
            Some(current) if current == reference => plan.identical += 1,
            Some(current) => match decide(name, current, reference)? {
                ImportDecision::Yes => {
                    plan.changes.push((name.clone(), reference.clone()));
                    plan.overwritten += 1;
                }
                ImportDecision::No => plan.kept += 1,
                ImportDecision::Abort => {
                    return Err("secret import aborted; no changes saved".into())
                }
            },
        }
    }
    Ok(plan)
}

fn confirm_secret_overwrite(
    name: &str,
    current: &str,
    incoming: &str,
) -> Result<ImportDecision, String> {
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return Err(
            "secret import has conflicts and needs an interactive terminal; no changes saved"
                .into(),
        );
    }
    println!("Conflict for {name}:\n  Registered: {current}\n  File:       {incoming}");
    println!("Existing client grants for {name} will apply to the replacement.");
    loop {
        print!("Overwrite {name}? [y]es / [n]o / [a]bort: ");
        io::stdout()
            .flush()
            .map_err(|_| "could not write import prompt")?;
        let mut answer = String::new();
        if io::stdin()
            .read_line(&mut answer)
            .map_err(|_| "could not read import response")?
            == 0
        {
            return Err("secret import aborted; no changes saved".into());
        }
        match answer.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(ImportDecision::Yes),
            "n" | "no" => return Ok(ImportDecision::No),
            "a" | "abort" => return Ok(ImportDecision::Abort),
            _ => println!("Choose Yes, No, or Abort."),
        }
    }
}

pub(crate) fn add_client(registry: &mut Registry, name: &str, process: &str) -> Result<(), String> {
    registry::name(name)?;
    if registry.clients.contains_key(name) {
        return Err("client already exists; use 'client update' to replace it".into());
    }
    let (process, identity) = prepare_client(registry, name, process)?;
    registry.clients.insert(
        name.to_string(),
        Client {
            identity,
            process,
            commands: BTreeSet::new(),
            secrets: BTreeSet::new(),
            exec: BTreeSet::new(),
        },
    );
    Ok(())
}

pub(crate) fn update_client(
    registry: &mut Registry,
    name: &str,
    process: &str,
) -> Result<(), String> {
    if !registry.clients.contains_key(name) {
        return Err("client does not exist".into());
    }
    let (process, identity) = prepare_client(registry, name, process)?;
    let client = registry
        .clients
        .get_mut(name)
        .expect("client checked above");
    client.process = process;
    client.identity = identity;
    Ok(())
}

fn prepare_client(
    registry: &Registry,
    name: &str,
    process: &str,
) -> Result<(String, registry::ClientIdentity), String> {
    registry::absolute_path(process)?;
    let wildcard = process.contains('*');
    if wildcard
        && process[1..]
            .split('/')
            .any(|part| part == "." || part == ".." || part.is_empty())
    {
        return Err("wildcard path must not contain empty, . or .. components".into());
    }
    let mut candidates = vec![PathBuf::from("/")];
    for component in process[1..].split('/') {
        let mut next = Vec::new();
        for parent in candidates {
            if component.contains('*') {
                let entries = match std::fs::read_dir(&parent) {
                    Ok(entries) => entries,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                        ) =>
                    {
                        continue
                    }
                    Err(_) => return Err("could not read wildcard client directory".into()),
                };
                for entry in entries {
                    let entry = entry.map_err(|_| "could not read wildcard client directory")?;
                    if entry
                        .file_name()
                        .to_str()
                        .is_some_and(|value| registry::component_matches(component, value))
                    {
                        next.push(entry.path());
                    }
                }
            } else {
                next.push(parent.join(component));
            }
        }
        candidates = next;
    }
    // A path edit that includes the existing executable keeps its trusted
    // identity. Running processes are still signature-checked on connection.
    let retained_identity = registry
        .clients
        .get(name)
        .filter(|client| {
            matches!(client.identity, registry::ClientIdentity::Signed { .. })
                && (client.process == process
                    || candidates.iter().any(|candidate| {
                        candidate
                            .canonicalize()
                            .ok()
                            .and_then(|path| path.to_str().map(str::to_owned))
                            .is_some_and(|path| registry::process_matches(&client.process, &path))
                    }))
        })
        .map(|client| client.identity.clone());
    let mut identity = None;
    let mut stored = process.to_owned();
    for candidate in candidates {
        if !candidate.is_file() {
            continue;
        }
        let canonical = candidate
            .canonicalize()
            .map_err(|_| "could not resolve client process")?;
        let canonical = canonical
            .to_str()
            .ok_or("client process path is not UTF-8")?;
        if wildcard && !registry::process_matches(process, canonical) {
            return Err("wildcard path must match the canonical executable path; use its resolved directory".into());
        }
        if registry.clients.iter().any(|(other, client)| {
            other != name && registry::process_matches(&client.process, canonical)
        }) {
            return Err("process is already registered to another client".into());
        }
        let captured = if let Some(identity) = &retained_identity {
            identity.clone()
        } else {
            crate::ui::note("Inspecting client signature; macOS verification may take a while...");
            crate::identity::capture(canonical)?
        };
        if identity
            .as_ref()
            .is_some_and(|previous| previous != &captured)
        {
            return Err("matching client executables have different signing identities; use a narrower path".into());
        }
        identity = Some(captured);
        if !wildcard {
            stored = canonical.to_owned();
        }
    }
    let identity = identity.ok_or("client path must match at least one existing file")?;
    if registry
        .clients
        .iter()
        .any(|(other, client)| other != name && client.process == stored)
    {
        return Err("process is already registered".into());
    }
    Ok((stored, identity))
}

fn canonical_cwd(path: &str) -> Result<String, String> {
    registry::absolute_path(path)?;
    let canonical = std::fs::canonicalize(path).map_err(|_| "cwd does not exist")?;
    if !canonical.is_dir() {
        return Err("cwd is not a directory".into());
    }
    Ok(canonical.to_string_lossy().into_owned())
}

fn project_mut<'a>(registry: &'a mut Registry, name: &str) -> Result<&'a mut Project, String> {
    registry
        .projects
        .get_mut(name)
        .ok_or("project does not exist".into())
}

fn project_ref<'a>(registry: &'a Registry, name: &str) -> Result<&'a Project, String> {
    registry
        .projects
        .get(name)
        .ok_or("project does not exist".into())
}

fn required_remove<T>(value: Option<T>, kind: &str) -> Result<(), String> {
    value
        .map(|_| ())
        .ok_or_else(|| format!("{kind} does not exist"))
}

fn prompt(label: &str) -> Result<String, String> {
    print!("{label}");
    io::stdout().flush().map_err(|_| "could not write prompt")?;
    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .map_err(|_| "could not read prompt")?;
    Ok(value.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        command_env_bindings, plan_secret_import, resolve_command_cwd, resolve_import_path,
        ImportDecision,
    };
    use std::collections::BTreeMap;
    use std::path::Path;

    #[test]
    fn command_environment_must_match_registered_references() {
        let mut project = crate::registry::Project::default();
        project
            .secrets
            .insert("API_KEY".into(), "op://vault/item/key".into());
        let mappings = BTreeMap::from([("API_KEY".into(), "op://vault/item/key".into())]);
        assert_eq!(
            command_env_bindings(&project, &mappings).unwrap()["API_KEY"],
            "API_KEY"
        );
        let wrong = BTreeMap::from([("API_KEY".into(), "op://vault/other/key".into())]);
        assert!(command_env_bindings(&project, &wrong).is_err());
        let alias = BTreeMap::from([("ALIAS".into(), "op://vault/item/key".into())]);
        assert!(command_env_bindings(&project, &alias).is_err());
    }

    #[test]
    fn wildcard_client_update_preserves_grants_and_failure_is_atomic() {
        let root = std::env::temp_dir().join(format!("larp-client-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let root = {
            std::fs::create_dir_all(&root).unwrap();
            root.canonicalize().unwrap()
        };
        for version in ["0.159.2-arm64", "0.160.0-arm64"] {
            let bin = root.join(version).join("bin");
            std::fs::create_dir_all(&bin).unwrap();
            std::fs::write(bin.join("codex"), "#!/bin/sh\nexit 0\n").unwrap();
        }
        let mut registry = crate::registry::Registry::default();
        super::add_client(
            &mut registry,
            "codex",
            root.join("0.159.2-arm64/bin/codex").to_str().unwrap(),
        )
        .unwrap();
        registry
            .clients
            .get_mut("codex")
            .unwrap()
            .commands
            .insert(("demo".into(), "check".into()));
        registry
            .clients
            .get_mut("codex")
            .unwrap()
            .secrets
            .insert(("demo".into(), "token".into()));
        registry
            .clients
            .get_mut("codex")
            .unwrap()
            .exec
            .insert("demo".into());
        let pattern = format!("{}/*/bin/codex", root.display());
        super::update_client(&mut registry, "codex", &pattern).unwrap();
        assert_eq!(registry.clients["codex"].process, pattern);
        assert_eq!(registry.clients["codex"].commands.len(), 1);
        assert_eq!(registry.clients["codex"].secrets.len(), 1);
        assert!(registry.clients["codex"].exec.contains("demo"));
        assert!(registry
            .client_for_process(root.join("0.160.0-arm64/bin/codex").to_str().unwrap())
            .is_some());
        assert!(super::add_client(&mut registry, "other", &pattern).is_err());
        // The fixture is unsigned: recapturing would replace this identity
        // with PathOnly. A path-only edit must retain the signed requirement.
        registry.clients.get_mut("codex").unwrap().identity =
            crate::registry::ClientIdentity::Signed {
                requirement: "test registered requirement".into(),
            };
        super::update_client(
            &mut registry,
            "codex",
            root.join("0.160.0-arm64/bin/codex").to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(registry.clients["codex"].identity.label(), "signed");
        super::update_client(&mut registry, "codex", &pattern).unwrap();
        assert_eq!(registry.clients["codex"].identity.label(), "signed");
        let before = serde_json::to_string(&registry).unwrap();
        assert!(super::update_client(
            &mut registry,
            "codex",
            &format!("{}/missing*/bin/codex", root.display())
        )
        .is_err());
        assert_eq!(before, serde_json::to_string(&registry).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn import_resolves_relative_file_from_admin_cwd() {
        let cwd = std::env::current_dir().unwrap();
        let (relative, needs_confirmation) = resolve_import_path(".env.op", &cwd).unwrap();
        assert!(needs_confirmation);
        assert_eq!(relative, cwd.canonicalize().unwrap().join(".env.op"));

        let absolute = Path::new("/tmp/.env.op");
        let (resolved, needs_confirmation) =
            resolve_import_path(absolute.to_str().unwrap(), &cwd).unwrap();
        assert_eq!(resolved, absolute);
        assert!(!needs_confirmation);
    }

    #[test]
    fn command_cwd_resolves_relative_directory_to_absolute() {
        let current = std::env::current_dir().unwrap();
        let expected = current
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            resolve_command_cwd(".", &current).unwrap(),
            (expected.clone(), true)
        );
        assert_eq!(
            resolve_command_cwd(&expected, &current).unwrap(),
            (expected, false)
        );
        assert!(resolve_command_cwd("Cargo.toml", &current).is_err());
    }

    #[test]
    fn import_skips_identical_and_applies_only_confirmed_conflicts() {
        let existing = BTreeMap::from([
            ("SAME".to_owned(), "op://vault/item/same".to_owned()),
            ("CHANGE".to_owned(), "op://vault/item/old".to_owned()),
        ]);
        let incoming = BTreeMap::from([
            ("SAME".to_owned(), "op://vault/item/same".to_owned()),
            ("CHANGE".to_owned(), "op://vault/item/new".to_owned()),
            ("NEW".to_owned(), "op://vault/item/added".to_owned()),
        ]);
        let plan = plan_secret_import(&existing, &incoming, |name, _, _| {
            assert_eq!(name, "CHANGE");
            Ok(ImportDecision::No)
        })
        .unwrap();
        assert_eq!(
            (plan.added, plan.overwritten, plan.identical, plan.kept),
            (1, 0, 1, 1)
        );
        assert_eq!(
            plan.changes,
            [("NEW".into(), "op://vault/item/added".into())]
        );

        let plan =
            plan_secret_import(&existing, &incoming, |_, _, _| Ok(ImportDecision::Yes)).unwrap();
        assert_eq!(
            (plan.added, plan.overwritten, plan.identical, plan.kept),
            (1, 1, 1, 0)
        );
        assert_eq!(existing["CHANGE"], "op://vault/item/old");
    }

    #[test]
    fn abort_discards_the_entire_preflight_plan() {
        let existing =
            BTreeMap::from([("Z_CONFLICT".to_owned(), "op://vault/item/old".to_owned())]);
        let incoming = BTreeMap::from([
            ("A_NEW".to_owned(), "op://vault/item/new".to_owned()),
            (
                "Z_CONFLICT".to_owned(),
                "op://vault/item/replacement".to_owned(),
            ),
        ]);
        assert!(
            plan_secret_import(&existing, &incoming, |_, _, _| Ok(ImportDecision::Abort)).is_err()
        );
        assert_eq!(existing.len(), 1);
        assert!(!existing.contains_key("A_NEW"));
    }
}
