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
        ["command", "add" | "update", project, name, command]
        | ["command", "add" | "update", project, name, command, "--cwd", _] => {
            registry::name(name)?;
            let exists = project_ref(&registry, project)?
                .commands
                .contains_key(*name);
            if words[1] == "add" && exists {
                return Err("command already exists; use 'command update' to replace it".into());
            }
            if words[1] == "update" && !exists {
                return Err("command does not exist; use 'command add' to create it".into());
            }
            let argv = shlex::split(command).ok_or("invalid command quoting")?;
            if argv.is_empty() {
                return Err("command is empty".into());
            }
            let current = std::env::current_dir().map_err(|_| "could not read cwd")?;
            let (cwd, relative) = if words.len() == 7 {
                resolve_command_cwd(words[6], &current)?
            } else {
                resolve_command_cwd(&current.to_string_lossy(), &current)?
            };
            if relative {
                confirm_command_cwd(&cwd)?;
            }
            crate::runner::resolve_executable(&argv[0], &cwd)?;
            let item = project_mut(&mut registry, project)?;
            item.commands
                .insert(name.to_string(), RegisteredCommand { argv, cwd });
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
                    "{name}\t{}\t{}",
                    command.cwd,
                    shlex::try_join(command.argv.iter().map(String::as_str)).unwrap_or_default()
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
            println!("Restart 'larp start' to load the updated secret references.");
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
        [kind @ ("command" | "secret"), "remove", project, name] => {
            format!("Removed {kind} {name} from {project}.")
        }
        [kind, "add", name, ..] | [kind, "update", name, ..] => {
            format!("Saved {kind} {name}.")
        }
        [kind, "remove", name, ..] => format!("Removed {kind} {name}."),
        ["project", "cwd", name, ..] => format!("Updated working directory for {name}."),
        _ => "Saved.".into(),
    }
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
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return Err(
            "relative secret imports need an interactive terminal; no changes saved".into(),
        );
    }
    println!(
        "Import directory: {}",
        path.parent().unwrap_or(path).display()
    );
    println!("Import file:      {}", path.display());
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
            return Err("secret import cancelled; no changes saved".into());
        }
        match answer.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(()),
            "n" | "no" => return Err("secret import cancelled; no changes saved".into()),
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

fn add_client(registry: &mut Registry, name: &str, process: &str) -> Result<(), String> {
    registry::name(name)?;
    registry::absolute_path(process)?;
    let canonical = std::fs::canonicalize(process).map_err(|_| "client process does not exist")?;
    if !canonical.is_file() {
        return Err("client process is not a file".into());
    }
    let canonical = canonical.to_string_lossy().into_owned();
    if registry
        .clients
        .values()
        .any(|client| client.process == canonical)
    {
        return Err("process is already registered".into());
    }
    if registry.clients.contains_key(name) {
        return Err("client already exists".into());
    }
    registry.clients.insert(
        name.to_string(),
        Client {
            identity: crate::identity::capture(&canonical)?,
            process: canonical,
            commands: BTreeSet::new(),
            secrets: BTreeSet::new(),
            exec: BTreeSet::new(),
        },
    );
    Ok(())
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
    use super::{plan_secret_import, resolve_command_cwd, resolve_import_path, ImportDecision};
    use std::collections::BTreeMap;
    use std::path::Path;

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
