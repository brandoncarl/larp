use std::io::{self, IsTerminal};

fn color_enabled() -> bool {
    io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").is_ok_and(|term| term != "dumb")
}

fn paint(text: &str, color: &str) -> String {
    if color_enabled() {
        format!("\x1b[{color}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

pub fn prompt() -> String {
    paint("larp> ", "1;36")
}

pub fn heading(text: &str) -> String {
    paint(text, "1;36")
}

pub fn success(message: &str) {
    println!("{} {message}", paint("✓", "1;32"));
}

pub fn error(message: &str) {
    eprintln!("{} {}", paint("✗", "1;31"), error_text(message));
}

pub fn error_text(message: &str) -> String {
    let mut chars = message.chars();
    match chars.next() {
        Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

pub fn note(message: &str) {
    println!("{} {message}", paint("→", "1;36"));
}

pub fn start_banner() {
    if io::stdout().is_terminal() {
        println!(
            "\n{}  Local actions, ready when you are.\n",
            heading("🦙 LARP")
        );
    } else {
        println!("LARP starting");
    }
}

pub fn start_waiting() {
    note("Waiting for 1Password approval…");
}

pub fn start_ready(secret_count: usize) {
    success(&format!("{secret_count} secrets loaded into memory"));
    success("MCP server ready");
    println!("  Connect with `larp mcp`. Leave this window open.\n");
}

#[cfg(test)]
mod tests {
    use super::error_text;

    #[test]
    fn error_messages_start_with_a_capital_letter() {
        assert_eq!(
            error_text("invalid LARP bridge identity"),
            "Invalid LARP bridge identity"
        );
        assert_eq!(
            error_text("LARP busy; retry later"),
            "LARP busy; retry later"
        );
        assert_eq!(error_text(""), "");
    }
}
