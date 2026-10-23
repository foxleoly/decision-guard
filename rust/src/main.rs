//! `decision-guard hook <agent>`: reads the agent's JSON payload on stdin, prints its decision on stdout and always
//! exits 0. `decision-guard web` is the log viewer, `decision-guard archive` the weekly log archive,
//! `decision-guard service` lists or switches the decision service and `decision-guard check` the deterministic
//! stages on commands from stdin (never the model).

use std::io::{Read, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("hook") => {
            let mut bytes = Vec::new();
            let _ = std::io::stdin().read_to_end(&mut bytes);
            let agent = args.get(1).cloned();
            // A panic must not turn into a non-zero exit (Copilot reads that as a deny).
            let out = std::panic::catch_unwind(|| {
                decision_guard::hook::run(agent.as_deref(), &String::from_utf8_lossy(&bytes))
            });
            match out {
                Ok(out) => {
                    let _ = std::io::stdout().write_all(out.stdout.as_bytes());
                    let _ = std::io::stderr().write_all(out.stderr.as_bytes());
                }
                Err(_) => eprintln!("decision-guard: internal error"),
            }
            ExitCode::SUCCESS
        }
        Some("web") => ExitCode::from(decision_guard::web::main(&args[1..]) as u8),
        Some("archive") => ExitCode::from(decision_guard::archive::main(&args[1..]) as u8),
        Some("service") => ExitCode::from(decision_guard::service::main(&args[1..]) as u8),
        Some("rules") => ExitCode::from(decision_guard::rules_cmd::main(&args[1..]) as u8),
        Some("check") => {
            let mut text = String::new();
            let _ = std::io::stdin().read_to_string(&mut text);
            let no_config = args.iter().any(|a| a == "--no-config");
            let _ = std::io::stdout()
                .write_all(decision_guard::decide::check(&text, no_config).as_bytes());
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: decision-guard hook <claude|codex|copilot|opencode|pi>   (payload JSON on stdin)\n       decision-guard web [--port N] [--db PATH] [--config PATH]\n       decision-guard archive [--keep-days N] [--dry-run] [--db PATH] [--out DIR]\n       decision-guard check [--no-config]   (one command per line, or JSON lines, on stdin)\n       decision-guard service [<name>] [--config PATH]   (list the configured services, or switch the active one)\n       decision-guard rules list|add|remove|enable|disable|export|import   (the live allow/deny lists)");
            ExitCode::from(2)
        }
    }
}
