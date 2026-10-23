//! `decision-guard rules list|add|remove|enable|disable|export|import`: the live lists, from a terminal.
//!
//! Everything goes through `crate::live`, so the CLI and the viewer cannot drift apart. `export`/`import` use one
//! JSON shape; on import a deny always beats an allow for the same pattern, because a shared list must never turn
//! someone's deny into an allow.

use crate::jsc::{iso_from_ms, now_ms, opt};
use crate::live::{self, Entry};
use crate::rules::Action;
use serde_json::Value;
use std::io::Read;

pub fn main(args: &[String]) -> i32 {
    match run(args) {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("{message}");
            2
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or("list");
    let rest = &args[1..];
    let path = live::path();
    let conn = live::open(&path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    match command {
        "list" => list(&conn, rest),
        "add" => add(&conn, rest),
        "remove" => by_id(rest, |id| live::remove(&conn, id)),
        "enable" => by_id(rest, |id| live::set_enabled(&conn, id, true)),
        "disable" => by_id(rest, |id| live::set_enabled(&conn, id, false)),
        "export" => export(&conn, rest),
        "import" => import(&conn, rest),
        other => Err(format!(
            "unknown subcommand {other}\nusage: decision-guard rules list|add|remove|enable|disable|export|import"
        )),
    }
}

fn list(conn: &rusqlite::Connection, args: &[String]) -> Result<(), String> {
    let source = opt(args, "--source")?;
    let action = opt(args, "--action")?;
    let now = crate::jsc::iso_now();
    let entries = live::all(conn).map_err(|e| e.to_string())?;
    if args.iter().any(|a| a == "--json") {
        let rows: Vec<Value> = entries
            .iter()
            .filter(|e| source.is_none_or(|s| e.source == s))
            .filter(|e| action.is_none_or(|a| e.action.as_str() == a))
            .map(Entry::to_json)
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows).unwrap_or_default());
        return Ok(());
    }
    println!(
        "{:>4}  {:<5}  {:<8}  {:>5}  {:<20}  {:<24}  pattern",
        "id", "act", "source", "hits", "last hit", "expires"
    );
    for entry in entries {
        if source.is_some_and(|s| entry.source != s) || action.is_some_and(|a| entry.action.as_str() != a) {
            continue;
        }
        let state = if !entry.enabled {
            " [disabled]"
        } else if !entry.live(&now) {
            " [expired]"
        } else {
            ""
        };
        println!(
            "{:>4}  {:<5}  {:<8}  {:>5}  {:<20}  {:<24}  {}{}",
            entry.id,
            entry.action.as_str(),
            entry.source,
            entry.hit_count,
            entry.last_hit_at.as_deref().unwrap_or("-"),
            entry.expires_at.as_deref().unwrap_or("never"),
            entry.pattern,
            state
        );
    }
    Ok(())
}

fn add(conn: &rusqlite::Connection, args: &[String]) -> Result<(), String> {
    let pattern = opt(args, "--pattern")?
        .or_else(|| args.iter().find(|a| !a.starts_with("--")).map(String::as_str))
        .ok_or("usage: rules add <pattern> --action allow|deny [--note TEXT] [--days N] [--cwd PATH]")?;
    let action = match opt(args, "--action")?.unwrap_or("allow") {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        other => return Err(format!("--action must be allow or deny, not {other}")),
    };
    let expires = match opt(args, "--days")? {
        Some(days) => {
            let days: f64 = days.parse().map_err(|_| format!("--days must be a number, not {days}"))?;
            Some(iso_from_ms(now_ms() + (days * 86_400_000.0) as i64))
        }
        None => None,
    };
    let note = opt(args, "--note")?;
    let cwd = opt(args, "--cwd")?;
    let id = live::add(conn, pattern, action, note, expires.as_deref(), cwd).map_err(|e| e.to_string())?;
    println!("added rule {id}: {} {}", action.as_str(), pattern);
    Ok(())
}

fn by_id(args: &[String], change: impl Fn(i64) -> rusqlite::Result<bool>) -> Result<(), String> {
    let id: i64 = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .ok_or("an id is required")?
        .parse()
        .map_err(|_| "the id must be a number".to_string())?;
    match change(id).map_err(|e| e.to_string())? {
        true => {
            println!("rule {id} updated");
            Ok(())
        }
        false => Err(format!("no rule with id {id}")),
    }
}

fn export(conn: &rusqlite::Connection, args: &[String]) -> Result<(), String> {
    let body = live::export(conn).map_err(|e| e.to_string())?;
    let text = serde_json::to_string_pretty(&body).map_err(|e| e.to_string())?;
    match opt(args, "--out")? {
        Some(file) => {
            std::fs::write(file, text).map_err(|e| format!("cannot write {file}: {e}"))?;
            println!("wrote {file}");
        }
        None => println!("{text}"),
    }
    Ok(())
}

fn import(conn: &rusqlite::Connection, args: &[String]) -> Result<(), String> {
    let file = opt(args, "--file")?
        .or_else(|| args.iter().find(|a| !a.starts_with("--")).map(String::as_str))
        .ok_or("usage: rules import <file.json>")?;
    let mut text = String::new();
    std::fs::File::open(file)
        .map_err(|e| format!("cannot read {file}: {e}"))?
        .read_to_string(&mut text)
        .map_err(|e| format!("cannot read {file}: {e}"))?;
    let body: Value = serde_json::from_str(&text).map_err(|e| format!("{file} is not JSON: {e}"))?;
    let (added, skipped) = live::import(conn, &body).map_err(|e| e.to_string())?;
    println!("imported {added}, skipped {skipped} (deny wins on conflict)");
    Ok(())
}
