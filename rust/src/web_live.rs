//! The live lists, over `rules.db`, for the viewer's Rules page: `GET /api/live` (list + search + counts),
//! `POST /api/live/add` (a `gui`-sourced row), `POST /api/live/toggle` (enable/disable by id) and
//! `GET /api/live/preview` (glob preview with precheck's own matcher).
//!
//! Every read goes through `crate::live`, so the page, the CLI and the hook cannot drift apart.

use crate::jsc::normalize;
use crate::live::{self, Entry};
use crate::rules::{glob_match, Action};
use rusqlite::{params, Connection};
use serde_json::{json, Value};

/// Open `rules.db` for the viewer. The hook path and the CLI use `live::path()`; the `--rules` flag
/// overrides the file the viewer reads and writes.
pub fn open(path: &std::path::Path) -> Result<Connection, String> {
    live::open(path).map_err(|e| format!("rules.db: {e}"))
}

/// `GET /api/live?q=<text>` — the whole live list, optionally filtered on the pattern text, plus the
/// per-action counts. Filtering is in memory (the list is small by design); an unreadable file yields
/// an empty result, never a 500.
pub fn get(conn: &Connection, q: Option<&str>) -> Value {
    let all = live::all(conn).unwrap_or_default();
    let entries: Vec<Entry> = match q {
        Some(q) if !q.trim().is_empty() => {
            let needle = q.to_lowercase();
            all.into_iter()
                .filter(|e| e.pattern.to_lowercase().contains(&needle))
                .collect()
        }
        _ => all,
    };
    let counts = live::counts(conn).unwrap_or_default();
    let entries_json: Vec<Value> = entries.iter().map(Entry::to_json).collect();
    json!({ "entries": entries_json, "counts": counts })
}

/// `POST /api/live/add` — one `gui` row. A `deny` always beats an `allow` on the same pattern: the new
/// deny replaces any allow, mirroring `live::import`.
pub fn add(conn: &Connection, body: &Value) -> Result<Value, (u16, Value)> {
    let pattern = body
        .get("pattern")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or((400, json!({"error": "pattern is required"})))?;
    let action = body
        .get("action")
        .and_then(Value::as_str)
        .and_then(action_from)
        .ok_or((400, json!({"error": "action must be allow, ask or deny"})))?;
    let note = body.get("note").and_then(Value::as_str);
    if action == Action::Deny {
        // Deny wins: a new deny supersedes any allow of the same pattern.
        let _ = conn.execute(
            "DELETE FROM rules WHERE pattern = ?1 AND action = 'allow'",
            params![pattern],
        );
    }
    let id = live::add(conn, pattern, action, note, None, None)
        .map_err(|e| (500, json!({"error": format!("{e}")})))?;
    Ok(json!({ "id": id, "pattern": pattern, "action": action.as_str() }))
}

/// `POST /api/live/toggle` — flip one row's `enabled`; 404 when the id is unknown.
pub fn toggle(conn: &Connection, body: &Value) -> Result<Value, (u16, Value)> {
    let idv = body.get("id").cloned().unwrap_or(Value::Null);
    let idf: f64 = idv.as_f64().unwrap_or(f64::NAN);
    let id: i64 = i64::try_from(idf as u64).unwrap_or(0);
    if idf.is_nan() || id <= 0 {
        return Err((400, json!({"error": "id is required"})));
    }
    let current: i64 = conn
        .query_row("SELECT enabled FROM rules WHERE id = ?1", params![id], |r| r.get(0))
        .map_err(|_| (404, json!({"error": "no such rule"})))?;
    let now_enabled = current == 0;
    live::set_enabled(conn, id, now_enabled)
        .map_err(|e| (500, json!({"error": format!("{e}")})))?;
    Ok(json!({ "id": id, "enabled": now_enabled }))
}

fn action_from(text: &str) -> Option<Action> {
    match text {
        "allow" => Some(Action::Allow),
        "ask" => Some(Action::Ask),
        "deny" => Some(Action::Deny),
        _ => None,
    }
}

/// `GET /api/live/preview?pattern=<glob>` — which of a fixed sample of commands the glob matches,
/// using the same matcher as precheck (`normalize` + `glob_match`), so the preview is exactly what
/// the hook will see.
pub fn preview(pattern: &str) -> Value {
    if pattern.trim().is_empty() {
        return json!({ "pattern": pattern, "samples": [] });
    }
    let probes = [
        "git status",
        "git push origin main",
        "cargo test",
        "ls -la",
        "rm -rf /tmp",
        "rm -rf $HOME",
        "rm -rf /tmp/dg-verify-probe",
    ];
    let normalized = normalize(pattern);
    let mut samples = Vec::new();
    for probe in probes {
        if glob_match(&normalized, &normalize(probe)) || glob_match(pattern, probe) {
            samples.push(probe);
        }
    }
    json!({ "pattern": pattern, "samples": samples })
}
