//! The live lists: which commands may run, kept as data in `~/.decision-guard/rules.db`.
//!
//! A separate database from `decisions.db` on purpose: the log is archived after 30 days, and a permission
//! that disappears with it would be a silent regression. The log also takes one INSERT per command while a
//! hit takes one UPDATE, and two writers in one file still serialise on the WAL write lock.
//!
//! The hook is a fresh process per command, so every read here is "open, one indexed SELECT, match in
//! memory". `rust/tests/live_perf.rs` holds the budget: open+select ≤1 ms, glob ≤0.2 ms, hit UPDATE ≤0.5 ms.
//!
//! Row sources: `builtin` (imported from config.json's allow/deny once), `gui` (added in the viewer or by
//! `decision-guard rules add`), `pack` (reserved for Phase 3) and `learned` (reserved for v1.1; nothing
//! writes it yet).

use crate::fsx;
use crate::jsc::{iso_now, normalize, state_dir};
use crate::rules::{glob_match, Action};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

pub fn path() -> PathBuf {
    state_dir().join("rules.db")
}

/// `cwd` is part of the uniqueness so one approval in one directory does not cover another. SQLite treats
/// NULLs as distinct in a UNIQUE constraint, hence the COALESCE expression index.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS rules (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern     TEXT NOT NULL,
  action      TEXT NOT NULL,              -- allow | ask | deny
  source      TEXT NOT NULL,              -- builtin | gui | pack | learned
  note        TEXT,
  created_at  TEXT NOT NULL,
  hit_count   INTEGER NOT NULL DEFAULT 0,
  last_hit_at TEXT,
  enabled     INTEGER NOT NULL DEFAULT 1,
  expires_at  TEXT,                       -- NULL = permanent, ISO-8601 UTC
  cwd         TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS rules_unique ON rules (pattern, action, source, COALESCE(cwd, ''));
CREATE INDEX IF NOT EXISTS rules_lookup ON rules (enabled, action);
";

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub id: i64,
    pub pattern: String,
    pub action: Action,
    pub source: String,
    pub note: Option<String>,
    pub created_at: String,
    pub hit_count: i64,
    pub last_hit_at: Option<String>,
    pub enabled: bool,
    pub expires_at: Option<String>,
    pub cwd: Option<String>,
}

impl Entry {
    /// A row that has not expired. `expires_at` is ISO-8601 UTC like `iso_now()`, so a string compare is a
    /// time compare.
    pub fn live(&self, now: &str) -> bool {
        self.enabled && self.expires_at.as_deref().is_none_or(|at| at > now)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "pattern": self.pattern,
            "action": self.action.as_str(),
            "source": self.source,
            "note": self.note,
            "created_at": self.created_at,
            "hit_count": self.hit_count,
            "last_hit_at": self.last_hit_at,
            "enabled": self.enabled,
            "expires_at": self.expires_at,
            "cwd": self.cwd,
        })
    }
}

/// The rows precheck needs, loaded once per hook.
#[derive(Clone, Debug, Default)]
pub struct Live {
    pub entries: Vec<Entry>,
}

fn action_from(text: &str) -> Option<Action> {
    match text {
        "allow" => Some(Action::Allow),
        "ask" => Some(Action::Ask),
        "deny" => Some(Action::Deny),
        _ => None,
    }
}

impl Live {
    /// config.json's allow/deny as in-memory entries. Used by the tests and by the first run before the
    /// database exists; the persistent copy is `import_config`.
    pub fn from_config(allow: &[String], deny: &[String]) -> Live {
        let now = iso_now();
        let mut entries = Vec::new();
        let mut id = 1;
        for (patterns, action, source) in [(deny, Action::Deny, "builtin"), (allow, Action::Allow, "builtin")] {
            for pattern in patterns {
                entries.push(Entry {
                    id,
                    pattern: pattern.clone(),
                    action,
                    source: source.into(),
                    note: None,
                    created_at: now.clone(),
                    hit_count: 0,
                    last_hit_at: None,
                    enabled: true,
                    expires_at: None,
                    cwd: None,
                });
                id += 1;
            }
        }
        Live { entries }
    }

    /// Everything enabled and unexpired. An unreadable database yields an empty list: a broken rules file
    /// must not stop the guard from judging (the built-in deny list still runs).
    pub fn load(path: &Path) -> Live {
        let Ok(conn) = open(path) else {
            return Live::default();
        };
        Live::from_conn(&conn).unwrap_or_default()
    }

    pub fn from_conn(conn: &Connection) -> rusqlite::Result<Live> {
        let mut statement = conn.prepare(
            "SELECT id, pattern, action, source, note, created_at, hit_count, last_hit_at, enabled,
                    expires_at, cwd
             FROM rules WHERE enabled = 1 ORDER BY id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(Entry {
                id: row.get(0)?,
                pattern: row.get(1)?,
                action: action_from(&row.get::<_, String>(2)?).unwrap_or(Action::Ask),
                source: row.get(3)?,
                note: row.get(4)?,
                created_at: row.get(5)?,
                hit_count: row.get(6)?,
                last_hit_at: row.get(7)?,
                enabled: row.get::<_, i64>(8)? != 0,
                expires_at: row.get(9)?,
                cwd: row.get(10)?,
            })
        })?;
        let now = iso_now();
        let mut entries = Vec::new();
        for row in rows {
            let entry = row?;
            if entry.live(&now) {
                entries.push(entry);
            }
        }
        Ok(Live { entries })
    }

    /// Deny is loose, like the old config deny: the whole command or any single command of a chain.
    pub fn deny(&self, command: &str, chain: &[String]) -> Option<&Entry> {
        let normalized = normalize(command);
        self.entries
            .iter()
            .filter(|e| e.action == Action::Deny)
            .find(|e| glob_match(&e.pattern, &normalized) || chain.iter().any(|part| glob_match(&e.pattern, part)))
    }

    /// Allow is strict: the whole command, and only when there is nothing that could chain or substitute.
    pub fn allow(&self, command: &str) -> Option<&Entry> {
        let normalized = normalize(command);
        self.entries
            .iter()
            .filter(|e| e.action == Action::Allow)
            .find(|e| glob_match(&e.pattern, &normalized))
    }
}

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
    conn.execute_batch(SCHEMA)?;
    let _ = fsx::restrict(path);
    Ok(conn)
}

/// Counts one hit. Called on the hot path, so it is a single autocommit UPDATE.
pub fn bump(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE rules SET hit_count = hit_count + 1, last_hit_at = ?1 WHERE id = ?2",
        params![iso_now(), id],
    )?;
    Ok(())
}

/// The one-time migration: config.json's allow/deny become `source = builtin` rows. Existing rows win, so
/// running it twice changes nothing, and a row the user deleted in the viewer does not come back.
pub fn import_config(conn: &Connection, allow: &[String], deny: &[String]) -> rusqlite::Result<usize> {
    let mut added = 0;
    let now = iso_now();
    for (patterns, action) in [(deny, Action::Deny), (allow, Action::Allow)] {
        for pattern in patterns {
            let changed = conn.execute(
                "INSERT OR IGNORE INTO rules (pattern, action, source, created_at)
                 VALUES (?1, ?2, 'builtin', ?3)",
                params![pattern, action.as_str(), now],
            )?;
            added += changed;
        }
    }
    Ok(added)
}

pub fn add(
    conn: &Connection,
    pattern: &str,
    action: Action,
    note: Option<&str>,
    expires_at: Option<&str>,
    cwd: Option<&str>,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO rules (pattern, action, source, note, created_at, expires_at, cwd)
         VALUES (?1, ?2, 'gui', ?3, ?4, ?5, ?6)
         ON CONFLICT (pattern, action, source, COALESCE(cwd, '')) DO UPDATE SET
           note = COALESCE(excluded.note, note),
           expires_at = excluded.expires_at,
           enabled = 1",
        params![pattern, action.as_str(), note, iso_now(), expires_at, cwd],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn remove(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM rules WHERE id = ?1", params![id])? > 0)
}

pub fn set_enabled(conn: &Connection, id: i64, enabled: bool) -> rusqlite::Result<bool> {
    Ok(conn.execute(
        "UPDATE rules SET enabled = ?1 WHERE id = ?2",
        params![enabled as i64, id],
    )? > 0)
}

pub fn all(conn: &Connection) -> rusqlite::Result<Vec<Entry>> {
    let mut statement = conn.prepare(
        "SELECT id, pattern, action, source, note, created_at, hit_count, last_hit_at, enabled,
                expires_at, cwd
         FROM rules ORDER BY action DESC, id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(Entry {
            id: row.get(0)?,
            pattern: row.get(1)?,
            action: action_from(&row.get::<_, String>(2)?).unwrap_or(Action::Ask),
            source: row.get(3)?,
            note: row.get(4)?,
            created_at: row.get(5)?,
            hit_count: row.get(6)?,
            last_hit_at: row.get(7)?,
            enabled: row.get::<_, i64>(8)? != 0,
            expires_at: row.get(9)?,
            cwd: row.get(10)?,
        })
    })?;
    rows.collect()
}

/// JSON for `rules export` and the viewer.
pub fn export(conn: &Connection) -> rusqlite::Result<Value> {
    let entries: Vec<Value> = all(conn)?.iter().map(Entry::to_json).collect();
    Ok(json!({ "version": 1, "rules": entries }))
}

/// Imports rows from an exported file. Deny wins on conflict: a shared list must never turn someone's deny
/// into an allow. Imported rows are marked `gui` so their provenance stays visible.
pub fn import(conn: &Connection, body: &Value) -> rusqlite::Result<(usize, usize)> {
    let Some(list) = body.get("rules").and_then(Value::as_array) else {
        return Ok((0, 0));
    };
    let mut added = 0;
    let mut skipped = 0;
    let now = iso_now();
    for item in list {
        let Some(pattern) = item.get("pattern").and_then(Value::as_str) else {
            skipped += 1;
            continue;
        };
        let action = item.get("action").and_then(Value::as_str).and_then(action_from).unwrap_or(Action::Ask);
        let blocked = if action == Action::Allow {
            // Refuse an allow when any deny for the same pattern already exists.
            conn.query_row(
                "SELECT 1 FROM rules WHERE pattern = ?1 AND action = 'deny' LIMIT 1",
                params![pattern],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        } else {
            false
        };
        if blocked {
            skipped += 1;
            continue;
        }
        if action == Action::Deny {
            // A deny replaces any allow of the same pattern, whichever machine it came from.
            conn.execute("DELETE FROM rules WHERE pattern = ?1 AND action = 'allow'", params![pattern])?;
        }
        let note = item.get("note").and_then(Value::as_str);
        let expires = item.get("expires_at").and_then(Value::as_str);
        let cwd = item.get("cwd").and_then(Value::as_str);
        added += conn.execute(
            "INSERT OR IGNORE INTO rules (pattern, action, source, note, created_at, expires_at, cwd)
             VALUES (?1, ?2, 'gui', ?3, ?4, ?5, ?6)",
            params![pattern, action.as_str(), note, now, expires, cwd],
        )?;
    }
    Ok((added, skipped))
}

/// `{ action: count }` for the viewer's summary.
pub fn counts(conn: &Connection) -> rusqlite::Result<Map<String, Value>> {
    let mut out = Map::new();
    let mut statement = conn.prepare("SELECT action, COUNT(*) FROM rules WHERE enabled = 1 GROUP BY action")?;
    let rows = statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?;
    for row in rows {
        let (action, count) = row?;
        out.insert(action, json!(count));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dg-live-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("rules.db")
    }

    #[test]
    fn config_lists_become_builtin_rows_once() {
        let path = temp("import");
        let conn = open(&path).unwrap();
        let allow = vec!["git status*".to_string()];
        let deny = vec!["rm *".to_string()];
        assert_eq!(import_config(&conn, &allow, &deny).unwrap(), 2);
        assert_eq!(import_config(&conn, &allow, &deny).unwrap(), 0, "second import adds nothing");
        let live = Live::from_conn(&conn).unwrap();
        assert_eq!(live.entries.len(), 2);
        assert!(live.entries.iter().all(|e| e.source == "builtin"));
        assert!(live.deny("rm -rf x", &[]).is_some());
        assert!(live.allow("git status -s").is_some());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn an_expired_row_stops_matching() {
        let path = temp("expiry");
        let conn = open(&path).unwrap();
        add(&conn, "make deploy*", Action::Allow, None, Some("2000-01-01T00:00:00.000Z"), None).unwrap();
        add(&conn, "npm run*", Action::Allow, None, Some("2999-01-01T00:00:00.000Z"), None).unwrap();
        let live = Live::from_conn(&conn).unwrap();
        assert!(live.allow("make deploy-prod").is_none(), "expired row must not match");
        assert!(live.allow("npm run build").is_some(), "future row still matches");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn import_refuses_to_turn_a_deny_into_an_allow() {
        let path = temp("conflict");
        let conn = open(&path).unwrap();
        add(&conn, "rm -rf *", Action::Deny, None, None, None).unwrap();
        let body = json!({"version": 1, "rules": [
            {"pattern": "rm -rf *", "action": "allow"},
            {"pattern": "kubectl get *", "action": "allow"}
        ]});
        let (added, skipped) = import(&conn, &body).unwrap();
        assert_eq!((added, skipped), (1, 1));
        let live = Live::from_conn(&conn).unwrap();
        assert!(live.deny("rm -rf build", &[]).is_some(), "deny still wins");
        assert!(live.allow("kubectl get pods").is_some());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_hit_is_counted_and_timestamped() {
        let path = temp("hit");
        let conn = open(&path).unwrap();
        let id = add(&conn, "git status*", Action::Allow, None, None, None).unwrap();
        bump(&conn, id).unwrap();
        bump(&conn, id).unwrap();
        let entry = &all(&conn).unwrap()[0];
        assert_eq!(entry.hit_count, 2);
        assert!(entry.last_hit_at.is_some());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
