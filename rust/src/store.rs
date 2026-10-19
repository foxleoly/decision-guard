//! SQLite audit log: `~/.decision-guard/decisions.db`. The schema, migrations and recorded columns are the ones the
//! earlier Node implementation wrote, so an existing database keeps working.

use crate::jsc::{iso_now, slice_utf16, state_dir, trim};
use crate::judge::{Call, Service};
use rusqlite::{params, Connection};
use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

pub const PROMPTS_KEPT: i64 = 3;

pub fn db_path() -> PathBuf {
    state_dir().join("decisions.db")
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS decisions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL,           -- UTC, ISO 8601
	agent TEXT NOT NULL,        -- claude | codex | copilot | opencode | pi
	session_id TEXT,
	cwd TEXT NOT NULL,
	command TEXT NOT NULL,
	source TEXT NOT NULL,       -- rule | cache | api | no_service | error
	rule TEXT,                  -- which deterministic rule fired: denylist | user-deny | dir-delete | exfiltration | allowlist | readonly (source = rule)
	provider TEXT,              -- \"openai\" or the host of the base URL
	model TEXT,
	choice TEXT,                -- safe | risky | destructive (null for rule / no_service / error)
	confidence REAL,
	probabilities TEXT,         -- JSON, api only
	user_requested REAL,        -- probability the user asked for it (only asked when a model verdict would ask)
	action TEXT NOT NULL,       -- allow | ask | deny: what the guard decided, not what the user then answered
	latency_ms INTEGER NOT NULL,
	input_tokens INTEGER,       -- api only
	error TEXT
);
CREATE TABLE IF NOT EXISTS prompts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL,
	agent TEXT NOT NULL,
	session_id TEXT NOT NULL,
	text TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_calls (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	decision_id INTEGER REFERENCES decisions(id),
	ts TEXT NOT NULL,
	provider TEXT,
	model TEXT,
	url TEXT,
	purpose TEXT,               -- the question asked: risk | user_requested
	request TEXT NOT NULL,      -- the JSON body sent, exactly; credentials are never in it
	status INTEGER,             -- HTTP status; NULL when no response arrived (timeout, refused connection)
	response TEXT,              -- the raw response body, also for error statuses
	latency_ms INTEGER,
	error TEXT
);";

/// Columns added after the first release; an older decisions.db gets them on first open.
const ADDED_COLUMNS: [(&str, &str); 5] = [
    ("session_id", "TEXT"),
    ("user_requested", "REAL"),
    ("provider", "TEXT"),
    ("model", "TEXT"),
    ("rule", "TEXT"),
];

/// Opens (creating and migrating if needed) the database and runs `f` against it. Never fails the caller: logging must
/// not break the guard, so any error yields `None`.
pub fn with_db<T>(f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Option<T> {
    let result = (|| -> rusqlite::Result<T> {
        let io = |e: std::io::Error| rusqlite::Error::ToSqlConversionFailure(Box::new(e));
        std::fs::create_dir_all(state_dir()).map_err(io)?;
        let db = Connection::open(db_path())?;
        db.busy_timeout(Duration::from_millis(2000))?; // concurrent hook processes wait instead of failing
        db.execute_batch(SCHEMA)?;
        let have: HashSet<String> = db
            .prepare("PRAGMA table_info(decisions)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<rusqlite::Result<_>>()?;
        for (name, ty) in ADDED_COLUMNS {
            if !have.contains(name) {
                db.execute_batch(&format!("ALTER TABLE decisions ADD COLUMN {name} {ty}"))?;
            }
        }
        // The directory-delete rule was the only rule before this column existed.
        if !have.contains("rule") {
            db.execute_batch("UPDATE decisions SET rule = 'dir-delete' WHERE source = 'rule'")?;
        }
        f(&db)
    })()
    .ok();
    let _ = std::fs::set_permissions(db_path(), std::fs::Permissions::from_mode(0o600));
    result
}

/// One decision as logged. Absent values are stored as NULL.
// shortcut: stores commands and prompts verbatim, so a secret typed inline lands in the file (mode 600);
// add redaction if the log is ever shared.
#[derive(Debug, Default)]
pub struct Row<'a> {
    pub agent: &'a str,
    pub session_id: Option<&'a str>,
    pub cwd: &'a str,
    pub command: &'a str,
    pub source: &'a str,
    pub rule: Option<&'a str>,
    pub provider: Option<&'a str>,
    pub model: Option<&'a str>,
    pub choice: Option<&'a str>,
    pub confidence: Option<f64>,
    pub probabilities: Option<&'a str>,
    pub user_requested: Option<f64>,
    pub action: &'a str,
    pub latency_ms: i64,
    pub input_tokens: Option<f64>,
    pub error: Option<&'a str>,
}

/// Stores a decision and, linked to it, every API call made for it. `svc` is the service in force (if any).
pub fn record(row: &Row, calls: &[Call], svc: Option<&Service>) -> Option<()> {
    with_db(|db| {
        db.execute(
            "INSERT INTO decisions (ts, agent, session_id, cwd, command, source, rule, provider, model, choice, confidence, probabilities, user_requested, action, latency_ms, input_tokens, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![iso_now(), row.agent, row.session_id, row.cwd, row.command, row.source, row.rule, row.provider, row.model, row.choice, row.confidence, row.probabilities, row.user_requested, row.action, row.latency_ms, row.input_tokens, row.error],
        )?;
        let id = db.last_insert_rowid();
        let mut insert = db.prepare("INSERT INTO api_calls (decision_id, ts, provider, model, url, purpose, request, status, response, latency_ms, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")?;
        for c in calls {
            insert.execute(params![
                id,
                iso_now(),
                svc.map(|s| s.name.as_str()),
                svc.map(|s| s.model.as_str()),
                svc.map(|s| s.url.as_str()),
                c.purpose,
                c.request,
                c.status,
                c.response,
                c.latency_ms,
                c.error
            ])?;
        }
        Ok(())
    })
}

/// Stores a user prompt so a later tool call in the same session can ask "did the user request this?".
pub fn record_prompt(agent: &str, session_id: Option<&str>, text: &str) -> Option<()> {
    let session_id = session_id.filter(|s| !s.is_empty())?;
    if trim(text).is_empty() {
        return None;
    }
    with_db(|db| {
        db.execute(
            "INSERT INTO prompts (ts, agent, session_id, text) VALUES (?, ?, ?, ?)",
            params![iso_now(), agent, session_id, slice_utf16(text, 2000)],
        )
        .map(|_| ())
    })
}

/// The session's last few user prompts, oldest first. Empty when none were recorded.
pub fn recent_prompts(session_id: Option<&str>) -> Vec<String> {
    let Some(session_id) = session_id.filter(|s| !s.is_empty()) else {
        return Vec::new();
    };
    let rows = with_db(|db| {
        db.prepare("SELECT text FROM prompts WHERE session_id = ? ORDER BY id DESC LIMIT ?")?
            .query_map(params![session_id, PROMPTS_KEPT], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()
    });
    let mut rows = rows.unwrap_or_default();
    rows.reverse();
    rows
}
