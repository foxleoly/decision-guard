//! `decision-guard web [--port 8765] [--db path] [--config path]`: a page over `decisions.db` and the allow/deny lists
//! in `config.json`. The page itself is `web-page.html`, embedded in the binary.
//!
//! Local by design: it binds to 127.0.0.1, only answers requests whose Host is a loopback name (so a web page cannot
//! reach it through DNS rebinding), loads nothing from the network and renders every value as text. Commands are
//! shown as typed, which can include secrets: do not expose the port.
//! Read-only over the database; it writes only the "allow", "deny" and "readonly" keys of config.json, every other key
//! (including api_key) is preserved as is and never returned to the page.

use crate::jsc::{env, js_string, num, number_str, opt, state_dir, stringify};
use crate::judge::{read_config, resolve_service, thresholds, Format};
use crate::rules::{precheck, validate_rules, Rules, Validated};
use crate::store::db_path;
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::types::{Value as Sql, ValueRef};
use rusqlite::{params_from_iter, Connection, OpenFlags};
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use subtle::ConstantTimeEq;

const PAGE: &str = include_str!("web-page.html");
const COLUMNS: [&str; 18] = [
    "id",
    "ts",
    "agent",
    "session_id",
    "cwd",
    "command",
    "source",
    "rule",
    "provider",
    "model",
    "choice",
    "confidence",
    "probabilities",
    "user_requested",
    "action",
    "latency_ms",
    "input_tokens",
    "error",
];
const BODY_MAX: usize = 65536;
const HEAD_MAX: usize = 16384;

/// Mirrors the names in rules.rs's deny list; kept here only for display, never used for matching.
fn builtin_deny() -> Value {
    json!([
        {"name": "disk-erase", "description": "diskutil erase / secureErase / partitionDisk / reformat / apfs delete..."},
        {"name": "raw-device-write", "description": "dd ... of=/dev/rdisk, or a redirect onto /dev/rdisk"},
        {"name": "mkfs", "description": "mkfs / newfs"},
        {"name": "fork-bomb", "description": ":(){ :|:& };:"},
    ])
}

struct Viewer {
    port: u16,
    db: PathBuf,
    config: PathBuf,
    nonce: String,
    // A per-process secret the page must echo back on every POST (like the CSP nonce), so a page from another origin
    // that merely guesses the loopback Host cannot write rules just by being allowed to load the HTML.
    token: String,
}

struct Response {
    status: u16,
    content_type: &'static str,
    body: String,
}

fn reply(status: u16, content_type: &'static str, body: impl Into<String>) -> Response {
    Response {
        status,
        content_type,
        body: body.into(),
    }
}

fn json_reply(status: u16, v: &Value) -> Response {
    reply(status, "application/json", stringify(v))
}

fn text(status: u16, body: &'static str) -> Response {
    reply(status, "text/plain", body)
}

// ── entry point ──────────────────────────────────────────────────────────────────────────────────────────

/// Runs the viewer until the process is killed; returns the exit code when it cannot start.
pub fn main(args: &[String]) -> i32 {
    let parsed = (|| -> Result<(u16, PathBuf, PathBuf), String> {
        let port = match opt(args, "--port")? {
            None => 8765.0,
            Some(s) => number_str(s),
        };
        if !(port.fract() == 0.0 && (0.0..=65535.0).contains(&port)) {
            return Err("--port must be a number from 0 to 65535".into());
        }
        let db = opt(args, "--db")?.map_or_else(db_path, PathBuf::from);
        let config =
            opt(args, "--config")?.map_or_else(|| state_dir().join("config.json"), PathBuf::from);
        Ok((port as u16, db, config))
    })();
    let (port, db, config) = match parsed {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            eprintln!("port {port} is already in use, pick another with --port");
            return 1;
        }
        Err(e) => {
            eprintln!("viewer failed: {e}");
            return 1;
        }
    };
    let port = listener.local_addr().map_or(port, |a| a.port());
    let viewer = Arc::new(Viewer {
        port,
        nonce: random_b64(16),
        token: random_b64(32),
        db,
        config,
    });
    println!(
        "decision-guard viewer: http://127.0.0.1:{port}/   (database: {}, Ctrl+C to stop)",
        viewer.db.display()
    );
    for stream in listener.incoming().flatten() {
        let viewer = viewer.clone();
        std::thread::spawn(move || serve(&viewer, stream));
    }
    0
}

fn random_b64(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::getrandom(&mut buf).expect("the viewer needs the system RNG for its page token");
    STANDARD.encode(buf)
}

// ── HTTP ─────────────────────────────────────────────────────────────────────────────────────────────────

// Not tiny_http: it owns the accepted sockets, so there is no way to set the per-connection read/write timeouts this
// viewer needs (a stalled client would pin one of its worker threads forever), and it adds Date/Server headers.
struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
    fn count(&self, name: &str) -> usize {
        self.headers.iter().filter(|(n, _)| n == name).count()
    }
}

fn read_head(r: &mut impl BufRead) -> Option<Request> {
    let mut used = 0;
    let mut line = |r: &mut dyn BufRead| -> Option<String> {
        let mut buf = Vec::new();
        used += r.take(HEAD_MAX as u64).read_until(b'\n', &mut buf).ok()?;
        (used <= HEAD_MAX && buf.ends_with(b"\n"))
            .then(|| String::from_utf8_lossy(&buf).trim_end().to_string())
    };
    let first = line(r)?;
    let mut parts = first.split(' ');
    let (method, target) = (parts.next()?.to_string(), parts.next()?.to_string());
    let mut headers = Vec::new();
    loop {
        let l = line(r)?;
        if l.is_empty() {
            return Some(Request {
                method,
                target,
                headers,
            });
        }
        let (name, value) = l.split_once(':')?;
        headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        _ => "Internal Server Error",
    }
}

fn serve(v: &Viewer, stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let mut reader = std::io::BufReader::new(&stream);
    let mut is_head = false;
    let res = match read_head(&mut reader) {
        Some(req) => {
            is_head = req.method == "HEAD";
            route(v, &req, &mut reader)
        }
        None => text(400, "bad request"),
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: {}; charset=utf-8\r\ncontent-length: {}\r\ncache-control: no-store\r\nx-content-type-options: nosniff\r\nreferrer-policy: no-referrer\r\ncontent-security-policy: default-src 'none'; style-src 'nonce-{n}'; script-src 'nonce-{n}'; connect-src 'self'; base-uri 'none'; form-action 'none'\r\nconnection: close\r\n\r\n",
        res.status,
        reason(res.status),
        res.content_type,
        res.body.len(),
        n = v.nonce
    );
    let mut out = &stream;
    let _ = out.write_all(head.as_bytes()).and_then(|()| {
        // A HEAD response carries the headers (including the length) but no body.
        if is_head {
            Ok(())
        } else {
            out.write_all(res.body.as_bytes())
        }
    });
    // Answering before the request body was read must not end in a reset that hides the answer: close our side, then
    // swallow what the client still sends.
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = std::io::copy(&mut reader.take(1 << 17), &mut std::io::sink());
}

/// `URLSearchParams` (the `url` crate's form_urlencoded): `+` is a space, `%XX` is a byte, the first value of a name
/// wins (see `get`).
fn query(target: &str) -> Vec<(String, String)> {
    let Some((_, q)) = target.split_once('?') else {
        return Vec::new();
    };
    let q = q.split('#').next().unwrap_or("");
    url::form_urlencoded::parse(q.as_bytes())
        .into_owned()
        .collect()
}

fn get<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(n, _)| n == key)
        .map(|(_, v)| v.as_str())
}

fn route(v: &Viewer, req: &Request, body: &mut impl Read) -> Response {
    let host = req.header("host").unwrap_or("");
    let allowed = [
        format!("127.0.0.1:{}", v.port),
        format!("localhost:{}", v.port),
        format!("[::1]:{}", v.port),
    ];
    if req.count("host") > 1 || !allowed.iter().any(|a| a == host) {
        return text(403, "forbidden");
    }
    let path = req.target.split(['?', '#']).next().unwrap_or("");
    let params = query(&req.target);

    match req.method.as_str() {
        "GET" => match path {
            "/" => reply(
                200,
                "text/html",
                PAGE.replace("__NONCE__", &v.nonce)
                    .replace("__TOKEN__", &v.token),
            ),
            "/api/decisions" => json_reply(200, &decisions(&v.db, &params)),
            "/api/summary" => json_reply(200, &summary(&v.db)),
            "/api/status" => json_reply(200, &status(&v.db)),
            "/api/calls" => json_reply(
                200,
                &calls(&v.db, get(&params, "decision").map_or(0.0, number_str)),
            ),
            "/api/rules" => {
                let rules = read_rules(&v.config);
                json_reply(
                    200,
                    &json!({
                        "allow": rules.allow,
                        "deny": rules.deny,
                        "builtin": builtin_deny(),
                        "readonly": {
                            "enabled": saved_readonly(&v.config),
                            "forced_by_env": env_readonly().is_some(),
                            "tools": crate::readonly::tool_names(),
                        },
                    }),
                )
            }
            _ => text(404, "not found"),
        },
        "POST" if path == "/api/rules" || path == "/api/check" => {
            post(v, req, path == "/api/rules", body)
        }
        _ => text(405, "method not allowed"),
    }
}

fn post(v: &Viewer, req: &Request, save: bool, body: &mut impl Read) -> Response {
    let content_type = req.header("content-type").unwrap_or("");
    if content_type.split(';').next().unwrap_or("").trim() != "application/json" {
        return text(400, "content-type must be application/json");
    }
    let presented = req
        .header("x-dg-token")
        .filter(|_| req.count("x-dg-token") == 1);
    if !presented.is_some_and(|p| bool::from(p.as_bytes().ct_eq(v.token.as_bytes()))) {
        return text(403, "forbidden");
    }
    let host = req.header("host").unwrap_or("");
    if req
        .header("origin")
        .is_some_and(|o| o.strip_prefix("http://") != Some(host))
    {
        return text(403, "forbidden");
    }
    // shortcut: bodies must carry a Content-Length (every browser fetch does); chunked uploads are refused.
    if req.header("transfer-encoding").is_some() {
        return text(400, "chunked bodies are not supported");
    }
    let len = req
        .header("content-length")
        .map_or(Ok(0), str::parse::<usize>);
    let Ok(len) = len else {
        return text(400, "bad content-length");
    };
    if len > BODY_MAX {
        return text(413, "body too large");
    }
    let mut raw = vec![0u8; len];
    if body.read_exact(&mut raw).is_err() {
        return text(400, "incomplete body");
    }
    let Ok(json) = serde_json::from_str::<Value>(&String::from_utf8_lossy(&raw)) else {
        return rule_errors(&[
            json!({"list": null, "index": null, "pattern": null, "message": "body must be valid JSON"}),
        ]);
    };
    let validated = match validate_body(&json) {
        Ok(v) => v,
        Err(e) => return rule_errors(&[e]),
    };
    let readonly = match json.get("readonly") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => {
            return rule_errors(&[
                json!({"list": null, "index": null, "pattern": null, "message": "readonly must be true or false"}),
            ])
        }
    };

    if save {
        if !validated.ok {
            return json_reply(400, &json!({"errors": errors_json(&validated)}));
        }
        return match write_rules(&v.config, &validated, readonly) {
            Ok(()) => {
                let mut out = json!({"allow": validated.allow, "deny": validated.deny});
                if let Some(b) = readonly {
                    out["readonly"] = b.into();
                }
                json_reply(200, &out)
            }
            Err(_) => text(500, "could not write the config file"),
        };
    }
    // /api/check: stateless dry run, never calls the model and never writes anything.
    let mut rules: Rules = if json.get("allow").is_some() || json.get("deny").is_some() {
        validated.into()
    } else {
        read_rules(&v.config)
    };
    // Like the hook: the environment wins, then the value in the request (unsaved), then config.json.
    rules.readonly =
        env_readonly().unwrap_or_else(|| readonly.unwrap_or_else(|| saved_readonly(&v.config)));
    let string = |k: &str| match json.get(k) {
        None | Some(Value::Null) => None,
        Some(v) => Some(js_string(v)),
    };
    let cwd = string("cwd").unwrap_or_else(|| {
        std::env::current_dir().map_or_else(|_| "/".into(), |p| p.to_string_lossy().into_owned())
    });
    let p = precheck(&string("command").unwrap_or_default(), &cwd, &rules);
    let mut out = Map::new();
    out.insert("stage".into(), p.stage.as_str().into());
    if let Some(r) = p.rule {
        out.insert("rule".into(), r.into());
    }
    if let Some(a) = p.action {
        out.insert("action".into(), a.as_str().into());
    }
    if let Some(s) = p.pattern {
        out.insert("pattern".into(), s.into());
    }
    if let Some(s) = p.reason {
        out.insert("reason".into(), s.into());
    }
    json_reply(200, &Value::Object(out))
}

fn rule_errors(errors: &[Value]) -> Response {
    json_reply(400, &json!({ "errors": errors }))
}

fn errors_json(v: &Validated) -> Vec<Value> {
    v.errors
        .iter()
        .map(|e| json!({"list": e.list, "index": e.index, "pattern": e.pattern, "message": e.message}))
        .collect()
}

/// The body's "allow" and "deny" through validate_rules. A missing list is empty; anything but an array is refused
/// (the JS would throw on it).
fn validate_body(json: &Value) -> Result<Validated, Value> {
    let list = |key: &'static str| match json.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => Ok(a.clone()),
        Some(_) => Err(
            json!({"list": key, "index": null, "pattern": null, "message": format!("{key} must be an array")}),
        ),
    };
    Ok(validate_rules(&list("allow")?, &list("deny")?))
}

// ── config.json ──────────────────────────────────────────────────────────────────────────────────────────

static CONFIG_LOCK: Mutex<()> = Mutex::new(());

fn read_config_file(path: &Path) -> Map<String, Value> {
    match std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
    {
        Some(Value::Object(m)) => m,
        _ => Map::new(), // no config file yet
    }
}

/// Config.json's allow/deny, cleaned through validate_rules so an already-saved bad entry cannot slip through.
fn read_rules(path: &Path) -> Rules {
    let _guard = CONFIG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let raw = read_config_file(path);
    let list = |k: &str| match raw.get(k) {
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    };
    validate_rules(&list("allow"), &list("deny")).into()
}

/// The "readonly" setting in config.json alone (default on), ignoring the environment.
fn saved_readonly(path: &Path) -> bool {
    let _guard = CONFIG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    crate::judge::readonly_enabled(&|_| None, &Value::Object(read_config_file(path)))
}

/// What DECISION_GUARD_READONLY forces, when it is set to anything.
fn env_readonly() -> Option<bool> {
    env("DECISION_GUARD_READONLY")
        .filter(|s| !s.is_empty())
        .map(|_| crate::judge::readonly_enabled(&env, &Value::Null))
}

/// Writes the allow/deny keys (and "readonly" when given), preserving every other key (api_key, base_url, ...),
/// atomically and mode 600.
fn write_rules(path: &Path, rules: &Validated, readonly: Option<bool>) -> std::io::Result<()> {
    let _guard = CONFIG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut next = read_config_file(path);
    next.insert("allow".into(), json!(rules.allow));
    next.insert("deny".into(), json!(rules.deny));
    if let Some(b) = readonly {
        next.insert("readonly".into(), b.into());
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let written = (|| {
        let mut f = crate::fsx::create_private(&tmp)?;
        crate::fsx::restrict(&tmp)?;
        f.write_all(serde_json::to_string_pretty(&Value::Object(next))?.as_bytes())?;
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

// ── database ─────────────────────────────────────────────────────────────────────────────────────────────

/// Runs `f` on a fresh read-only handle with the set of columns this database actually has (an older file may lack
/// some). `None` when there is no database yet, no decisions table, or a query fails.
fn with_db<T>(
    path: &Path,
    f: impl FnOnce(&Connection, &HashSet<String>) -> rusqlite::Result<T>,
) -> Option<T> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    db.busy_timeout(Duration::from_millis(2000)).ok()?;
    let have: HashSet<String> = db
        .prepare("PRAGMA table_info(decisions)")
        .ok()?
        .query_map([], |r| r.get(1))
        .ok()?
        .collect::<rusqlite::Result<_>>()
        .ok()?;
    if have.is_empty() {
        return None;
    }
    f(&db, &have).ok()
}

/// Every row as an object, values typed the way node:sqlite returned them (integers and reals as numbers).
fn rows(db: &Connection, sql: &str, args: Vec<Sql>) -> rusqlite::Result<Vec<Map<String, Value>>> {
    let mut stmt = db.prepare(sql)?;
    let names: Vec<String> = stmt
        .column_names()
        .iter()
        .map(|n| (*n).to_string())
        .collect();
    let mut out = Vec::new();
    let mut cursor = stmt.query(params_from_iter(args))?;
    while let Some(row) = cursor.next()? {
        let mut m = Map::new();
        for (i, name) in names.iter().enumerate() {
            m.insert(
                name.clone(),
                match row.get_ref(i)? {
                    ValueRef::Integer(n) => n.into(),
                    ValueRef::Real(f) => num(f),
                    ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned().into(),
                    ValueRef::Null | ValueRef::Blob(_) => Value::Null,
                },
            );
        }
        out.push(m);
    }
    Ok(out)
}

fn all(db: &Connection, sql: &str, args: Vec<Sql>) -> rusqlite::Result<Vec<Value>> {
    Ok(rows(db, sql, args)?
        .into_iter()
        .map(Value::Object)
        .collect())
}

/// A LIKE pattern for "contains s", with `\`, `%` and `_` taken literally.
fn like(s: &str) -> String {
    let mut out = String::from("%");
    for c in s.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

fn decisions(db_file: &Path, params: &[(String, String)]) -> Value {
    let param = |k: &str| get(params, k);
    let n = |k: &str| param(k).map_or(0.0, number_str);
    let limit = match n("limit") {
        l if l.is_nan() || l == 0.0 => 100.0,
        l => l,
    }
    .clamp(1.0, 500.0);
    let empty = json!({"rows": [], "hasMore": false});
    // SQLite refuses a fractional LIMIT, which the script's catch turned into an empty page.
    if limit.fract() != 0.0 {
        return empty;
    }
    let limit = limit as usize;
    let before = n("before");
    let out = with_db(db_file, |db, have| {
        let mut sql = Vec::new();
        let mut vals: Vec<Sql> = Vec::new();
        match param("view").unwrap_or("dangerous") {
            "dangerous" => sql.push("action IN ('ask','deny')".to_string()),
            "unjudged" => sql.push("source IN ('no_service','error')".to_string()),
            _ => {}
        }
        for key in ["agent", "source", "rule", "action"] {
            if let Some(v) = param(key).filter(|v| !v.is_empty() && have.contains(key)) {
                sql.push(format!("{key} = ?"));
                vals.push(Sql::Text(v.into()));
            }
        }
        if let Some(q) = param("q").filter(|q| !q.is_empty()) {
            sql.push("(command LIKE ? ESCAPE '\\' OR cwd LIKE ? ESCAPE '\\')".into());
            vals.push(Sql::Text(like(q)));
            vals.push(Sql::Text(like(q)));
        }
        if before > 0.0 {
            sql.push("id < ?".into());
            vals.push(Sql::Real(before));
        }
        vals.push(Sql::Integer(limit as i64 + 1));
        let select = COLUMNS
            .iter()
            .map(|c| {
                if have.contains(*c) {
                    (*c).to_string()
                } else {
                    format!("NULL AS {c}")
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        let clause = if sql.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", sql.join(" AND "))
        };
        let found = rows(
            db,
            &format!("SELECT {select} FROM decisions {clause} ORDER BY id DESC LIMIT ?"),
            vals,
        )?;
        let has_more = found.len() > limit;
        let page: Vec<Value> = found
            .into_iter()
            .take(limit)
            .map(|r| {
                // Older rows hold an array or nothing instead of an object with "destructive".
                let p = r
                    .get("probabilities")
                    .and_then(Value::as_str)
                    .and_then(|s| serde_json::from_str::<Value>(s).ok())
                    .and_then(|p| p.get("destructive").filter(|d| d.is_number()).cloned());
                let mut out: Map<String, Value> = r
                    .into_iter()
                    .filter(|(k, _)| k != "probabilities")
                    .collect();
                out.insert("p_destructive".into(), p.unwrap_or(Value::Null));
                Value::Object(out)
            })
            .collect();
        Ok(json!({"rows": page, "hasMore": has_more}))
    });
    out.unwrap_or(empty)
}

/// The requests sent to the decision service for one decision, exactly as sent and received.
fn calls(db_file: &Path, decision_id: f64) -> Value {
    with_db(db_file, |db, _| {
        all(
            db,
            "SELECT id, ts, provider, model, url, purpose, request, status, response, latency_ms, error FROM api_calls WHERE decision_id = ? ORDER BY id",
            vec![Sql::Real(decision_id)],
        )
    })
    .map_or_else(|| json!([]), Value::Array)
}

fn percentile(sorted: &[Value], p: f64) -> Value {
    sorted
        .get(((sorted.len() as f64 * p).floor() as usize).min(sorted.len().saturating_sub(1)))
        .cloned()
        .unwrap_or(Value::Null)
}

fn summary(db_file: &Path) -> Value {
    let empty = json!({"total": 0, "asked": 0, "denied": 0, "unjudged": 0, "agents": [], "sources": [], "rules": [], "verdicts": [], "days": [], "hours": [], "top": [], "latency": {"n": 0, "p50": null, "p95": null, "errors": 0}});
    with_db(db_file, |db, have| {
        let q = |sql: &str| all(db, sql, vec![]);
        let mut totals = rows(db, "SELECT count(*) AS total, sum(action = 'ask') AS asked, sum(action = 'deny') AS denied, sum(source IN ('no_service','error')) AS unjudged FROM decisions", vec![])?.remove(0);
        let since = crate::jsc::iso_from_ms(crate::jsc::now_ms() - 24 * 3_600_000);
        // No api_calls table yet: the latency block stays empty.
        let latency = (|| -> rusqlite::Result<Value> {
            let ms: Vec<Value> = rows(db, "SELECT latency_ms FROM api_calls WHERE status = 200 AND latency_ms IS NOT NULL ORDER BY latency_ms", vec![])?
                .into_iter()
                .map(|mut r| r.remove("latency_ms").unwrap_or(Value::Null))
                .collect();
            let errors = rows(db, "SELECT count(*) AS n FROM api_calls WHERE status IS NULL OR status >= 400", vec![])?.remove(0);
            Ok(json!({"n": ms.len(), "p50": percentile(&ms, 0.5), "p95": percentile(&ms, 0.95), "errors": errors["n"]}))
        })()
        .unwrap_or_else(|_| empty["latency"].clone());
        totals.insert("agents".into(), q("SELECT agent, count(*) AS total, sum(action IN ('ask','deny')) AS dangerous FROM decisions GROUP BY agent ORDER BY total DESC")?.into());
        totals.insert("sources".into(), q("SELECT source, count(*) AS n FROM decisions GROUP BY source ORDER BY n DESC")?.into());
        totals.insert(
            "rules".into(),
            if have.contains("rule") { q("SELECT rule, count(*) AS n FROM decisions WHERE rule IS NOT NULL GROUP BY rule ORDER BY n DESC")? } else { vec![] }.into(),
        );
        totals.insert("verdicts".into(), q("SELECT choice, count(*) AS n FROM decisions WHERE choice IS NOT NULL GROUP BY choice ORDER BY n DESC")?.into());
        totals.insert("days".into(), q("SELECT date(ts) AS day, count(*) AS total, sum(action IN ('ask','deny')) AS dangerous FROM decisions GROUP BY day ORDER BY day DESC LIMIT 14")?.into());
        totals.insert(
            "hours".into(),
            all(db, "SELECT substr(ts, 1, 13) AS hour, count(*) AS total, sum(action IN ('ask','deny')) AS dangerous FROM decisions WHERE ts >= ? GROUP BY hour ORDER BY hour", vec![Sql::Text(since)])?.into(),
        );
        totals.insert("top".into(), q("SELECT substr(command, 1, 200) AS command, count(*) AS n, max(action) AS action FROM decisions WHERE action IN ('ask','deny') GROUP BY command ORDER BY n DESC, max(id) DESC LIMIT 8")?.into());
        totals.insert("latency".into(), latency);
        Ok(Value::Object(totals))
    })
    .unwrap_or(empty)
}

/// Which service answers, the thresholds in force and how much is stored. Never includes a credential.
fn status(db_file: &Path) -> Value {
    let config = read_config();
    let service = match resolve_service(&env, &config) {
        Err(error) => json!({ "error": error }),
        Ok(s) => json!({
            "name": s.name,
            "format": match s.format { Format::OpenAi => "openai", Format::SystemOne => "systemone" },
            "url": s.url,
            "model": s.model,
            "timeout_ms": num(s.timeout),
            "has_key": s.key.as_deref().is_some_and(|k| !k.is_empty()),
        }),
    };
    let t = thresholds(&env, &config);
    let counts = with_db(db_file, |db, _| {
        let n = |table: &str| {
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get::<_, i64>(0))
                .unwrap_or(0)
        };
        Ok(json!({"decisions": n("decisions"), "api_calls": n("api_calls"), "prompts": n("prompts")}))
    })
    .unwrap_or_else(|| json!({"decisions": 0, "api_calls": 0, "prompts": 0}));
    let mut database = Map::new();
    database.insert("path".into(), db_file.display().to_string().into());
    database.insert(
        "bytes".into(),
        std::fs::metadata(db_file).map_or(0, |m| m.len()).into(),
    );
    database.extend(counts.as_object().cloned().unwrap_or_default());
    let dir = db_file.parent().unwrap_or(Path::new("")).join("archive");
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|f| f.ends_with(".db.gz"))
        .collect();
    files.sort();
    let bytes: u64 = files
        .iter()
        .filter_map(|f| std::fs::metadata(dir.join(f)).ok())
        .map(|m| m.len())
        .sum();
    json!({
        "service": service,
        "thresholds": {"askP": num(t.ask_p), "userP": num(t.user_p)},
        "fail_closed": env("DECISION_GUARD_FAIL_CLOSED").is_some_and(|v| !v.is_empty()),
        "database": database,
        "archives": {"count": files.len(), "bytes": bytes, "latest": files.last()},
    })
}
