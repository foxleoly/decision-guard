//! `decide`: the order of everything.
//!
//! built-in deny list -> your deny list -> recursive delete -> secret exfiltration -> your allow list -> read-only proof
//! -> cache -> model.
//! The guard never force-approves: `Allow` means "no objection". An unjudged command (no service, API error, budget
//! used up) is allowed with a warning, or denied when DECISION_GUARD_FAIL_CLOSED is set.

use crate::jsc::{env, fmt_number, normalize};
use crate::judge::{self, Call, Service};
use crate::rules::{
    delete_targets, exfiltration, is_catastrophic, precheck, validate_rules, Action, Rules, Stage,
};
use crate::store::{self, Row};
use serde_json::Value;
use std::time::Instant;

/// What the adapter knows about the conversation.
#[derive(Debug, Default)]
pub struct Context {
    pub session_id: Option<String>,
    /// The session's recent user messages, oldest first.
    pub prompts: Vec<String>,
}

#[derive(Debug, PartialEq)]
pub struct Decision {
    pub action: Action,
    pub reason: Option<String>,
    pub detail: Option<String>,
    /// Why a command was not judged (the hook prints it on stderr).
    pub warning: Option<String>,
    /// rule | cache | api | no_service | error; `None` only for an empty command, which is not logged.
    pub source: Option<&'static str>,
}

/// Extra columns of one audit row.
#[derive(Default)]
struct Logged {
    rule: Option<&'static str>,
    choice: Option<String>,
    confidence: Option<f64>,
    probabilities: Option<String>,
    user_requested: Option<f64>,
    input_tokens: Option<f64>,
    error: Option<String>,
}

/// The allow/deny lists from config.json, validated. A non-array list is a hard error in the JS too (it throws), and
/// the hook turns it into a stderr message.
fn rules_from_config(cfg: &Value) -> Result<Rules, String> {
    let list = |key: &str| -> Result<Vec<Value>, String> {
        match cfg.get(key) {
            None => Ok(Vec::new()),
            Some(Value::Array(a)) => Ok(a.clone()),
            Some(Value::Null) => Err("Cannot read properties of null (reading 'length')".into()),
            Some(_) => Err("list.slice is not a function".into()),
        }
    };
    let mut rules: Rules = validate_rules(&list("allow")?, &list("deny")?).into();
    rules.readonly = judge::readonly_enabled(&env, cfg);
    Ok(rules)
}

fn plain(action: Action) -> Decision {
    Decision {
        action,
        reason: None,
        detail: None,
        warning: None,
        source: None,
    }
}

/// `agent`: which tool is asking. Err only for what the JS lets throw (a cache file that cannot be written).
pub fn decide(command: &str, cwd: &str, agent: &str, ctx: &Context) -> Result<Decision, String> {
    if crate::jsc::trim(command).is_empty() {
        return Ok(plain(Action::Allow));
    }
    let started = Instant::now();
    let fail_closed = env("DECISION_GUARD_FAIL_CLOSED").is_some_and(|v| !v.is_empty());
    let cfg = judge::read_config();
    let svc = judge::resolve_service(&env, &cfg);
    let svc_ref: Option<&Service> = svc.as_ref().ok();
    let (provider, model) = (
        svc_ref.map(|s| s.name.as_str()),
        svc_ref.map(|s| s.model.as_str()),
    );
    let session = ctx.session_id.as_deref();

    // Every request sent to the service for this command is kept, as sent and as received.
    let finish =
        |mut result: Decision, source: &'static str, logged: Logged, calls: &[Call]| -> Decision {
            store::record(
                &Row {
                    agent,
                    session_id: session,
                    cwd,
                    command,
                    source,
                    rule: logged.rule,
                    provider,
                    model,
                    choice: logged.choice.as_deref(),
                    confidence: logged.confidence,
                    probabilities: logged.probabilities.as_deref(),
                    user_requested: logged.user_requested,
                    action: result.action.as_str(),
                    latency_ms: started.elapsed().as_millis() as i64,
                    input_tokens: logged.input_tokens,
                    error: logged.error.as_deref(),
                },
                calls,
                svc_ref,
            );
            result.source = Some(source);
            result
        };
    // Not judged (no service / API down): allow with a warning, or deny when the user asked for fail-closed.
    let unjudged =
        |warning: String, source: &'static str, logged: Logged, calls: &[Call]| -> Decision {
            let result = if fail_closed {
                Decision {
                    reason: Some(format!(
                        "decision-guard: {warning}, and DECISION_GUARD_FAIL_CLOSED is set"
                    )),
                    ..plain(Action::Deny)
                }
            } else {
                Decision {
                    warning: Some(format!("{warning}; this command was not judged")),
                    ..plain(Action::Allow)
                }
            };
            finish(result, source, logged, calls)
        };
    let mut calls: Vec<Call> = Vec::new();

    // Deterministic: one shared path (precheck) decides the built-in deny list, your own deny/allow lists and the two
    // fixed rules, in that order; allow can never override any of the earlier stages.
    let pre = precheck(command, cwd, &rules_from_config(&cfg)?);
    let rule = |name: &'static str| Logged {
        rule: Some(name),
        ..Logged::default()
    };
    match pre.stage {
        Stage::BuiltinDeny => {
            let banned = pre
                .reason
                .as_deref()
                .unwrap_or("")
                .trim_start_matches("refusing ");
            let reason = format!("decision-guard: refusing {banned}. It destroys a disk or the machine and is never run through an agent; run it yourself in a terminal if you mean it.");
            return Ok(finish(
                Decision {
                    reason: Some(reason),
                    ..plain(Action::Deny)
                },
                "rule",
                rule("denylist"),
                &calls,
            ));
        }
        Stage::UserDeny => {
            let reason = format!("decision-guard: refusing this command, it {}; edit your deny list on the web viewer if this is wrong.", pre.reason.as_deref().unwrap_or(""));
            return Ok(finish(
                Decision {
                    reason: Some(reason),
                    ..plain(Action::Deny)
                },
                "rule",
                rule("user-deny"),
                &calls,
            ));
        }
        Stage::DirDelete => {
            let targets = delete_targets(command, cwd);
            if pre.action == Some(Action::Deny) {
                let fatal: Vec<&str> = targets
                    .iter()
                    .filter(|t| is_catastrophic(t))
                    .map(String::as_str)
                    .collect();
                let reason = format!("decision-guard: refusing to delete {}. The root, your home directory and its parents are never removed through an agent; run it yourself in a terminal if you mean it.", fatal.join(", "));
                return Ok(finish(
                    Decision {
                        reason: Some(reason),
                        ..plain(Action::Deny)
                    },
                    "rule",
                    rule("dir-delete"),
                    &calls,
                ));
            }
            let dirs = targets
                .iter()
                .map(|d| format!("  - {d}"))
                .collect::<Vec<_>>()
                .join("\n");
            let result = Decision {
                reason: Some(
                    "decision-guard: each directory needs its own approval; nothing is remembered"
                        .into(),
                ),
                detail: Some(format!("Deleting:\n{dirs}")),
                ..plain(Action::Ask)
            };
            return Ok(finish(result, "rule", rule("dir-delete"), &calls));
        }
        Stage::Exfiltration => {
            let leak = exfiltration(command).ok_or("exfiltration rule matched without a match")?;
            let result = Decision {
                reason: Some("decision-guard: this command looks like it sends secrets off the machine; approval is never remembered".into()),
                detail: Some(format!("Reads: {}\nSends with: {}", leak.secret, leak.sink)),
                ..plain(Action::Ask)
            };
            return Ok(finish(result, "rule", rule("exfiltration"), &calls));
        }
        Stage::UserAllow => {
            return Ok(finish(
                plain(Action::Allow),
                "rule",
                rule("allowlist"),
                &calls,
            ))
        }
        Stage::ReadOnly => {
            return Ok(finish(
                plain(Action::Allow),
                "rule",
                rule("readonly"),
                &calls,
            ))
        }
        Stage::Model => {}
    }

    let cmd_key = normalize(command);
    let mut cache = judge::load_cache();
    let mut verdict = judge::cache_get(&cache, &cmd_key).and_then(judge::verdict_from_value);
    // Entries from before the service was recorded came from OpenAI's default model.
    if let (Some(v), Some(s)) = (&verdict, svc_ref) {
        if v.provider.as_deref().unwrap_or("openai") != s.name
            || v.model.as_deref().unwrap_or(judge::OPENAI_MODEL) != s.model
        {
            verdict = None;
        }
    }
    let thresholds = judge::thresholds(&env, &cfg);
    let mut source = "cache";
    let mut logged = Logged::default();
    if verdict.is_none() {
        let s = match &svc {
            Ok(s) => s,
            Err(e) => return Ok(unjudged(e.clone(), "no_service", Logged::default(), &calls)),
        };
        let judged = match judge::judge(command, cwd, s, started, &mut calls) {
            Ok(j) => j,
            Err(e) => {
                return Ok(unjudged(
                    format!("judge unavailable ({e})"),
                    "error",
                    Logged {
                        error: Some(e),
                        ..Logged::default()
                    },
                    &calls,
                ))
            }
        };
        source = "api";
        if let Some(j) = judged {
            logged.probabilities = j.probabilities;
            logged.input_tokens = j.input_tokens;
            let kept = judge::Verdict {
                provider: Some(s.name.clone()),
                model: Some(s.model.clone()),
                ..j.verdict
            };
            judge::remember(&mut cache, &cmd_key, &kept).map_err(|e| e.to_string())?;
            verdict = Some(kept);
        }
    }
    logged.choice = verdict.as_ref().and_then(|v| v.choice.clone());
    logged.confidence = verdict.as_ref().and_then(|v| v.confidence);
    let Some(verdict) = verdict.filter(|v| judge::needs_approval(v, &thresholds)) else {
        return Ok(finish(plain(Action::Allow), source, logged, &calls));
    };

    // The model would ask. If we know what the user said and they asked for exactly this, do not ask again.
    let mut user_requested = None;
    if let (false, Ok(s)) = (ctx.prompts.is_empty(), &svc) {
        if let Ok((p, tokens)) =
            judge::was_user_requested(command, cwd, &ctx.prompts, s, started, &mut calls)
        {
            user_requested = p;
            logged.input_tokens = Some(logged.input_tokens.unwrap_or(0.0) + tokens.unwrap_or(0.0));
        }
    }
    logged.user_requested = user_requested;
    if user_requested.is_some_and(|p| p >= thresholds.user_p) {
        return Ok(finish(plain(Action::Allow), source, logged, &calls));
    }
    let confidence = verdict.confidence.map_or(String::new(), |c| {
        format!(" (confidence {})", crate::jsc::to_fixed2(c))
    });
    Ok(finish(
        Decision {
            reason: Some(format!(
                "decision-guard: classified destructive{confidence}"
            )),
            ..plain(Action::Ask)
        },
        source,
        logged,
        &calls,
    ))
}

/// `decision-guard check`: one line per command, `stage<TAB>rule<TAB>action<TAB>reason` (`-` for what the stage does
/// not set), through `precheck` only: no model, no cache, no audit row. Input is one command per line, or JSON lines
/// `{"command": "...", "cwd": "..."}` when the first non-blank character is `{` (so a multi-line command can be
/// checked). `no_config` uses empty allow/deny lists; the read-only switch still follows the environment.
pub fn check(input: &str, no_config: bool) -> String {
    let cfg = if no_config {
        Value::Null
    } else {
        judge::read_config()
    };
    let mut rules = if no_config {
        Rules::default()
    } else {
        rules_from_config(&cfg).unwrap_or_default()
    };
    rules.readonly = judge::readonly_enabled(&env, &cfg);
    let json_lines = input.trim_start().starts_with('{');
    let default_cwd =
        std::env::current_dir().map_or_else(|_| "/".into(), |p| p.to_string_lossy().into_owned());
    let line = |fields: [&str; 4]| {
        let clean: Vec<String> = fields
            .iter()
            .map(|f| f.replace(['\t', '\n', '\r'], " "))
            .collect();
        clean.join("\t") + "\n"
    };
    let mut out = String::new();
    for raw in input.lines().filter(|l| !l.trim().is_empty()) {
        let (command, cwd) = if json_lines {
            match serde_json::from_str::<Value>(raw) {
                Ok(v) => (
                    v.get("command")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    v.get("cwd")
                        .and_then(Value::as_str)
                        .unwrap_or(&default_cwd)
                        .to_string(),
                ),
                Err(e) => {
                    out.push_str(&line(["error", "-", "-", &e.to_string()]));
                    continue;
                }
            }
        } else {
            (raw.to_string(), default_cwd.clone())
        };
        let p = precheck(&command, &cwd, &rules);
        out.push_str(&line([
            p.stage.as_str(),
            p.rule.unwrap_or("-"),
            p.action.map_or("-", Action::as_str),
            p.reason.as_deref().unwrap_or("-"),
        ]));
    }
    out
}

/// A session id as the database stores it: a non-empty string, or a number as SQLite spells a double.
pub fn session_id(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        // node:sqlite binds a JS number as a double, and TEXT affinity then stores 42 as "42.0".
        Value::Number(n) => {
            let f = n.as_f64().filter(|f| *f != 0.0)?;
            Some(if f.fract() == 0.0 && f.abs() < 1e15 {
                format!("{}.0", f as i64)
            } else {
                fmt_number(f)
            })
        }
        _ => None,
    }
}
