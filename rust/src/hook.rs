//! Command-hook adapter for Claude Code, Codex and Copilot CLI (and any agent that speaks the Claude format):
//! `decision-guard hook <agent>`.
//!
//! One command serves two events, told apart by the payload:
//!   PreToolUse        -> judge the Bash command, print the tool's decision JSON on stdout
//!   UserPromptSubmit  -> remember the prompt, so a later command can be matched to "the user asked for this"
//! Any internal failure exits 0 with no output (unless DECISION_GUARD_FAIL_CLOSED is set): Copilot treats a non-zero
//! preToolUse exit as a deny, and a guard that crashes should not freeze the agent.

use crate::decide::{decide, session_id, Context};
use crate::jsc::{env, js_string, stringify, truthy};
use crate::rules::Action;
use crate::store;
use serde_json::{json, Value};

#[derive(Debug, Default, PartialEq)]
pub struct Output {
    pub stdout: String,
    pub stderr: String,
}

fn emit(agent: Option<&str>, action: Action, reason: &str, source: Option<&str>) -> String {
    let codex = agent == Some("codex");
    if codex && action == Action::Ask && source != Some("rule") {
        // Codex cannot prompt (its hook API parses "ask" but fails the hook), so warn the user and the model and let
        // the call proceed. Recursive directory deletes stay a hard deny: that rule must never run unasked.
        return stringify(&json!({
            "systemMessage": reason,
            "hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": format!("{reason}. Confirm with the user before running this or anything similar.")}
        })) + "\n";
    }
    let decision = if action == Action::Ask && codex {
        "deny"
    } else {
        action.as_str()
    };
    let body = if agent == Some("copilot") {
        json!({"permissionDecision": decision, "permissionDecisionReason": reason})
    } else {
        json!({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason}})
    };
    stringify(&body) + "\n"
}

fn is_bash(name: &str) -> bool {
    ["bash", "shell", "exec_command"]
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n))
}

fn is_prompt_event(name: &str) -> bool {
    name.eq_ignore_ascii_case("userpromptsubmit")
        || name.eq_ignore_ascii_case("userpromptsubmitted")
}

/// Handles one payload. Never panics on bad input; always returns (the caller exits 0).
pub fn run(agent: Option<&str>, stdin: &str) -> Output {
    let mut out = Output::default();
    let mut judging = false; // a tool call is being judged: only then does fail-closed have a decision to emit
    if let Err(msg) = handle(agent, stdin, &mut out, &mut judging) {
        out.stderr.push_str(&format!("decision-guard: {msg}\n"));
        if env("DECISION_GUARD_FAIL_CLOSED").is_some_and(|v| !v.is_empty()) && judging {
            out.stdout.push_str(&emit(
                agent,
                Action::Deny,
                &format!(
                    "decision-guard unavailable ({msg}) and DECISION_GUARD_FAIL_CLOSED is set"
                ),
                None,
            ));
        }
    }
    out
}

fn handle(
    agent: Option<&str>,
    stdin: &str,
    out: &mut Output,
    judging: &mut bool,
) -> Result<(), String> {
    let input: Value = serde_json::from_str(stdin).map_err(|e| e.to_string())?;
    if input.is_null() {
        return Err("Cannot read properties of null (reading 'session_id')".into());
    }
    // `a ?? b`: only null/absent fall through.
    let nn = |key: &str| input.get(key).filter(|v| !v.is_null());
    let session = session_id(nn("session_id").or_else(|| nn("sessionId")));
    let name_value = nn("tool_name").or_else(|| nn("toolName"));
    let name = name_value.map(js_string).unwrap_or_default();
    let event = nn("hook_event_name").map(js_string).unwrap_or_default();

    if !name_value.is_some_and(truthy)
        && (is_prompt_event(&event) || input.get("prompt").is_some_and(Value::is_string))
    {
        let text = nn("prompt")
            .or_else(|| nn("user_prompt"))
            .map(js_string)
            .unwrap_or_default();
        if let Some(agent) = agent {
            store::record_prompt(agent, session.as_deref(), &text);
        }
    } else if is_bash(&name) {
        *judging = true;
        let mut args = nn("tool_input").or_else(|| nn("toolArgs")).cloned();
        if let Some(Value::String(s)) = &args {
            args = Some(serde_json::from_str(s).map_err(|e| e.to_string())?); // camelCase Copilot payloads carry a JSON string
        }
        let command = args
            .as_ref()
            .and_then(|a| a.get("command"))
            .filter(|v| !v.is_null())
            .map(js_string)
            .unwrap_or_default();
        let cwd = match nn("cwd") {
            Some(v) => js_string(v),
            None => std::env::current_dir()
                .map(|d| d.to_string_lossy().into_owned())
                .unwrap_or_default(),
        };
        let ctx = Context {
            prompts: store::recent_prompts(session.as_deref()),
            session_id: session,
        };
        let result = decide(&command, &cwd, agent.unwrap_or("unknown"), &ctx)?;
        if let Some(w) = &result.warning {
            out.stderr.push_str(&format!("decision-guard: {w}\n"));
        }
        if result.action != Action::Allow {
            let reason = result.reason.as_deref().unwrap_or("");
            let reason = match result.detail.as_deref().filter(|d| !d.is_empty()) {
                Some(d) => format!("{reason}\n{d}"),
                None => reason.to_string(),
            };
            out.stdout
                .push_str(&emit(agent, result.action, &reason, result.source));
        }
    }
    Ok(())
}
