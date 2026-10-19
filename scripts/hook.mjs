#!/usr/bin/env node
// Command-hook adapter for Claude Code, Codex and Copilot CLI: `hook.mjs <claude|codex|copilot>`.
// One command serves two events, told apart by the payload:
//   PreToolUse        -> judge the Bash command, print the tool's decision JSON on stdout
//   UserPromptSubmit  -> remember the prompt, so a later command can be matched to "the user asked for this"
// Any internal failure exits 0 with no output (unless DECISION_GUARD_FAIL_CLOSED is set): Copilot treats a
// non-zero preToolUse exit as a deny, and a guard that crashes should not freeze the agent.

import { decide, recentPrompts, recordPrompt } from "./core.mjs";

const tool = process.argv[2];
const BASH_NAMES = /^(bash|shell|exec_command)$/i;
const PROMPT_EVENTS = /^userpromptsubmit(ted)?$/i;

function emit(action, reason, { source } = {}) {
	if (tool === "codex" && action === "ask" && source !== "rule") {
		// Codex cannot prompt (its hook API parses "ask" but fails the hook), so warn the user and the model and
		// let the call proceed. Recursive directory deletes stay a hard deny: that rule must never run unasked.
		console.log(
			JSON.stringify({
				systemMessage: reason,
				hookSpecificOutput: { hookEventName: "PreToolUse", additionalContext: `${reason}. Confirm with the user before running this or anything similar.` },
			}),
		);
		return;
	}
	const decision = action === "ask" && tool === "codex" ? "deny" : action;
	if (tool === "copilot") {
		console.log(JSON.stringify({ permissionDecision: decision, permissionDecisionReason: reason }));
	} else {
		console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision, permissionDecisionReason: reason } }));
	}
}

async function readStdin() {
	let data = "";
	for await (const chunk of process.stdin) data += chunk;
	return data;
}

let judging = false; // a tool call is being judged: only then does fail-closed have a decision to emit
try {
	const input = JSON.parse(await readStdin());
	const sessionId = input.session_id ?? input.sessionId;
	const name = input.tool_name ?? input.toolName ?? "";
	if (!name && (PROMPT_EVENTS.test(input.hook_event_name ?? "") || typeof input.prompt === "string")) {
		await recordPrompt(tool, sessionId, String(input.prompt ?? input.user_prompt ?? ""));
	} else if (BASH_NAMES.test(name)) {
		judging = true;
		let args = input.tool_input ?? input.toolArgs;
		if (typeof args === "string") args = JSON.parse(args); // camelCase Copilot payloads carry a JSON string
		const result = await decide(String(args?.command ?? ""), input.cwd ?? process.cwd(), tool, { sessionId, prompts: await recentPrompts(sessionId) });
		if (result.warning) process.stderr.write(`decision-guard: ${result.warning}\n`);
		if (result.action !== "allow") emit(result.action, result.detail ? `${result.reason}\n${result.detail}` : result.reason, result);
	}
} catch (err) {
	process.stderr.write(`decision-guard: ${err.message}\n`);
	if (process.env.DECISION_GUARD_FAIL_CLOSED && judging) emit("deny", `decision-guard unavailable (${err.message}) and DECISION_GUARD_FAIL_CLOSED is set`);
}
