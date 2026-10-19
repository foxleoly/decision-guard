// OpenCode adapter for decision-guard: a thin wrapper around `~/.decision-guard/bin/decision-guard hook opencode`.
//
// Two modes, picked once at start from OpenCode's own config:
//  - permission.bash is "ask" (or {"*": "ask"}): OpenCode asks for every bash command and this plugin answers
//    through `permission.ask`: allow -> no prompt, ask -> the real OpenCode prompt, deny -> refused.
//  - otherwise there is no prompt channel, so a command that needs approval is rejected with the reason.
import { spawn } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";

const BIN = join(homedir(), ".decision-guard", "bin", "decision-guard");

const textOf = (parts) => (parts ?? []).filter((p) => p?.type === "text" && typeof p.text === "string").map((p) => p.text).join("\n");

// Runs the hook once with a Claude-format payload on stdin; `failed` means the binary could not be run at all.
const hook = (payload) =>
	new Promise((resolve) => {
		const child = spawn(BIN, ["hook", "opencode"], { stdio: ["pipe", "pipe", "ignore"] });
		let stdout = "";
		child.stdout.on("data", (chunk) => (stdout += chunk));
		child.on("error", () => resolve({ stdout: "", failed: true }));
		child.on("close", () => resolve({ stdout, failed: false }));
		child.stdin.on("error", () => {}); // EPIPE when the binary is missing; "error" above reports it
		child.stdin.end(JSON.stringify(payload));
	});

export const DecisionGuard = async ({ client, directory }) => {
	const bash = await client?.config
		?.get?.()
		.then((res) => res?.data?.permission?.bash)
		.catch(() => undefined);
	const realPrompt = bash === "ask" || bash?.["*"] === "ask";

	// The session's user messages, oldest first; empty when the server cannot be reached.
	const promptsOf = async (sessionID) => {
		const res = await client?.session?.messages?.({ path: { id: sessionID } }).catch(() => null);
		return (res?.data ?? []).filter((m) => m.info?.role === "user").map((m) => textOf(m.parts)).filter(Boolean);
	};
	// The binary keeps prompts in its own log, so hand it each user message once (at most the last 3 on first sight).
	const recorded = new Map(); // sessionID -> user messages already handed over
	const recordPrompts = async (sessionID) => {
		const all = await promptsOf(sessionID);
		const start = Math.max(recorded.get(sessionID) ?? 0, all.length - 3);
		recorded.set(sessionID, all.length);
		for (const prompt of all.slice(start)) await hook({ session_id: sessionID, hook_event_name: "UserPromptSubmit", prompt });
	};
	// -> { action: "allow" | "ask" | "deny", reason, detail }
	const judge = async (command, sessionID) => {
		if (sessionID) await recordPrompts(sessionID);
		const { stdout, failed } = await hook({ session_id: sessionID, tool_name: "bash", tool_input: { command }, cwd: directory });
		if (failed && process.env.DECISION_GUARD_FAIL_CLOSED) {
			return { action: "deny", reason: `decision-guard unavailable (cannot run ${BIN}) and DECISION_GUARD_FAIL_CLOSED is set` };
		}
		if (!stdout.trim()) return { action: "allow" }; // the hook prints nothing for allow, and fails open
		const out = JSON.parse(stdout).hookSpecificOutput;
		const [reason, ...detail] = String(out.permissionDecisionReason).split("\n"); // the hook joins "reason\ndetail"
		return { action: out.permissionDecision, reason, detail: detail.join("\n") };
	};

	return {
		"tool.execute.before": async (input, output) => {
			if (input.tool !== "bash" || realPrompt) return; // with real prompts, permission.ask decides
			const result = await judge(String(output.args?.command ?? ""), input.sessionID);
			if (result.action !== "allow") {
				throw new Error(`${result.reason}${result.detail ? `\n${result.detail}` : ""}\nNot run. Ask the user to confirm or choose a safer approach.`);
			}
		},

		"permission.ask": async (input, output) => {
			if (input.type !== "bash" || !realPrompt) return;
			const command = String(input.metadata?.command ?? (Array.isArray(input.pattern) ? input.pattern[0] : input.pattern) ?? "");
			if (!command.trim()) return;
			const result = await judge(command, input.sessionID);
			output.status = result.action; // allow | ask | deny
		},
	};
};
