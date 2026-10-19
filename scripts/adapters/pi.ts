// Pi / OMP adapter for decision-guard: a thin wrapper around `~/.decision-guard/bin/decision-guard hook pi`.
// Both agents share this extension API; a command that needs approval opens a confirm dialog.
import { spawn } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";

const BIN = join(homedir(), ".decision-guard", "bin", "decision-guard");

interface Decision {
	action: "allow" | "ask" | "deny";
	reason?: string;
	detail?: string;
	warning?: string;
}

interface ToolCallEvent {
	toolName: string;
	input?: { command?: unknown };
}

interface SessionEntry {
	type?: string;
	message?: { role?: string; content?: string | { type?: string; text?: string }[] };
}

interface Ctx {
	cwd: string;
	hasUI: boolean;
	sessionManager?: { getSessionId?(): string; getBranch?(): SessionEntry[] };
	ui: {
		notify(message: string, level: string): void;
		confirm(title: string, message: string): Promise<boolean>;
	};
}

interface ExtensionApi {
	on(event: "tool_call", handler: (event: ToolCallEvent, ctx: Ctx) => Promise<{ block: true; reason: string } | undefined>): void;
}

// Runs the hook once with a Claude-format payload on stdin; `failed` means the binary could not be run at all.
function hook(payload: object): Promise<{ stdout: string; stderr: string; failed: boolean }> {
	return new Promise((resolve) => {
		const child = spawn(BIN, ["hook", "pi"], { stdio: ["pipe", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => (stdout += chunk));
		child.stderr.on("data", (chunk) => (stderr += chunk));
		child.on("error", (err) => resolve({ stdout: "", stderr: `decision-guard: cannot run ${BIN}: ${err.message}`, failed: true }));
		child.on("close", () => resolve({ stdout, stderr, failed: false }));
		child.stdin.on("error", () => {}); // EPIPE when the binary is missing; "error" above reports it
		child.stdin.end(JSON.stringify(payload));
	});
}

// The session's user messages, oldest first.
function userPrompts(ctx: Ctx): string[] {
	const texts: string[] = [];
	for (const entry of ctx.sessionManager?.getBranch?.() ?? []) {
		if (entry.type !== "message" || entry.message?.role !== "user") continue;
		const content = entry.message.content;
		const text = typeof content === "string" ? content : (content ?? []).map((b) => (b.type === "text" ? b.text : "")).join("\n");
		if (text?.trim()) texts.push(text.trim());
	}
	return texts;
}

export default function (pi: ExtensionApi): void {
	let warned = false;
	// The binary keeps prompts in its own log, so hand it each user message once (at most the last 3 on first sight).
	const recorded = new Map<string, number>(); // session id -> user messages already handed over
	async function recordPrompts(sessionId: string, ctx: Ctx): Promise<void> {
		const all = userPrompts(ctx);
		const start = Math.max(recorded.get(sessionId) ?? 0, all.length - 3);
		recorded.set(sessionId, all.length);
		for (const prompt of all.slice(start)) await hook({ session_id: sessionId, hook_event_name: "UserPromptSubmit", prompt });
	}

	async function judge(command: string, ctx: Ctx): Promise<Decision> {
		const sessionId = ctx.sessionManager?.getSessionId?.();
		if (sessionId) await recordPrompts(sessionId, ctx);
		const { stdout, stderr, failed } = await hook({ session_id: sessionId, tool_name: "bash", tool_input: { command }, cwd: ctx.cwd });
		const warning = stderr.trim().replace(/^decision-guard: /, "") || undefined;
		if (failed && process.env.DECISION_GUARD_FAIL_CLOSED) {
			return { action: "deny", reason: `decision-guard unavailable (${warning}) and DECISION_GUARD_FAIL_CLOSED is set` };
		}
		if (!stdout.trim()) return { action: "allow", warning }; // the hook prints nothing for allow, and fails open
		const out = JSON.parse(stdout).hookSpecificOutput;
		const [reason, ...detail] = String(out.permissionDecisionReason).split("\n"); // the hook joins "reason\ndetail"
		return { action: out.permissionDecision, reason, detail: detail.join("\n"), warning };
	}

	pi.on("tool_call", async (event, ctx) => {
		if (event.toolName !== "bash") return undefined;
		const command = String(event.input?.command ?? "");
		const result = await judge(command, ctx);

		if (result.warning && !warned) {
			warned = true;
			ctx.ui.notify(`decision-guard: ${result.warning}`, "warning");
		}
		if (result.action === "allow") return undefined;
		if (result.action === "deny") return { block: true, reason: result.reason ?? "decision-guard: denied" };

		const detail = result.detail ? `${result.detail}\n` : "";
		if (ctx.hasUI && (await ctx.ui.confirm("Approve this command?", `${command}\n${detail}\n${result.reason}`))) return undefined;
		return { block: true, reason: `${result.reason}. Not approved; ask the user to confirm or choose a safer approach.` };
	});
}
