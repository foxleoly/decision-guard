#!/usr/bin/env node
// decision-guard web viewer: a page over ~/.decision-guard/decisions.db and the allow/deny lists in config.json.
// `node web.mjs [--port 8765] [--db path]`, then open the printed URL. The page itself is web-page.html next to this file.
//
// Local by design: it binds to 127.0.0.1, only answers requests whose Host is a loopback name (so a web page cannot
// reach it through DNS rebinding), loads nothing from the network, and renders every value as text. Commands are
// shown as typed, which can include secrets: do not expose the port.
// Read-only over the database (opened with { readOnly: true }); it writes only the "allow" and "deny" keys of
// config.json, every other key (including api_key) is preserved as is and never returned to the page.

import { randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync, readdirSync, renameSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { precheck, resolveService, thresholds, validateRules } from "./core.mjs";

const args = process.argv.slice(2);
const opt = (name, fallback) => (args.includes(name) ? args[args.indexOf(name) + 1] : fallback);
const PORT = Number(opt("--port", 8765));
const DB_FILE = opt("--db", join(homedir(), ".decision-guard", "decisions.db"));
const PAGE = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "web-page.html"), "utf8");
const COLUMNS = ["id", "ts", "agent", "session_id", "cwd", "command", "source", "rule", "provider", "model", "choice", "confidence", "probabilities", "user_requested", "action", "latency_ms", "input_tokens", "error"];
const CONFIG_FILE = opt("--config", join(homedir(), ".decision-guard", "config.json"));
// Mirrors the names in core.mjs's DENY_LIST; kept here only for display, never used for matching.
const BUILTIN_DENY = [
	{ name: "disk-erase", description: "diskutil erase / secureErase / partitionDisk / reformat / apfs delete..." },
	{ name: "raw-device-write", description: "dd ... of=/dev/rdisk, or a redirect onto /dev/rdisk" },
	{ name: "mkfs", description: "mkfs / newfs" },
	{ name: "fork-bomb", description: ":(){ :|:& };:" },
];

// Runs fn on a fresh read-only handle with the set of columns this database actually has (an older file may lack some).
function withDb(fn) {
	let db;
	try {
		db = new DatabaseSync(DB_FILE, { readOnly: true });
		db.exec("PRAGMA busy_timeout = 2000");
		const have = new Set(db.prepare("PRAGMA table_info(decisions)").all().map((c) => c.name));
		return have.size ? fn(db, have) : undefined;
	} catch {
		return undefined; // no database yet, or no decisions table
	} finally {
		db?.close();
	}
}

const like = (s) => `%${s.replace(/[\\%_]/g, "\\$&")}%`;

function where(params, have) {
	const sql = [];
	const vals = [];
	const view = params.get("view") ?? "dangerous";
	if (view === "dangerous") sql.push("action IN ('ask','deny')");
	else if (view === "unjudged") sql.push("source IN ('no_service','error')");
	for (const key of ["agent", "source", "rule", "action"]) {
		const v = params.get(key);
		if (v && have.has(key)) {
			sql.push(`${key} = ?`);
			vals.push(v);
		}
	}
	const q = params.get("q");
	if (q) {
		sql.push("(command LIKE ? ESCAPE '\\' OR cwd LIKE ? ESCAPE '\\')");
		vals.push(like(q), like(q));
	}
	return { clause: sql.length ? `WHERE ${sql.join(" AND ")}` : "", vals };
}

function decisions(params) {
	const limit = Math.min(Math.max(Number(params.get("limit")) || 100, 1), 500);
	const out = withDb((db, have) => {
		const { clause, vals } = where(params, have);
		const before = Number(params.get("before"));
		const paged = before > 0 ? `${clause ? `${clause} AND` : "WHERE"} id < ?` : clause;
		const select = COLUMNS.map((c) => (have.has(c) ? c : `NULL AS ${c}`)).join(", ");
		const rows = db.prepare(`SELECT ${select} FROM decisions ${paged} ORDER BY id DESC LIMIT ?`).all(...vals, ...(before > 0 ? [before] : []), limit + 1);
		const page = rows.slice(0, limit).map((r) => {
			let p;
			try {
				p = JSON.parse(r.probabilities)?.destructive;
			} catch {
				// older rows hold an array or nothing
			}
			const { probabilities, ...rest } = r;
			return { ...rest, p_destructive: typeof p === "number" ? p : null };
		});
		return { rows: page, hasMore: rows.length > limit };
	});
	return out ?? { rows: [], hasMore: false };
}

/** The requests sent to the decision service for one decision, exactly as sent and received. */
function calls(decisionId) {
	return withDb((db) => db.prepare("SELECT id, ts, provider, model, url, purpose, request, status, response, latency_ms, error FROM api_calls WHERE decision_id = ? ORDER BY id").all(decisionId)) ?? [];
}

const percentile = (sorted, p) => (sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))] : null);

function summary() {
	const empty = { total: 0, asked: 0, denied: 0, unjudged: 0, agents: [], sources: [], rules: [], verdicts: [], days: [], hours: [], top: [], latency: { n: 0, p50: null, p95: null, errors: 0 } };
	return (
		withDb((db, have) => {
			const all = (sql, ...vals) => db.prepare(sql).all(...vals);
			const totals = all("SELECT count(*) AS total, sum(action = 'ask') AS asked, sum(action = 'deny') AS denied, sum(source IN ('no_service','error')) AS unjudged FROM decisions")[0];
			const since = new Date(Date.now() - 24 * 3_600_000).toISOString();
			let latency = empty.latency;
			try {
				const ms = all("SELECT latency_ms FROM api_calls WHERE status = 200 AND latency_ms IS NOT NULL ORDER BY latency_ms").map((r) => r.latency_ms);
				latency = { n: ms.length, p50: percentile(ms, 0.5), p95: percentile(ms, 0.95), errors: all("SELECT count(*) AS n FROM api_calls WHERE status IS NULL OR status >= 400")[0].n };
			} catch {
				// no api_calls table yet
			}
			return {
				...totals,
				agents: all("SELECT agent, count(*) AS total, sum(action IN ('ask','deny')) AS dangerous FROM decisions GROUP BY agent ORDER BY total DESC"),
				sources: all("SELECT source, count(*) AS n FROM decisions GROUP BY source ORDER BY n DESC"),
				rules: have.has("rule") ? all("SELECT rule, count(*) AS n FROM decisions WHERE rule IS NOT NULL GROUP BY rule ORDER BY n DESC") : [],
				verdicts: all("SELECT choice, count(*) AS n FROM decisions WHERE choice IS NOT NULL GROUP BY choice ORDER BY n DESC"),
				days: all("SELECT date(ts) AS day, count(*) AS total, sum(action IN ('ask','deny')) AS dangerous FROM decisions GROUP BY day ORDER BY day DESC LIMIT 14"),
				hours: all("SELECT substr(ts, 1, 13) AS hour, count(*) AS total, sum(action IN ('ask','deny')) AS dangerous FROM decisions WHERE ts >= ? GROUP BY hour ORDER BY hour", since),
				top: all("SELECT substr(command, 1, 200) AS command, count(*) AS n, max(action) AS action FROM decisions WHERE action IN ('ask','deny') GROUP BY command ORDER BY n DESC, max(id) DESC LIMIT 8"),
				latency,
			};
		}) ?? empty
	);
}

/** Which service answers, the thresholds in force and how much is stored. Never includes a credential. */
function status() {
	const svc = resolveService();
	const rows = withDb((db) => {
		const n = (table) => {
			try {
				return db.prepare(`SELECT count(*) AS n FROM ${table}`).get().n;
			} catch {
				return 0;
			}
		};
		return { decisions: n("decisions"), api_calls: n("api_calls"), prompts: n("prompts") };
	}) ?? { decisions: 0, api_calls: 0, prompts: 0 };
	const archiveDir = join(dirname(DB_FILE), "archive");
	const files = existsSync(archiveDir) ? readdirSync(archiveDir).filter((f) => f.endsWith(".db.gz")).sort() : [];
	return {
		service: svc.error ? { error: svc.error } : { name: svc.name, format: svc.format, url: svc.url, model: svc.model, timeout_ms: svc.timeout, has_key: Boolean(svc.key) },
		thresholds: thresholds(),
		fail_closed: Boolean(process.env.DECISION_GUARD_FAIL_CLOSED),
		database: { path: DB_FILE, bytes: existsSync(DB_FILE) ? statSync(DB_FILE).size : 0, ...rows },
		archives: { count: files.length, bytes: files.reduce((sum, f) => sum + statSync(join(archiveDir, f)).size, 0), latest: files.at(-1) ?? null },
	};
}

/** Config.json's allow/deny, cleaned through validateRules so an already-saved bad entry cannot slip through. */
function readRules() {
	let raw = {};
	try {
		raw = JSON.parse(readFileSync(CONFIG_FILE, "utf8"));
	} catch {
		// no config file yet
	}
	return validateRules({ allow: raw.allow, deny: raw.deny });
}

/** Writes only the allow/deny keys, preserving every other key (api_key, base_url, ...), atomically and mode 600. */
function writeRules(allow, deny) {
	let raw = {};
	try {
		raw = JSON.parse(readFileSync(CONFIG_FILE, "utf8"));
	} catch {
		// no config file yet
	}
	const next = { ...raw, allow, deny };
	const tmp = `${CONFIG_FILE}.${process.pid}`;
	writeFileSync(tmp, JSON.stringify(next, null, 2), { mode: 0o600 });
	renameSync(tmp, CONFIG_FILE);
}

const nonce = randomBytes(16).toString("base64");
// A per-process secret the page must echo back on every POST (like the CSP nonce), so a page from another origin
// that merely guesses the loopback Host cannot write rules just by being allowed to load the HTML.
const token = randomBytes(32).toString("base64");
const tokenBuf = Buffer.from(token);
const safeEqual = (a) => {
	const buf = Buffer.from(a);
	return buf.length === tokenBuf.length && timingSafeEqual(buf, tokenBuf);
};

const server = createServer((req, res) => {
	const allowed = new Set([`127.0.0.1:${server.address().port}`, `localhost:${server.address().port}`, `[::1]:${server.address().port}`]);
	const send = (status, type, body) => {
		res.writeHead(status, {
			"content-type": `${type}; charset=utf-8`,
			"cache-control": "no-store",
			"x-content-type-options": "nosniff",
			"referrer-policy": "no-referrer",
			"content-security-policy": `default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'`,
		});
		res.end(body);
	};
	if (!allowed.has(req.headers.host ?? "")) return send(403, "text/plain", "forbidden");
	const url = new URL(req.url, "http://localhost");

	if (req.method === "GET") {
		if (url.pathname === "/") return send(200, "text/html", PAGE.replaceAll("__NONCE__", nonce).replaceAll("__TOKEN__", token));
		if (url.pathname === "/api/decisions") return send(200, "application/json", JSON.stringify(decisions(url.searchParams)));
		if (url.pathname === "/api/summary") return send(200, "application/json", JSON.stringify(summary()));
		if (url.pathname === "/api/status") return send(200, "application/json", JSON.stringify(status()));
		if (url.pathname === "/api/calls") return send(200, "application/json", JSON.stringify(calls(Number(url.searchParams.get("decision")))));
		if (url.pathname === "/api/rules") {
			const rules = readRules();
			return send(200, "application/json", JSON.stringify({ allow: rules.allow, deny: rules.deny, builtin: BUILTIN_DENY }));
		}
		return send(404, "text/plain", "not found");
	}

	if (req.method === "POST" && (url.pathname === "/api/rules" || url.pathname === "/api/check")) {
		if ((req.headers["content-type"] ?? "").split(";")[0].trim() !== "application/json") return send(400, "text/plain", "content-type must be application/json");
		const presented = req.headers["x-dg-token"];
		if (typeof presented !== "string" || !safeEqual(presented)) return send(403, "text/plain", "forbidden");
		const origin = req.headers.origin;
		if (origin != null && origin !== `http://${req.headers.host}`) return send(403, "text/plain", "forbidden");

		let body = "";
		let tooLarge = false;
		req.on("data", (chunk) => {
			if (tooLarge) return;
			body += chunk;
			if (Buffer.byteLength(body) > 65536) {
				tooLarge = true;
				send(413, "text/plain", "body too large");
				req.destroy();
			}
		});
		req.on("end", () => {
			if (tooLarge) return;
			let json;
			try {
				json = JSON.parse(body);
			} catch {
				return send(400, "application/json", JSON.stringify({ errors: [{ list: null, index: null, pattern: null, message: "body must be valid JSON" }] }));
			}
			if (url.pathname === "/api/rules") {
				const result = validateRules({ allow: json.allow, deny: json.deny });
				if (!result.ok) return send(400, "application/json", JSON.stringify({ errors: result.errors }));
				writeRules(result.allow, result.deny);
				return send(200, "application/json", JSON.stringify({ allow: result.allow, deny: result.deny }));
			}
			// /api/check: stateless dry run, never calls the model and never writes anything.
			const hasOwn = Object.prototype.hasOwnProperty;
			const rules = hasOwn.call(json, "allow") || hasOwn.call(json, "deny") ? validateRules({ allow: json.allow, deny: json.deny }) : readRules();
			return send(200, "application/json", JSON.stringify(precheck(String(json.command ?? ""), String(json.cwd ?? process.cwd()), rules)));
		});
		return;
	}
	return send(405, "text/plain", "method not allowed");
});

server.on("error", (err) => {
	console.error(err.code === "EADDRINUSE" ? `port ${PORT} is already in use, pick another with --port` : `viewer failed: ${err.message}`);
	process.exit(1);
});
server.listen(PORT, "127.0.0.1", () => {
	console.log(`decision-guard viewer: http://127.0.0.1:${server.address().port}/   (database: ${DB_FILE}, Ctrl+C to stop)`);
});
