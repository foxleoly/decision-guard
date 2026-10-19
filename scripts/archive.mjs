#!/usr/bin/env node
// decision-guard archive: moves rows older than N days out of decisions.db into a gzipped SQLite file and shrinks the
// live database, so the log keeps its history without growing forever.
//   node archive.mjs [--keep-days 30] [--dry-run] [--db path] [--out dir]
// Keep-days also comes from DECISION_GUARD_ARCHIVE_KEEP_DAYS or "archive_keep_days" in config.json (default 30).
//
// Order matters: the archive is written and read back first, and only then are the rows deleted, so a failure leaves
// the live database untouched. To read an archive: `gunzip -c archive/decisions-2026-10-12.db.gz > /tmp/a.db`, then
// `sqlite3 /tmp/a.db` or `node web.mjs --db /tmp/a.db`.

import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { gunzipSync, gzipSync } from "node:zlib";

const args = process.argv.slice(2);
const opt = (name, fallback) => (args.includes(name) ? args[args.indexOf(name) + 1] : fallback);
const DRY_RUN = args.includes("--dry-run");
const HOME_DIR = join(homedir(), ".decision-guard");
const DB_FILE = opt("--db", join(HOME_DIR, "decisions.db"));
const OUT_DIR = opt("--out", join(dirname(DB_FILE), "archive"));

function readConfig() {
	try {
		return JSON.parse(readFileSync(join(HOME_DIR, "config.json"), "utf8"));
	} catch {
		return {};
	}
}

const KEEP_DAYS = Number(opt("--keep-days", process.env.DECISION_GUARD_ARCHIVE_KEEP_DAYS ?? readConfig().archive_keep_days ?? 30));
if (!Number.isFinite(KEEP_DAYS) || KEEP_DAYS < 0) {
	console.error("keep-days must be a number of days, 0 or more");
	process.exit(2);
}
if (!existsSync(DB_FILE)) {
	console.log(`nothing to archive: ${DB_FILE} does not exist yet`);
	process.exit(0);
}

const kb = (bytes) => `${(bytes / 1024).toFixed(0)} KB`;
const cutoff = new Date(Date.now() - KEEP_DAYS * 86_400_000).toISOString(); // a literal we built ourselves, never user text
const db = new DatabaseSync(DB_FILE);
const tmp = join(OUT_DIR, `.archive-${process.pid}.db`);

try {
	db.exec("PRAGMA busy_timeout = 15000");
	const tables = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((t) => t.name));
	if (!tables.has("decisions")) {
		console.log("nothing to archive: no decisions table yet");
		process.exit(0);
	}
	const oldDecisions = `SELECT id FROM decisions WHERE ts < '${cutoff}'`;
	// What moves, per table. A call goes with its decision; a call with no decision goes by its own age.
	const plan = {
		decisions: `ts < '${cutoff}'`,
		api_calls: `decision_id IN (${oldDecisions}) OR (decision_id IS NULL AND ts < '${cutoff}')`,
		prompts: `ts < '${cutoff}'`,
	};
	const count = (table) => (tables.has(table) ? db.prepare(`SELECT count(*) AS n FROM ${table} WHERE ${plan[table]}`).get().n : 0);
	const counts = Object.fromEntries(Object.keys(plan).map((t) => [t, count(t)]));
	const total = counts.decisions + counts.api_calls + counts.prompts;
	const before = statSync(DB_FILE).size;

	console.log(`keeping the last ${KEEP_DAYS} days (rows before ${cutoff.slice(0, 10)} move): ${counts.decisions} decisions, ${counts.api_calls} api calls, ${counts.prompts} prompts`);
	if (total === 0) {
		console.log("nothing to archive");
		process.exit(0);
	}
	if (DRY_RUN) {
		console.log("dry run: nothing written");
		process.exit(0);
	}

	mkdirSync(OUT_DIR, { recursive: true, mode: 0o700 });
	const stamp = new Date().toISOString().slice(0, 10);
	let archive = join(OUT_DIR, `decisions-${stamp}.db.gz`);
	for (let i = 2; existsSync(archive); i++) archive = join(OUT_DIR, `decisions-${stamp}-${i}.db.gz`);

	// 1. Copy the old rows into a fresh database and check the copy.
	db.exec(`ATTACH DATABASE '${tmp.replaceAll("'", "''")}' AS arc`);
	for (const table of Object.keys(plan)) if (tables.has(table)) db.exec(`CREATE TABLE arc.${table} AS SELECT * FROM main.${table} WHERE ${plan[table]}`);
	for (const table of Object.keys(plan)) {
		if (tables.has(table) && db.prepare(`SELECT count(*) AS n FROM arc.${table}`).get().n !== counts[table]) throw new Error(`the copy of ${table} is incomplete`);
	}
	db.exec("DETACH DATABASE arc");

	// 2. Compress it and read it back.
	const raw = readFileSync(tmp);
	writeFileSync(archive, gzipSync(raw), { mode: 0o600 });
	if (!gunzipSync(readFileSync(archive)).equals(raw)) throw new Error("the compressed archive does not read back identical");
	rmSync(tmp);

	// 3. Only now remove the rows from the live database, and give the space back.
	db.exec("BEGIN IMMEDIATE");
	try {
		for (const table of ["api_calls", "decisions", "prompts"]) if (tables.has(table)) db.exec(`DELETE FROM ${table} WHERE ${plan[table]}`);
		db.exec("COMMIT");
	} catch (err) {
		db.exec("ROLLBACK");
		throw err;
	}
	db.exec("VACUUM");
	console.log(`archived to ${archive} (${kb(statSync(archive).size)}); ${DB_FILE}: ${kb(before)} -> ${kb(statSync(DB_FILE).size)}`);
} catch (err) {
	console.error(`archive failed, the live database was not changed: ${err.message}`);
	process.exitCode = 1;
} finally {
	rmSync(tmp, { force: true });
	db.close();
}
