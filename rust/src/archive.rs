//! `decision-guard archive [--keep-days 30] [--dry-run] [--db path] [--out dir]`: moves rows older than N days out of
//! decisions.db into a gzipped SQLite file and shrinks the live database, so the log keeps its history without growing
//! forever.
//! Keep-days also comes from DECISION_GUARD_ARCHIVE_KEEP_DAYS or "archive_keep_days" in config.json (default 30).
//!
//! Order matters: the archive is written and read back first, and only then are the rows deleted, so a failure leaves
//! the live database untouched. To read an archive: `gunzip -c archive/decisions-2026-10-12.db.gz > /tmp/a.db`, then
//! `sqlite3 /tmp/a.db` or `decision-guard web --db /tmp/a.db`.

use crate::jsc::{env, fmt_number, iso_from_ms, js_number, now_ms, number_str, opt};
use crate::judge::read_config;
use crate::store::db_path;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use rusqlite::{params, Connection};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Runs the archive; returns the process exit code. Messages go to stdout/stderr exactly like the script.
pub fn main(args: &[String]) -> i32 {
    match run(args) {
        Ok(code) => code,
        Err(Fail::Usage(msg)) => {
            eprintln!("{msg}");
            2
        }
        Err(Fail::Archive(msg)) => {
            eprintln!("archive failed, the live database was not changed: {msg}");
            1
        }
    }
}

enum Fail {
    Usage(String),
    Archive(String),
}

impl<E: std::fmt::Display> From<E> for Fail {
    fn from(e: E) -> Self {
        Fail::Archive(e.to_string())
    }
}

fn kb(bytes: u64) -> String {
    format!("{} KB", (bytes + 512) / 1024) // (bytes / 1024).toFixed(0): ties go up
}

fn run(args: &[String]) -> Result<i32, Fail> {
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let db_file = opt(args, "--db")
        .map_err(Fail::Usage)?
        .map_or_else(db_path, PathBuf::from);
    let out_dir = opt(args, "--out").map_err(Fail::Usage)?.map_or_else(
        || db_file.parent().unwrap_or(Path::new("")).join("archive"),
        PathBuf::from,
    );
    // `??` in the script: an empty environment variable is a value (0 days), not "unset".
    let keep_days = match opt(args, "--keep-days").map_err(Fail::Usage)? {
        Some(s) => number_str(s),
        None => match env("DECISION_GUARD_ARCHIVE_KEEP_DAYS") {
            Some(s) => number_str(&s),
            None => read_config()
                .get("archive_keep_days")
                .filter(|v| !v.is_null())
                .map_or(30.0, js_number),
        },
    };
    if !keep_days.is_finite() || keep_days < 0.0 {
        return Err(Fail::Usage(
            "keep-days must be a number of days, 0 or more".into(),
        ));
    }
    if !db_file.exists() {
        println!(
            "nothing to archive: {} does not exist yet",
            db_file.display()
        );
        return Ok(0);
    }

    // A literal we built ourselves, never user text. Clamped to year 0000: nothing is older, and Date has no wider ISO form here.
    let cutoff_ms = (now_ms() as f64 - keep_days * 86_400_000.0).max(-62_167_219_200_000.0);
    let cutoff = iso_from_ms(cutoff_ms as i64);
    let db = Connection::open(&db_file)?;
    let tmp = out_dir.join(format!(".archive-{}.db", std::process::id()));
    let result = archive(&db, &db_file, &out_dir, &tmp, &cutoff, keep_days, dry_run);
    let _ = std::fs::remove_file(&tmp);
    result
}

fn archive(
    db: &Connection,
    db_file: &Path,
    out_dir: &Path,
    tmp: &Path,
    cutoff: &str,
    keep_days: f64,
    dry_run: bool,
) -> Result<i32, Fail> {
    db.busy_timeout(std::time::Duration::from_millis(15000))?;
    let tables: HashSet<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    if !tables.contains("decisions") {
        println!("nothing to archive: no decisions table yet");
        return Ok(0);
    }
    let old_decisions = format!("SELECT id FROM decisions WHERE ts < '{cutoff}'");
    // What moves, per table. A call goes with its decision; a call with no decision goes by its own age.
    let plan = [
        ("decisions", format!("ts < '{cutoff}'")),
        (
            "api_calls",
            format!(
                "decision_id IN ({old_decisions}) OR (decision_id IS NULL AND ts < '{cutoff}')"
            ),
        ),
        ("prompts", format!("ts < '{cutoff}'")),
    ];
    let count = |schema: &str, table: &str, filter: &str| -> rusqlite::Result<i64> {
        db.query_row(
            &format!("SELECT count(*) FROM {schema}.{table} {filter}"),
            [],
            |r| r.get(0),
        )
    };
    let mut counts = Vec::new();
    for (table, filter) in &plan {
        counts.push(if tables.contains(*table) {
            count("main", table, &format!("WHERE {filter}"))?
        } else {
            0
        });
    }
    let total: i64 = counts.iter().sum();
    let before = std::fs::metadata(db_file)?.len();

    println!(
        "keeping the last {} days (rows before {} move): {} decisions, {} api calls, {} prompts",
        fmt_number(keep_days),
        &cutoff[..10],
        counts[0],
        counts[1],
        counts[2]
    );
    if total == 0 {
        println!("nothing to archive");
        return Ok(0);
    }
    if dry_run {
        println!("dry run: nothing written");
        return Ok(0);
    }

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(out_dir)?;
    let stamp = &iso_from_ms(now_ms())[..10];
    let mut archive = out_dir.join(format!("decisions-{stamp}.db.gz"));
    let mut i = 2;
    while archive.exists() {
        archive = out_dir.join(format!("decisions-{stamp}-{i}.db.gz"));
        i += 1;
    }

    // 1. Copy the old rows into a fresh database and check the copy.
    db.execute("ATTACH DATABASE ?1 AS arc", params![tmp.to_string_lossy()])?;
    for (table, filter) in &plan {
        if tables.contains(*table) {
            db.execute_batch(&format!(
                "CREATE TABLE arc.{table} AS SELECT * FROM main.{table} WHERE {filter}"
            ))?;
        }
    }
    for ((table, _), expected) in plan.iter().zip(&counts) {
        if tables.contains(*table) && count("arc", table, "")? != *expected {
            return Err(Fail::Archive(format!("the copy of {table} is incomplete")));
        }
    }
    db.execute_batch("DETACH DATABASE arc")?;

    // 2. Compress it and read it back.
    let raw = std::fs::read(tmp)?;
    let written = (|| -> Result<(), Fail> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&archive)?;
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&raw)?;
        file.write_all(&gz.finish()?)?;
        file.sync_all()?;
        let mut back = Vec::new();
        GzDecoder::new(std::fs::File::open(&archive)?).read_to_end(&mut back)?;
        if back != raw {
            return Err(Fail::Archive(
                "the compressed archive does not read back identical".into(),
            ));
        }
        Ok(())
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&archive); // a half-written archive must not be mistaken for a good one
        return Err(e);
    }
    std::fs::remove_file(tmp)?;

    // 3. Only now remove the rows from the live database, and give the space back.
    db.execute_batch("BEGIN IMMEDIATE")?;
    let deleted = ["api_calls", "decisions", "prompts"]
        .iter()
        .try_for_each(|table| match plan.iter().find(|(t, _)| t == table) {
            Some((_, filter)) if tables.contains(*table) => {
                db.execute_batch(&format!("DELETE FROM {table} WHERE {filter}"))
            }
            _ => Ok(()),
        });
    match deleted.and_then(|()| db.execute_batch("COMMIT")) {
        Ok(()) => {}
        Err(e) => {
            let _ = db.execute_batch("ROLLBACK");
            return Err(e.into());
        }
    }
    db.execute_batch("VACUUM")?;
    println!(
        "archived to {} ({}); {}: {} -> {}",
        archive.display(),
        kb(std::fs::metadata(&archive)?.len()),
        db_file.display(),
        kb(before),
        kb(std::fs::metadata(db_file)?.len())
    );
    Ok(0)
}
