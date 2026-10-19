//! End-to-end tests of `decision-guard archive`.

mod common;

use common::*;
use flate2::read::GzDecoder;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const OLD: &str = "2026-01-01T00:00:00.000Z";

struct Log {
    home: PathBuf,
    db: PathBuf,
    out: PathBuf,
    old_id: i64,
}

/// A database in a fresh HOME with one old and one recent decision, each with its API call, and one old and one recent
/// prompt.
fn seeded() -> Log {
    let home = home();
    let (url, _) = serve(|_| json!({"answers": {"risk": risk(0.95)}}));
    let env = [("DECISION_GUARD_BASE_URL", url.as_str())];
    let prompt = |session: &str, text: &str| {
        json!({"hook_event_name": "UserPromptSubmit", "session_id": session, "prompt": text})
            .to_string()
    };
    hook(&home, "claude", &prompt("old-s", "old prompt"), &env);
    hook(&home, "claude", &prompt("new-s", "new prompt"), &env);
    hook(&home, "claude", &bash("old-job one"), &env);
    hook(&home, "claude", &bash("new-job two"), &env);
    let dir = home.join(".decision-guard");
    let conn = db(&home);
    let old_id: i64 = conn
        .query_row(
            "SELECT id FROM decisions WHERE command = 'old-job one'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    conn.execute("UPDATE decisions SET ts = ? WHERE id = ?", (OLD, old_id))
        .unwrap();
    conn.execute(
        "UPDATE api_calls SET ts = ? WHERE decision_id = ?",
        (OLD, old_id),
    )
    .unwrap();
    conn.execute("UPDATE prompts SET ts = ? WHERE text = 'old prompt'", [OLD])
        .unwrap();
    Log {
        db: dir.join("decisions.db"),
        out: dir.join("archive"),
        home,
        old_id,
    }
}

#[derive(Debug, PartialEq)]
struct Live {
    commands: Vec<String>,
    calls: i64,
    prompts: Vec<String>,
}

fn live(path: &Path) -> Live {
    let conn = Connection::open(path).unwrap();
    let strings = |sql: &str| -> Vec<String> {
        conn.prepare(sql)
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    Live {
        commands: strings("SELECT command FROM decisions ORDER BY id"),
        calls: conn
            .query_row("SELECT count(*) FROM api_calls", [], |r| r.get(0))
            .unwrap(),
        prompts: strings("SELECT text FROM prompts ORDER BY id"),
    }
}

fn archive_with(home: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_decision-guard"))
        .arg("archive")
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .envs(env.iter().copied())
        .output()
        .unwrap()
}

fn archive(log: &Log, extra: &[&str]) -> Output {
    let (db, out) = (log.db.to_str().unwrap(), log.out.to_str().unwrap());
    let mut args = vec!["--db", db, "--out", out, "--keep-days", "30"];
    args.extend_from_slice(extra);
    archive_with(&log.home, &args, &[])
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn strings(l: &[&str]) -> Vec<String> {
    l.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn moves_rows_older_than_the_cut_off_with_their_api_calls_into_a_gzipped_database_that_reads_back_identical(
) {
    let log = seeded();
    let before = live(&log.db);
    assert_eq!(before.commands, strings(&["old-job one", "new-job two"]));

    let res = archive(&log, &[]);
    assert_eq!(res.status.code(), Some(0), "{}", stderr(&res));
    let out = stdout(&res);
    assert!(out.contains("1 decisions, 1 api calls, 1 prompts"), "{out}");
    assert!(
        out.starts_with("keeping the last 30 days (rows before "),
        "{out}"
    );
    let archived = out.lines().last().unwrap();
    assert!(
        archived.starts_with(&format!("archived to {}/decisions-", log.out.display()))
            && archived.contains(".db.gz ("),
        "{archived}"
    );
    assert!(
        archived.contains(&format!("{}: ", log.db.display())) && archived.contains(" KB -> "),
        "{archived}"
    );

    assert_eq!(
        live(&log.db),
        Live {
            commands: strings(&["new-job two"]),
            calls: 1,
            prompts: strings(&["new prompt"])
        }
    );

    let files: Vec<_> = std::fs::read_dir(&log.out)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(
        files.len(),
        1,
        "only the archive is left behind, no temp file: {files:?}"
    );
    let name = files[0].file_name().unwrap().to_str().unwrap();
    assert!(
        name.starts_with("decisions-")
            && name.ends_with(".db.gz")
            && name.len() == "decisions-2026-10-12.db.gz".len()
    );
    assert_eq!(
        std::fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&log.out).unwrap().permissions().mode() & 0o777,
        0o700
    );

    let unpacked = log.home.join("unpacked.db");
    let mut raw = Vec::new();
    GzDecoder::new(std::fs::File::open(&files[0]).unwrap())
        .read_to_end(&mut raw)
        .unwrap();
    std::fs::write(&unpacked, raw).unwrap();
    let moved = Connection::open(&unpacked).unwrap();
    let decisions: Vec<(i64, String)> = moved
        .prepare("SELECT id, command FROM decisions")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(decisions, [(log.old_id, "old-job one".to_string())]);
    let (decision_id, purpose, request, response): (i64, String, String, String) = moved
        .query_row(
            "SELECT decision_id, purpose, request, response FROM api_calls",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!((decision_id, purpose.as_str()), (log.old_id, "risk"));
    let request: Value = serde_json::from_str(&request).unwrap();
    assert!(request["state"].as_str().unwrap().contains("old-job one"));
    let response: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(response["answers"]["risk"]["choice"], "destructive");
    let prompts: Vec<String> = moved
        .prepare("SELECT text FROM prompts")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(prompts, ["old prompt"]);
}

#[test]
fn an_api_call_with_no_decision_goes_by_its_own_age() {
    let log = seeded();
    let conn = db(&log.home);
    for ts in [OLD, "2999-01-01T00:00:00.000Z"] {
        conn.execute(
            "INSERT INTO api_calls (decision_id, ts, request) VALUES (NULL, ?, '{}')",
            [ts],
        )
        .unwrap();
    }
    drop(conn);
    let res = archive(&log, &[]);
    assert_eq!(res.status.code(), Some(0), "{}", stderr(&res));
    assert!(
        stdout(&res).contains("1 decisions, 2 api calls, 1 prompts"),
        "{}",
        stdout(&res)
    );
    // The recent decision's call and the recent orphan stay.
    assert_eq!(live(&log.db).calls, 2);
}

#[test]
fn a_dry_run_writes_nothing_and_nothing_old_means_nothing_to_do() {
    let log = seeded();
    let dry = archive(&log, &["--dry-run"]);
    assert_eq!(dry.status.code(), Some(0));
    assert!(stdout(&dry).contains("1 decisions, 1 api calls, 1 prompts"));
    assert!(stdout(&dry).contains("dry run: nothing written"));
    assert!(!log.out.exists());
    assert_eq!(
        live(&log.db).commands,
        strings(&["old-job one", "new-job two"])
    );

    let (db, out) = (log.db.to_str().unwrap(), log.out.to_str().unwrap());
    let recent = archive_with(
        &log.home,
        &["--db", db, "--out", out, "--keep-days", "100000"],
        &[],
    );
    assert_eq!(recent.status.code(), Some(0));
    assert!(
        stdout(&recent).contains("nothing to archive"),
        "{}",
        stdout(&recent)
    );
    assert!(!log.out.exists());
}

#[test]
fn if_the_archive_cannot_be_written_the_live_database_is_left_exactly_as_it_was() {
    let log = seeded();
    std::fs::write(&log.out, "a file where the archive directory should be").unwrap();
    let before = std::fs::read(&log.db).unwrap();
    let res = archive(&log, &[]);
    assert_eq!(res.status.code(), Some(1));
    assert!(
        stderr(&res).starts_with("archive failed, the live database was not changed: "),
        "{}",
        stderr(&res)
    );
    assert_eq!(
        live(&log.db),
        Live {
            commands: strings(&["old-job one", "new-job two"]),
            calls: 2,
            prompts: strings(&["old prompt", "new prompt"])
        }
    );
    assert_eq!(
        std::fs::read(&log.db).unwrap(),
        before,
        "not a byte changed"
    );
}

#[test]
fn a_file_that_is_not_a_database_fails_without_touching_it() {
    let h = home();
    let junk = h.join("junk.db");
    std::fs::write(
        &junk,
        "this is not a sqlite database, just long enough to look like one ".repeat(4),
    )
    .unwrap();
    let res = archive_with(
        &h,
        &[
            "--db",
            junk.to_str().unwrap(),
            "--out",
            h.join("out").to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(res.status.code(), Some(1));
    assert!(
        stderr(&res).starts_with("archive failed, the live database was not changed: "),
        "{}",
        stderr(&res)
    );
    assert!(!h.join("out").exists());
}

#[test]
fn handles_a_database_that_does_not_exist_yet_or_has_no_decisions_table() {
    let h = home();
    let missing = h.join("nope.db");
    let res = archive_with(
        &h,
        &[
            "--db",
            missing.to_str().unwrap(),
            "--out",
            h.join("nope-archive").to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(res.status.code(), Some(0));
    assert_eq!(
        stdout(&res),
        format!(
            "nothing to archive: {} does not exist yet\n",
            missing.display()
        )
    );
    assert!(!missing.exists(), "archive never creates the database");

    let empty = h.join("empty.db");
    Connection::open(&empty)
        .unwrap()
        .execute_batch("CREATE TABLE other (x)")
        .unwrap();
    let res = archive_with(&h, &["--db", empty.to_str().unwrap()], &[]);
    assert_eq!(res.status.code(), Some(0));
    assert_eq!(stdout(&res), "nothing to archive: no decisions table yet\n");
}

#[test]
fn keep_days_comes_from_the_flag_then_the_environment_then_config_then_30_and_must_be_a_number_of_days(
) {
    let h = home();
    let conn = Connection::open(h.join("d.db")).unwrap();
    conn.execute_batch("CREATE TABLE decisions (id INTEGER PRIMARY KEY, ts TEXT)")
        .unwrap();
    drop(conn);
    let db = h.join("d.db");
    let args = ["--db", db.to_str().unwrap(), "--dry-run"];
    let keeping = |o: &Output| stdout(o).split(" days").next().unwrap().to_string();

    assert_eq!(
        keeping(&archive_with(&h, &args, &[])),
        "keeping the last 30"
    );
    std::fs::create_dir_all(h.join(".decision-guard")).unwrap();
    std::fs::write(
        h.join(".decision-guard/config.json"),
        r#"{"archive_keep_days": 7}"#,
    )
    .unwrap();
    assert_eq!(keeping(&archive_with(&h, &args, &[])), "keeping the last 7");
    let env = [("DECISION_GUARD_ARCHIVE_KEEP_DAYS", "12")];
    assert_eq!(
        keeping(&archive_with(&h, &args, &env)),
        "keeping the last 12"
    );
    let mut with_flag = args.to_vec();
    with_flag.extend(["--keep-days", "0.5"]);
    assert_eq!(
        keeping(&archive_with(&h, &with_flag, &env)),
        "keeping the last 0.5"
    );
    // An empty variable is a value, not "unset": zero days.
    assert_eq!(
        keeping(&archive_with(
            &h,
            &args,
            &[("DECISION_GUARD_ARCHIVE_KEEP_DAYS", "")]
        )),
        "keeping the last 0"
    );

    for bad in ["-1", "abc", "Infinity", "NaN"] {
        let mut a = args.to_vec();
        a.extend(["--keep-days", bad]);
        let res = archive_with(&h, &a, &[]);
        assert_eq!(res.status.code(), Some(2), "{bad}");
        assert_eq!(
            stderr(&res),
            "keep-days must be a number of days, 0 or more\n"
        );
    }
    // A huge value means a cut-off before any row: nothing moves.
    let mut a = args.to_vec();
    a.extend(["--keep-days", "1e12"]);
    assert_eq!(archive_with(&h, &a, &[]).status.code(), Some(0));
}

#[test]
fn a_second_archive_on_the_same_day_gets_its_own_file() {
    let log = seeded();
    assert_eq!(archive(&log, &[]).status.code(), Some(0));
    // Age the recent rows too, then archive again.
    db(&log.home)
        .execute_batch(&format!("UPDATE decisions SET ts = '{OLD}'; UPDATE api_calls SET ts = '{OLD}'; UPDATE prompts SET ts = '{OLD}'"))
        .unwrap();
    let res = archive(&log, &[]);
    assert_eq!(res.status.code(), Some(0), "{}", stderr(&res));
    let mut names: Vec<String> = std::fs::read_dir(&log.out)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(
        names[1].ends_with("-2.db.gz") || names[0].ends_with("-2.db.gz"),
        "{names:?}"
    );
    assert_eq!(
        live(&log.db),
        Live {
            commands: vec![],
            calls: 0,
            prompts: vec![]
        }
    );
}
