//! Hot-path latency test: P95 of `open + select + update` must stay ≤1.5 ms.
//!
//! Budget (live.rs header): open+select ≤1 ms, hit UPDATE ≤0.5 ms — a combined P95 of 1.5 ms.
//! No dev-dependencies needed; the temp dir is created under the system temp with a unique suffix.

use std::env;
use std::time::Instant;

/// The whole hot path the hook takes per command: open the db, load the rows, match a command,
/// record one hit. Returned in ms.
fn one_iteration(db: &std::path::Path) -> f64 {
    let start = Instant::now();
    let conn = decision_guard::live::open(db).expect("open");
    let live = decision_guard::live::Live::from_conn(&conn).expect("select all rows");
    let entry = live
        .entries
        .iter()
        .find(|e| e.action == decision_guard::rules::Action::Allow)
        .cloned();
    if let Some(e) = entry {
        // the hot-path UPDATE: bump the first enabled allow row
        decision_guard::live::bump(&conn, e.id).expect("bump");
    }
    start.elapsed().as_secs_f64() * 1000.0
}

#[test]
fn hot_path_p95_within_budget() {
    // Unique temp dir without the `tempfile` crate: env::temp_dir + pid + a counter.
    let base = env::temp_dir().join(format!("dg-live-perf-{}-{}", std::process::id(), std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("create dir");
    let db = base.join("rules.db");

    // Seed a realistic list: one allow glob that matches, one deny that does not.
    {
        let conn = decision_guard::live::open(&db).expect("open");
        decision_guard::live::add(
            &conn,
            "git status*",
            decision_guard::rules::Action::Allow,
            Some("harmless git"),
            None,
            None,
        )
        .expect("add allow");
        decision_guard::live::add(
            &conn,
            "rm -rf*",
            decision_guard::rules::Action::Deny,
            Some("delete"),
            None,
            None,
        )
        .expect("add deny");
    }

    let n = 2000usize;
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        samples.push(one_iteration(&db));
    }
    samples.sort_by(|a, b| a.total_cmp(b));

    let p95_idx = ((n as f64) * 0.95) as usize;
    let p95 = samples[p95_idx.min(n - 1)];
    let p50 = samples[n / 2];
    eprintln!(
        "hot-path latency: P50={p50:.3} ms  P95={p95:.3} ms  max={:.3} ms  (budget P95 ≤ 1.5 ms)",
        samples.last().unwrap()
    );

    assert!(
        p95 <= 1.5,
        "hot path P95 {p95:.3} ms exceeds the 1.5 ms budget"
    );

    let _ = std::fs::remove_dir_all(&base);
}
