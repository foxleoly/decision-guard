//! Black-box tests of scripts/install.sh on a copy of the skill tree: the real script and adapters, the real binary as the
//! prebuilt artifact, a private HOME. Nothing outside the temp directory is read or written.

mod common;

use common::home;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn triple() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        other => panic!("install.sh has no prebuilt target for {other:?}"),
    }
}

fn sha256(file: &Path) -> String {
    let out = Command::new("sh")
        .arg("-c")
        .arg("if command -v sha256sum >/dev/null; then sha256sum \"$1\"; else shasum -a 256 \"$1\"; fi")
        .arg("sh")
        .arg(file)
        .output()
        .unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

struct Tree {
    scripts: PathBuf,
    dist: PathBuf,
    home: PathBuf,
}

impl Tree {
    /// `<tmp>/skill/{scripts,dist}` and an empty `<tmp>/home`; dist holds the real binary and its SHA256SUMS line.
    fn new() -> Tree {
        let home = home();
        let skill = home.join("skill");
        let scripts = skill.join("scripts");
        let dist = skill.join("dist");
        let real = Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts");
        std::fs::create_dir_all(scripts.join("adapters")).unwrap();
        std::fs::create_dir_all(&dist).unwrap();
        for f in ["install.sh", "adapters/pi.ts", "adapters/opencode.js"] {
            std::fs::copy(real.join(f), scripts.join(f)).unwrap();
        }
        let artifact = dist.join(format!("decision-guard-{}", triple()));
        std::fs::copy(env!("CARGO_BIN_EXE_decision-guard"), &artifact).unwrap();
        std::fs::write(
            dist.join("SHA256SUMS"),
            format!("{}  decision-guard-{}\n", sha256(&artifact), triple()),
        )
        .unwrap();
        let home_dir = home.join("home");
        std::fs::create_dir_all(&home_dir).unwrap();
        Tree {
            scripts,
            dist,
            home: home_dir,
        }
    }

    fn install(&self, args: &[&str], path_prefix: Option<&Path>) -> Output {
        let path = std::env::var("PATH").unwrap();
        let path = path_prefix.map_or(path.clone(), |p| format!("{}:{path}", p.display()));
        Command::new("bash")
            .arg(self.scripts.join("install.sh"))
            .args(args)
            .env_clear()
            .env("PATH", path)
            .env("HOME", &self.home)
            .output()
            .unwrap()
    }

    fn dg(&self) -> PathBuf {
        self.home.join(".decision-guard")
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn files_installs_the_verified_binary_removes_stale_node_copies_and_is_idempotent() {
    let t = Tree::new();
    let dg = t.dg();
    std::fs::create_dir_all(&dg).unwrap();
    for stale in [
        "core.mjs",
        "hook.mjs",
        "web.mjs",
        "web-page.html",
        "archive.mjs",
    ] {
        std::fs::write(dg.join(stale), "old").unwrap();
    }
    std::fs::write(dg.join("key"), "sk-keep\n").unwrap();
    std::fs::write(dg.join("notes.mjs"), "not ours").unwrap();

    let dry = t.install(&["--dry-run", "files"], None);
    assert!(dry.status.success(), "{}", text(&dry.stderr));
    assert!(
        dg.join("core.mjs").exists() && !dg.join("bin").exists(),
        "a dry run changes nothing"
    );
    assert!(
        text(&dry.stdout).contains("[dry-run] rm -f"),
        "{}",
        text(&dry.stdout)
    );

    for run in 1..=2 {
        let out = t.install(&["files"], None);
        assert!(out.status.success(), "run {run}: {}", text(&out.stderr));
    }
    let bin = dg.join("bin/decision-guard");
    assert_eq!(
        sha256(&bin),
        sha256(&t.dist.join(format!("decision-guard-{}", triple())))
    );
    for stale in [
        "core.mjs",
        "hook.mjs",
        "web.mjs",
        "web-page.html",
        "archive.mjs",
    ] {
        assert!(!dg.join(stale).exists(), "{stale} should be gone");
    }
    assert_eq!(
        std::fs::read_to_string(dg.join("key")).unwrap(),
        "sk-keep\n"
    );
    assert!(
        dg.join("notes.mjs").exists(),
        "only the named stale files are removed"
    );
    assert!(dg.join("adapters/pi.ts").exists() && dg.join("adapters/opencode.js").exists());
}

#[test]
fn a_tampered_or_missing_artifact_is_refused_before_anything_is_written() {
    let t = Tree::new();
    let artifact = t.dist.join(format!("decision-guard-{}", triple()));
    let mut bytes = std::fs::read(&artifact).unwrap();
    bytes.push(0);
    std::fs::write(&artifact, bytes).unwrap();
    let out = t.install(&["files"], None);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("checksum mismatch"),
        "{}",
        text(&out.stderr)
    );
    assert!(!t.dg().exists());

    std::fs::remove_file(&artifact).unwrap();
    let out = t.install(&["files"], None);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("no prebuilt binary"),
        "{}",
        text(&out.stderr)
    );
    assert!(!t.dg().exists());
}

#[test]
fn the_archive_job_runs_the_binary_not_node() {
    let t = Tree::new();
    // A stand-in launchctl keeps the test away from the real launchd jobs of the user running it.
    let fake = t.home.join("fakebin");
    std::fs::create_dir_all(&fake).unwrap();
    std::fs::write(fake.join("launchctl"), "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(
        fake.join("launchctl"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();

    let out = t.install(&["archive"], Some(&fake));
    assert!(out.status.success(), "{}", text(&out.stderr));
    let dg = t.dg().display().to_string();
    let scheduled = if cfg!(target_os = "macos") {
        std::fs::read_to_string(
            t.home
                .join("Library/LaunchAgents/com.decision-guard.archive.plist"),
        )
        .unwrap()
    } else {
        text(&out.stdout)
    };
    assert!(
        scheduled.contains(&format!("{dg}/bin/decision-guard")),
        "{scheduled}"
    );
    assert!(
        scheduled.contains("archive") && !scheduled.contains("node") && !scheduled.contains(".mjs"),
        "{scheduled}"
    );
}
