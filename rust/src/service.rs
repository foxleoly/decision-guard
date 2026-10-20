//! `decision-guard service [<name>] [--config path]`: lists the decision services config.json names under
//! "services" and switches which one "active" points at. With no name it only prints and writes nothing.
//!
//! Resolution order, highest first: `DECISION_GUARD_BASE_URL`, config.json's "active" entry, config.json's top-level
//! `base_url`, an OpenAI key from `OPENAI_API_KEY` or ~/.decision-guard/key.

use crate::jsc::opt;
use crate::judge::{config_path, read_json, resolve_service};
use serde_json::{json, Map, Value};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Runs the subcommand; returns the process exit code. Prints to stdout, errors to stderr.
pub fn main(args: &[String]) -> i32 {
    match run(args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            2
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let config_flag = args.iter().position(|a| a == "--config");
    let path = opt(args, "--config")?.map_or_else(config_path, PathBuf::from);
    // The first bare word that is not the value of --config is the service to activate.
    let wanted = args
        .iter()
        .enumerate()
        .find(|(i, a)| !a.starts_with("--") && Some(*i) != config_flag.map(|p| p + 1))
        .map(|(_, a)| a.as_str());
    let file = read_json(&path);
    match wanted {
        Some(name) => activate(&path, &file, name),
        None => {
            show(&path, &file);
            Ok(())
        }
    }
}

/// Prints what answers now and what else is configured. Never touches the network.
fn show(path: &Path, file: &Value) {
    let env = |k: &str| std::env::var(k).ok();
    match resolve_service(&env, file) {
        Ok(svc) => println!(
            "active: {}\n        {}  model {}",
            svc.name, svc.url, svc.model
        ),
        Err(e) => println!("active: none ({e})"),
    }
    if env("DECISION_GUARD_BASE_URL").is_some_and(|v| !v.is_empty()) {
        println!("note: DECISION_GUARD_BASE_URL is set and wins over config.json");
    }
    let names = services(file);
    if names.is_empty() {
        println!(
            "\nno services in {} (add a \"services\" object)",
            path.display()
        );
        return;
    }
    let active = file.get("active").and_then(Value::as_str);
    println!("\nservices in {}:", path.display());
    for (name, v) in names {
        let url = v.get("base_url").and_then(Value::as_str).unwrap_or("-");
        let model = v.get("model").and_then(Value::as_str).unwrap_or("-");
        let mark = if Some(name.as_str()) == active {
            "  (active)"
        } else {
            ""
        };
        println!("  {name:<16} {model:<28} {url}{mark}");
    }
}

/// The `services` object's name -> object entries, in file order.
fn services(file: &Value) -> Vec<(String, Value)> {
    file.get("services")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter(|(_, v)| v.is_object())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// Points "active" at a name that exists under "services", keeping every other key (api_key, allow, ...).
fn activate(path: &Path, file: &Value, name: &str) -> Result<(), String> {
    let known = services(file);
    if !known.iter().any(|(k, _)| k == name) {
        let list = known
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(if list.is_empty() {
            format!(
                "no services in {} (add a \"services\" object first)",
                path.display()
            )
        } else {
            format!("unknown service {name}; configured: {list}")
        });
    }
    let mut map: Map<String, Value> = file.as_object().cloned().unwrap_or_default();
    map.insert("active".into(), json!(name));
    write_config(path, &map).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    println!("active: {name}");
    Ok(())
}

/// Rewrites config.json: temp file in the same directory, then rename (atomic), mode 600 like write_rules.
fn write_config(path: &Path, map: &Map<String, Value>) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let written = (|| {
        let mut f = crate::fsx::create_private(&tmp)?;
        crate::fsx::restrict(&tmp)?;
        f.write_all(serde_json::to_string_pretty(&Value::Object(map.clone()))?.as_bytes())?;
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &Path) -> PathBuf {
        dir.join("config.json")
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dg-service-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn switching_writes_active_and_keeps_every_other_key_at_mode_600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp("switch");
        let path = config(&dir);
        std::fs::write(
            &path,
            r#"{"services":{"jev":{"base_url":"http://127.0.0.1:11435/v1/systemone","model":"laya:latest"},
                          "pplx":{"base_url":"http://127.0.0.1:8092/v1/systemone","model":"pplx-decider-v1.1-27b"}},
                "api_key":"secret","ask_p":0.3}"#,
        )
        .unwrap();
        run(&["pplx".into(), "--config".into(), path.display().to_string()]).unwrap();
        let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["active"], json!("pplx"));
        assert_eq!(saved["api_key"], json!("secret"));
        assert_eq!(saved["ask_p"], json!(0.3));
        assert_eq!(saved["services"]["jev"]["model"], json!("laya:latest"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_or_missing_name_is_refused_and_nothing_is_written() {
        let dir = temp("refuse");
        let path = config(&dir);
        let before = r#"{"services":{"jev":{"base_url":"http://127.0.0.1:11435/v1/systemone"}}}"#;
        std::fs::write(&path, before).unwrap();
        let err = run(&["nope".into(), "--config".into(), path.display().to_string()]).unwrap_err();
        assert!(err.contains("unknown service nope"), "{err}");
        assert!(err.contains("jev"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        let empty = temp("empty");
        let err = run(&[
            "x".into(),
            "--config".into(),
            config(&empty).display().to_string(),
        ])
        .unwrap_err();
        assert!(err.contains("no services in"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&empty);
    }
}
