//! Helpers shared by the integration tests: a private HOME per test, the real `hook` binary, a fake model server.

#![allow(dead_code)] // each test crate uses a different subset

use parking_lot::Mutex;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub type Seen = Arc<Mutex<Vec<(Option<String>, Value)>>>;

pub fn home() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "dg-rs-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub struct Run {
    pub stdout: Option<Value>,
    pub stderr: String,
}

pub fn hook(home: &Path, agent: &str, payload: &str, env: &[(&str, &str)]) -> Run {
    let mut child = Command::new(env!("CARGO_BIN_EXE_decision-guard"))
        .args(["hook", agent])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "hook must always exit 0");
    let stdout = String::from_utf8(out.stdout).unwrap();
    Run {
        stdout: (!stdout.trim().is_empty()).then(|| serde_json::from_str(&stdout).unwrap()),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

pub fn bash(command: &str) -> String {
    json!({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": "/work"}).to_string()
}

pub fn db(home: &Path) -> Connection {
    Connection::open(home.join(".decision-guard/decisions.db")).unwrap()
}

/// A throwaway System One server: records every request body and answers with `answer(body)`.
pub fn serve(answer: impl Fn(&Value) -> Value + Send + 'static) -> (String, Seen) {
    serve_raw(move |body| (200, answer(body).to_string()))
}

/// Like `serve`, but the reply is a raw status code and body.
pub fn serve_raw(reply: impl Fn(&Value) -> (u16, String) + Send + 'static) -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/v1/systemone", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let (head_end, length) = loop {
                let n = stream.read(&mut chunk).unwrap();
                buf.extend_from_slice(&chunk[..n]);
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                    let length = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .map_or(0, |v| v.trim().parse::<usize>().unwrap());
                    break (i + 4, length);
                }
            };
            while buf.len() < head_end + length {
                let n = stream.read(&mut chunk).unwrap();
                buf.extend_from_slice(&chunk[..n]);
            }
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let auth = head.lines().find_map(|l| {
                l.to_lowercase()
                    .strip_prefix("authorization:")
                    .map(|v| v.trim().to_string())
            });
            let body: Value = serde_json::from_slice(&buf[head_end..head_end + length]).unwrap();
            let (status, reply) = reply(&body);
            log.lock().push((auth, body));
            write!(stream, "HTTP/1.1 {status} Reply\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}", reply.len()).unwrap();
        }
    });
    (url, seen)
}

/// Like `serve`, but speaks HTTP/1.1 keep-alive (a connection stays open for many requests) and counts the
/// accepted TCP connections.
pub fn serve_keep_alive(
    answer: impl Fn(&Value) -> Value + Send + Sync + 'static,
) -> (String, Seen, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/v1/systemone", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let accepted = Arc::new(AtomicUsize::new(0));
    let (log, count, answer) = (seen.clone(), accepted.clone(), Arc::new(answer));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let (log, answer) = (log.clone(), answer.clone());
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let head_end = loop {
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => return, // the client closed the connection
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    let length = head
                        .to_lowercase()
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    while buf.len() < head_end + length {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let auth = head.lines().find_map(|l| {
                        l.to_lowercase()
                            .strip_prefix("authorization:")
                            .map(|v| v.trim().to_string())
                    });
                    let body: Value =
                        serde_json::from_slice(&buf[head_end..head_end + length]).unwrap();
                    buf.drain(..head_end + length);
                    let reply = answer(&body).to_string();
                    log.lock().push((auth, body));
                    write!(stream, "HTTP/1.1 200 Reply\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{reply}", reply.len()).unwrap();
                }
            });
        }
    });
    (url, seen, accepted)
}

/// A server that accepts connections and never answers them.
pub fn hang() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/v1/systemone", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut held = Vec::new(); // an open connection with no reply, until the test process exits
        for stream in listener.incoming() {
            held.push(stream);
        }
    });
    url
}

pub fn risk(p: f64) -> Value {
    json!({"type": "choice", "choice": if p >= 0.5 { "destructive" } else { "safe" }, "probabilities": {"safe": 1.0 - p, "risky": 0, "destructive": p}, "confidence": 0.9})
}
