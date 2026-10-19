//! JavaScript-compatible primitives. The Rust port must write the same bytes and make the same decisions as the JS it
//! replaces (`JSON.stringify`, `String.prototype.trim`, `Number()`, `toFixed`, `os.homedir()`), so the few places where
//! the Rust standard library behaves differently are collected here instead of being scattered through the modules.

use serde_json::Value;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;

/// The characters JavaScript's `\s` (and `trim()`) treats as white space, written for use inside a regex class.
/// Rust's `\s` differs (it has U+0085 and lacks U+FEFF).
pub const WS: &str = "\\t\\n\\x0B\\x0C\\r \\x{A0}\\x{1680}\\x{2000}-\\x{200A}\\x{2028}\\x{2029}\\x{202F}\\x{205F}\\x{3000}\\x{FEFF}";

pub fn is_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// `s.trim()`.
pub fn trim(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// `s.trim().replace(/\s+/g, " ")`.
pub fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut gap = false;
    for c in trim(s).chars() {
        if is_space(c) {
            gap = true;
        } else {
            if gap {
                out.push(' ');
                gap = false;
            }
            out.push(c);
        }
    }
    out
}

/// `s.length` (UTF-16 code units).
pub fn utf16_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

/// `s.slice(0, n)` by UTF-16 units. shortcut: a surrogate pair straddling the cut is dropped whole instead of leaving a
/// lone surrogate (which cannot be valid UTF-8 anyway).
pub fn slice_utf16(s: &str, n: usize) -> &str {
    let mut used = 0;
    for (i, c) in s.char_indices() {
        used += c.len_utf16();
        if used > n {
            return &s[..i];
        }
    }
    s
}

/// JavaScript truthiness of a JSON value.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// `String(v)`.
pub fn js_string(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => number_to_string(n),
        Value::String(s) => s.clone(),
        Value::Array(a) => a
            .iter()
            .map(|e| {
                if e.is_null() {
                    String::new()
                } else {
                    js_string(e)
                }
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

/// `Number(s)` for a string.
pub fn number_str(s: &str) -> f64 {
    let t = trim(s);
    if t.is_empty() {
        return 0.0;
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0b", 2),
        ("0B", 2),
        ("0o", 8),
        ("0O", 8),
    ] {
        if let Some(digits) = t.strip_prefix(prefix) {
            return if digits.is_empty() {
                f64::NAN
            } else {
                digits
                    .chars()
                    .try_fold(0.0, |acc, c| {
                        c.to_digit(radix)
                            .map(|d| acc * f64::from(radix) + f64::from(d))
                    })
                    .unwrap_or(f64::NAN)
            };
        }
    }
    match t {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    // Rust's parser also accepts "inf", "nan" and "infinity"; JavaScript does not.
    if t.chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-'))
    {
        t.parse().unwrap_or(f64::NAN)
    } else {
        f64::NAN
    }
}

/// `Number(v)`.
pub fn js_number(v: &Value) -> f64 {
    match v {
        Value::Null => 0.0,
        Value::Bool(b) => f64::from(u8::from(*b)),
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::String(s) => number_str(s),
        Value::Array(_) => number_str(&js_string(v)),
        Value::Object(_) => f64::NAN,
    }
}

fn number_to_string(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        i.to_string()
    } else if let Some(u) = n.as_u64() {
        u.to_string()
    } else {
        fmt_number(n.as_f64().unwrap_or(f64::NAN))
    }
}

/// `Number.prototype.toString()` (ECMAScript Number::toString). serde_json and Rust's Display disagree with it for
/// integral floats (`1.0`) and for exponents (`2e-5` where JS prints `0.00002`).
pub fn fmt_number(x: f64) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x == 0.0 {
        return "0".into();
    }
    if x.is_infinite() {
        return if x < 0.0 { "-Infinity" } else { "Infinity" }.into();
    }
    let sign = if x < 0.0 { "-" } else { "" };
    let sci = format!("{:e}", x.abs()); // shortest round-trip digits: "d.ddde-5"
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exp.parse::<i32>().unwrap_or(0) + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let sign_e = if e < 0 { '-' } else { '+' };
        if k == 1 {
            format!("{digits}e{sign_e}{}", e.abs())
        } else {
            format!("{}.{}e{sign_e}{}", &digits[..1], &digits[1..], e.abs())
        }
    };
    format!("{sign}{body}")
}

/// `x.toFixed(2)`. JavaScript rounds an exact tie up (0.125 -> "0.13"), Rust rounds it to even ("0.12").
pub fn to_fixed2(x: f64) -> String {
    if x.is_nan() || x.is_infinite() || x.abs() >= 1e21 {
        return fmt_number(x);
    }
    let a = x.abs();
    let eighths = a * 8.0;
    if eighths.fract() == 0.0 && (eighths as u64) % 2 == 1 {
        let hundredths = (a * 100.0).round() as u64; // exact: a is a multiple of 1/8
        return format!(
            "{}{}.{:02}",
            if x < 0.0 { "-" } else { "" },
            hundredths / 100,
            hundredths % 100
        );
    }
    format!("{:.2}", if x == 0.0 { 0.0 } else { x })
}

/// `JSON.stringify(v)` for a parsed value: insertion-ordered keys, JavaScript number formatting.
pub fn stringify(v: &Value) -> String {
    let mut out = String::new();
    write_json(v, &mut out);
    out
}

fn write_json(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => match n.as_f64() {
            Some(f) if !f.is_finite() => out.push_str("null"),
            _ => out.push_str(&number_to_string(n)),
        },
        Value::String(s) => out.push_str(&serde_json::to_string(s).unwrap_or_default()),
        Value::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(e, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, e)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                write_json(e, out);
            }
            out.push('}');
        }
    }
}

/// A JSON number the way JavaScript would hold it: an integral float becomes an integer.
pub fn num(x: f64) -> Value {
    if x.is_finite() && x.fract() == 0.0 && x.abs() < 9e15 {
        Value::from(x as i64)
    } else {
        serde_json::Number::from_f64(x).map_or(Value::Null, Value::Number)
    }
}

/// `Date.now()`.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

/// `new Date().toISOString()`.
pub fn iso_now() -> String {
    iso_from_ms(now_ms())
}

/// `new Date(ms).toISOString()` for years 0000 through 9999 (the callers clamp; `time` refuses anything wider).
pub fn iso_from_ms(ms: i64) -> String {
    let t = OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .expect("timestamp within years 0000 through 9999");
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond()
    )
}

/// `os.homedir()`: `$HOME` when set and non-empty, otherwise the passwd entry.
#[allow(deprecated)]
pub fn homedir() -> String {
    std::env::home_dir().map_or_else(|| "/".into(), |p| p.to_string_lossy().into_owned())
}

/// `~/.decision-guard`.
pub fn state_dir() -> PathBuf {
    PathBuf::from(homedir()).join(".decision-guard")
}

/// `process.env[key]`.
pub fn env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// The value after `--name` in the arguments, like the scripts' `opt()`. A flag with nothing after it is an error
/// (the JS scripts would carry on with `undefined`).
pub fn opt<'a>(args: &'a [String], name: &str) -> Result<Option<&'a str>, String> {
    match args.iter().position(|a| a == name) {
        None => Ok(None),
        Some(i) => args
            .get(i + 1)
            .map(|v| Some(v.as_str()))
            .ok_or_else(|| format!("{name} needs a value")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_print_like_javascript() {
        for (x, s) in [
            (1.0, "1"),
            (0.9, "0.9"),
            (0.00002, "0.00002"),
            (2e-7, "2e-7"),
            (1.5e-7, "1.5e-7"),
            (123456.789, "123456.789"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (-0.5, "-0.5"),
            (0.97, "0.97"),
        ] {
            assert_eq!(fmt_number(x), s);
        }
    }

    #[test]
    fn to_fixed_rounds_ties_up() {
        assert_eq!(to_fixed2(0.125), "0.13");
        assert_eq!(to_fixed2(0.9), "0.90");
        assert_eq!(to_fixed2(0.995), "0.99");
        assert_eq!(to_fixed2(1.0), "1.00");
    }

    #[test]
    fn number_conversion_follows_javascript() {
        assert_eq!(number_str(" 5000 "), 5000.0);
        assert!(number_str("abc").is_nan());
        assert!(number_str("inf").is_nan());
        assert_eq!(number_str(""), 0.0);
        assert_eq!(number_str("0x10"), 16.0);
    }

    #[test]
    fn iso_timestamp_shape() {
        let t = iso_now();
        assert_eq!(t.len(), 24);
        assert!(t.ends_with('Z') && &t[10..11] == "T");
    }

    #[test]
    fn normalize_collapses_js_whitespace() {
        assert_eq!(normalize("  git \t status\u{a0} -s \n"), "git status -s");
    }
}
