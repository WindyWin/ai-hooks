//! Event log behind the block / mask counters.
//!
//! The hook appends one JSON line for every call it blocks (deny) or masks (rewrites so the command
//! prints masked output). Calls that pass untouched are not recorded, so ordinary tool use costs nothing.
//! A line holds when, which agent, which tool, what happened and a short detail (the secret file's base
//! name, or the command's first word). It never holds file content, values or a full command line.
//!
//! The log lives in `$MASK_SECRETS_LOG`, else `$XDG_STATE_HOME/mask-secrets/events.jsonl`
//! (`~/.local/state/...`; `%LOCALAPPDATA%\mask-secrets\events.jsonl` on Windows).
//! `MASK_SECRETS_LOG=off` turns logging off. The Python hook writes the same format to the same place.

use regex::Regex;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const ENV: &str = "MASK_SECRETS_LOG";
const SHELL_TOOLS: [&str; 4] = ["Bash", "exec_command", "shell_command", "shell"];
/// Words that open a command line without being what the call was about.
const PREFIX_WORDS: [&str; 8] = ["cd", "export", "set", "true", "false", ":", "source", "."];
const HOUR: u64 = 3600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Blocked,
    Masked,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Blocked => "blocked",
            Action::Masked => "masked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub ts: u64,
    pub agent: String,
    pub tool: String,
    pub action: Action,
    pub detail: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Where the log is written; `None` when logging is switched off.
pub fn log_path() -> Option<PathBuf> {
    match env::var(ENV) {
        Ok(v) if matches!(v.as_str(), "off" | "0" | "false") => return None,
        Ok(v) if !v.is_empty() => return Some(PathBuf::from(v)),
        _ => {}
    }
    let base = if cfg!(windows) {
        env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        env::var_os("XDG_STATE_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("state"))
            })
    }
    .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))?;
    Some(base.join("mask-secrets").join("events.jsonl"))
}

fn base_name(path: &str) -> String {
    path.trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .to_string()
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// The word a shell command is "about": its first command word, skipping `cd x &&`, `FOO=1` and the like.
fn command_head(command: &str) -> String {
    let mut first = None;
    for segment in Regex::new(r"&&|\|\||[;|&\n]").unwrap().split(command) {
        let word = segment
            .split_whitespace()
            .find(|w| !(w.contains('=') && !w.starts_with(['/', '.', '"', '\''])));
        let Some(word) = word else { continue };
        let word = base_name(word.trim_matches(['"', '\'', '(', '{']));
        if word.is_empty() {
            continue;
        }
        if !PREFIX_WORDS.contains(&word.as_str()) {
            return truncate(&word, 32);
        }
        first.get_or_insert(word);
    }
    truncate(&first.unwrap_or_default(), 32)
}

/// Turn a hook payload and the hook's own answer into an event, or `None` when nothing was blocked or masked.
pub fn classify(raw: &str, output: &str) -> Option<Event> {
    let out: Value = serde_json::from_str(output).ok()?;
    let hook = out.get("hookSpecificOutput")?;
    let action = if hook.get("permissionDecision").and_then(Value::as_str) == Some("deny") {
        Action::Blocked
    } else if hook.get("updatedInput").is_some() {
        Action::Masked
    } else {
        return None;
    };
    let data: Value = serde_json::from_str(raw).ok()?;
    let tool = data.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let input = data.get("tool_input").unwrap_or(&Value::Null);
    let text = |key: &str| input.get(key).and_then(Value::as_str);
    let detail = if tool == "Read" {
        base_name(text("file_path").unwrap_or(""))
    } else if tool == "Grep" {
        base_name(text("path").unwrap_or("."))
    } else if SHELL_TOOLS.contains(&tool) {
        command_head(text("command").or_else(|| text("cmd")).unwrap_or(""))
    } else {
        String::new()
    };
    Some(Event {
        ts: now(),
        agent: if data.get("turn_id").is_some() { "codex" } else { "claude" }.into(),
        tool: truncate(tool, 48),
        action,
        detail: truncate(&detail, 64),
    })
}

fn to_line(e: &Event) -> String {
    let mut line = json!({
        "ts": e.ts, "agent": e.agent, "tool": e.tool, "action": e.action.as_str(), "detail": e.detail,
    })
    .to_string();
    line.push('\n');
    line
}

fn append(path: &Path, event: &Event) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    // One write call on an O_APPEND handle: concurrent hooks do not interleave their lines.
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?
        .write_all(to_line(event).as_bytes())
}

/// Record the outcome of one hook call. Never fails and never prints: the hook's answer must not change.
pub fn record(raw: &str, output: &str) {
    let _ = std::panic::catch_unwind(|| {
        if let (Some(path), Some(event)) = (log_path(), classify(raw, output)) {
            let _ = append(&path, &event);
        }
    });
}

fn parse_line(line: &str) -> Option<Event> {
    let v: Value = serde_json::from_str(line).ok()?;
    let text = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    Some(Event {
        ts: v.get("ts")?.as_u64()?,
        agent: text("agent"),
        tool: text("tool"),
        action: match v.get("action")?.as_str()? {
            "blocked" => Action::Blocked,
            "masked" => Action::Masked,
            _ => return None,
        },
        detail: text("detail"),
    })
}

/// Every readable event in the log, oldest first. A missing file is an empty log; damaged lines are skipped.
pub fn read_events(path: &Path) -> Vec<Event> {
    let bytes = fs::read(path).unwrap_or_default();
    String::from_utf8_lossy(&bytes)
        .lines()
        .filter_map(parse_line)
        .collect()
}

pub fn clear(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub blocked: u64,
    pub masked: u64,
}

impl Counts {
    pub fn total(&self) -> u64 {
        self.blocked + self.masked
    }
    fn add(&mut self, action: Action) {
        match action {
            Action::Blocked => self.blocked += 1,
            Action::Masked => self.masked += 1,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub all: Counts,
    pub last_24h: Counts,
    pub last_7d: Counts,
    pub by_agent: BTreeMap<String, Counts>,
    pub by_tool: BTreeMap<String, Counts>,
    /// The last 24 hours, one bucket per hour, oldest first (the last bucket is the current hour).
    pub hourly: [Counts; 24],
}

pub fn summarize(events: &[Event], now: u64) -> Summary {
    let mut s = Summary::default();
    for e in events {
        s.all.add(e.action);
        s.by_agent.entry(e.agent.clone()).or_default().add(e.action);
        s.by_tool.entry(e.tool.clone()).or_default().add(e.action);
        let age = now.saturating_sub(e.ts);
        if age < 7 * 24 * HOUR {
            s.last_7d.add(e.action);
        }
        if age < 24 * HOUR {
            s.last_24h.add(e.action);
            s.hourly[23 - (age / HOUR) as usize].add(e.action);
        }
    }
    s
}

/// "5s", "3m", "2h", "4d".
pub fn age(ts: u64, now: u64) -> String {
    let secs = now.saturating_sub(ts);
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86399 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86400),
    }
}

fn pad(counts: Counts) -> String {
    format!(
        "{:>7} blocked {:>7} masked",
        counts.blocked, counts.masked
    )
}

/// Plain-text report for `mask-secrets stats`.
pub fn report(events: &[Event], now: u64, path: Option<&Path>) -> String {
    let s = summarize(events, now);
    let mut out = String::new();
    out.push_str(&match path {
        Some(p) => format!("Log: {}\n\n", p.display()),
        None => "Logging is off (MASK_SECRETS_LOG=off)\n\n".into(),
    });
    out.push_str(&format!("all time     {}\n", pad(s.all)));
    out.push_str(&format!("last 7 days  {}\n", pad(s.last_7d)));
    out.push_str(&format!("last 24 h    {}\n", pad(s.last_24h)));
    for (title, map) in [("agent", &s.by_agent), ("tool", &s.by_tool)] {
        if map.is_empty() {
            continue;
        }
        out.push_str(&format!("\nby {title}\n"));
        let mut rows: Vec<_> = map.iter().collect();
        rows.sort_by(|a, b| b.1.total().cmp(&a.1.total()).then(a.0.cmp(b.0)));
        for (name, counts) in rows {
            out.push_str(&format!("  {name:<16}{}\n", pad(*counts)));
        }
    }
    if !events.is_empty() {
        out.push_str("\nrecent\n");
        for e in events.iter().rev().take(10) {
            out.push_str(&format!(
                "  {:>4} ago  {:<7} {:<8} {:<14} {}\n",
                age(e.ts, now),
                e.action.as_str(),
                e.agent,
                e.tool,
                e.detail
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny_out() -> String {
        json!({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": "Blocked: KEY=SECRETVALUE"}})
        .to_string()
    }

    fn rewrite_out(codex: bool) -> String {
        let mut hook = json!({"hookEventName": "PreToolUse", "updatedInput": {"command": "rg --pre x y"}});
        if codex {
            hook["permissionDecision"] = json!("allow");
        }
        json!({ "hookSpecificOutput": hook }).to_string()
    }

    #[test]
    fn classifies_deny_and_rewrite_without_leaking_values() {
        let read = json!({"tool_name": "Read", "tool_input": {"file_path": "/srv/app/.env"}}).to_string();
        let e = classify(&read, &deny_out()).unwrap();
        assert_eq!((e.action, e.agent.as_str(), e.tool.as_str(), e.detail.as_str()), (Action::Blocked, "claude", "Read", ".env"));
        assert!(!to_line(&e).contains("SECRETVALUE"));

        let bash = json!({"tool_name": "Bash", "turn_id": "t1",
            "tool_input": {"command": "cd /x && FOO=1 /usr/bin/rg token --hidden"}})
        .to_string();
        let e = classify(&bash, &rewrite_out(true)).unwrap();
        assert_eq!((e.action, e.agent.as_str(), e.detail.as_str()), (Action::Masked, "codex", "rg"));
        assert!(!to_line(&e).contains("token"), "arguments are not logged");
    }

    #[test]
    fn plain_allow_or_garbage_is_not_an_event() {
        let raw = json!({"tool_name": "Bash", "tool_input": {"command": "ls"}}).to_string();
        let allow = json!({"hookSpecificOutput": {"permissionDecision": "allow"}}).to_string();
        assert!(classify(&raw, &allow).is_none());
        assert!(classify(&raw, "not json").is_none());
        assert!(classify("not json", &deny_out()).is_none());
    }

    #[test]
    fn command_head_skips_prefixes() {
        assert_eq!(command_head("cd /x && cat .env"), "cat");
        assert_eq!(command_head("API_KEY=abc node app.js"), "node");
        assert_eq!(command_head("sudo cat a"), "sudo");
        assert_eq!(command_head("cd /x"), "cd");
        assert_eq!(command_head(""), "");
    }

    #[test]
    fn summary_buckets_by_window() {
        let now = 1_000_000;
        let ev = |ago: u64, action| Event { ts: now - ago, agent: "claude".into(), tool: "Bash".into(), action, detail: String::new() };
        let events = [
            ev(10, Action::Blocked),
            ev(2 * HOUR + 5, Action::Masked),
            ev(30 * HOUR, Action::Blocked),
            ev(10 * 24 * HOUR, Action::Masked),
        ];
        let s = summarize(&events, now);
        assert_eq!(s.all, Counts { blocked: 2, masked: 2 });
        assert_eq!(s.last_7d, Counts { blocked: 2, masked: 1 });
        assert_eq!(s.last_24h, Counts { blocked: 1, masked: 1 });
        assert_eq!(s.hourly[23], Counts { blocked: 1, masked: 0 });
        assert_eq!(s.hourly[21], Counts { blocked: 0, masked: 1 });
        assert_eq!(age(now - 125, now), "2m");
    }

    #[test]
    fn append_read_and_clear_round_trip() {
        let path = env::temp_dir().join(format!("ms-stats-{}.jsonl", std::process::id()));
        let _ = fs::remove_file(&path);
        let e = Event { ts: 5, agent: "codex".into(), tool: "Read".into(), action: Action::Blocked, detail: ".env".into() };
        append(&path, &e).unwrap();
        append(&path, &e).unwrap();
        fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"{broken\n").unwrap();
        assert_eq!(read_events(&path), [e.clone(), e]);
        clear(&path).unwrap();
        assert!(read_events(&path).is_empty());
        clear(&path).unwrap(); // already gone is fine
    }
}
