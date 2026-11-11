//! `mask-secrets install`: register this binary as a PreToolUse hook for Claude Code and Codex.
//!
//! Idempotent (re-running updates the existing entry in place), keeps every other hook and
//! setting, preserves key order and indentation, and backs up each file it changes.

use regex::Regex;
use serde_json::{Map, Value, json};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MARKER: &str = "mask-secrets";
const EVENT: &str = "PreToolUse";

struct Agent {
    name: &'static str,
    matcher: &'static str,
    default_dir: &'static str,
    env: &'static str,
    file: &'static str,
}

const AGENTS: [Agent; 2] = [
    Agent {
        name: "claude",
        matcher: "Read|Grep|Bash|mcp__.*",
        default_dir: ".claude",
        env: "CLAUDE_CONFIG_DIR",
        file: "settings.json",
    },
    Agent {
        name: "codex",
        matcher: "^(Bash|Read|Grep|exec_command|shell_command|shell)$",
        default_dir: ".codex",
        env: "CODEX_HOME",
        file: "hooks.json",
    },
];

pub const USAGE: &str = "\
mask-secrets: PreToolUse hook that keeps .env / .properties values out of agent conversations.

USAGE
  mask-secrets                      run as a hook (reads one PreToolUse JSON payload on stdin)
  mask-secrets install [options]    register this binary with Claude Code and Codex
  mask-secrets uninstall [options]  remove it again (same as install --uninstall)
  mask-secrets --version

INSTALL OPTIONS
  --claude      only Claude Code (default: every agent whose config dir exists)
  --codex       only Codex
  --uninstall   remove the hook again
  --dry-run     show what would change without writing
";

fn home() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn config_dir(agent: &Agent) -> Option<PathBuf> {
    match env::var_os(agent.env).filter(|v| !v.is_empty()) {
        Some(dir) => Some(PathBuf::from(dir)),
        None => home().map(|h| h.join(agent.default_dir)),
    }
}

fn hook_entry(agent: &Agent, command: &str) -> Value {
    json!({
        "matcher": agent.matcher,
        "hooks": [{
            "type": "command",
            "command": command,
            "timeout": 5,
            "statusMessage": "Masking secrets...",
        }],
    })
}

fn is_ours(group: &Value) -> bool {
    group["hooks"].as_array().is_some_and(|hs| {
        hs.iter()
            .any(|h| h["command"].as_str().is_some_and(|c| c.contains(MARKER)))
    })
}

fn detect_indent(text: &str) -> String {
    Regex::new(r#"(?m)^( +|\t)""#)
        .unwrap()
        .captures(text)
        .map_or("  ".into(), |c| c[1].to_string())
}

fn to_pretty(value: &Value, indent: &str) -> String {
    use serde::Serialize;
    let mut buf = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(indent.as_bytes());
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, fmt);
    value
        .serialize(&mut ser)
        .expect("serializing a Value cannot fail");
    let mut text = String::from_utf8(buf).expect("serde_json emits UTF-8");
    text.push('\n');
    text
}

fn write_if_changed(
    path: &Path,
    new: &str,
    old: &str,
    dry_run: bool,
    label: &str,
) -> Result<(), String> {
    if new == old {
        println!("  {label}: already up to date");
        return Ok(());
    }
    if dry_run {
        println!("  {label}: would update {}", path.display());
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    let mut note = String::new();
    if path.exists() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let backup = path.with_file_name(format!(
            "{}.bak.{stamp}",
            path.file_name().unwrap().to_string_lossy()
        ));
        fs::copy(path, &backup).map_err(|e| format!("backup {}: {e}", backup.display()))?;
        note = format!(
            " (backup: {})",
            backup.file_name().unwrap().to_string_lossy()
        );
    }
    fs::write(path, new).map_err(|e| format!("{}: {e}", path.display()))?;
    println!("  {label}: updated {}{note}", path.display());
    Ok(())
}

fn update_hooks_json(
    agent: &Agent,
    dir: &Path,
    command: &str,
    uninstall: bool,
    dry_run: bool,
) -> Result<(), String> {
    let path = dir.join(agent.file);
    let old = fs::read_to_string(&path).unwrap_or_default();
    let mut data: Value = if old.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        serde_json::from_str(&old).map_err(|e| {
            format!(
                "{} is not valid JSON ({e}); fix it and re-run",
                path.display()
            )
        })?
    };
    let indent = if old.is_empty() {
        "  ".to_string()
    } else {
        detect_indent(&old)
    };
    let root = data
        .as_object_mut()
        .ok_or_else(|| format!("{} is not a JSON object", path.display()))?;
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| format!("{}: \"hooks\" is not an object", path.display()))?;

    let existing: Vec<Value> = hooks
        .get(EVENT)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut groups: Vec<Value> = Vec::new();
    let mut placed = false;
    for group in existing {
        if !is_ours(&group) {
            groups.push(group);
        } else if !uninstall && !placed {
            groups.push(hook_entry(agent, command)); // replace in place, keep position
            placed = true;
        }
    }
    if !uninstall && !placed {
        groups.push(hook_entry(agent, command));
    }
    if groups.is_empty() {
        hooks.remove(EVENT);
    } else {
        hooks.insert(EVENT.into(), Value::Array(groups));
    }
    if hooks.is_empty() {
        root.remove("hooks");
    }
    write_if_changed(&path, &to_pretty(&data, &indent), &old, dry_run, agent.name)
}

/// Codex ignores hooks.json unless `[features] hooks = true` is set in config.toml.
fn enable_codex_hooks_feature(dir: &Path, dry_run: bool) -> Result<(), String> {
    let path = dir.join("config.toml");
    let old = fs::read_to_string(&path).unwrap_or_default();
    let section = Regex::new(r"(?m)^\[features\][ \t]*\n").unwrap();
    let new = if let Some(m) = section.find(&old) {
        let rest = &old[m.end()..];
        let body_len = Regex::new(r"(?m)^\[")
            .unwrap()
            .find(rest)
            .map_or(rest.len(), |n| n.start());
        let body = &rest[..body_len];
        if Regex::new(r"(?m)^hooks[ \t]*=[ \t]*true\b")
            .unwrap()
            .is_match(body)
        {
            println!("  codex: config.toml already has features.hooks = true");
            return Ok(());
        }
        let hooks_line = Regex::new(r"(?m)^hooks[ \t]*=.*$").unwrap();
        let body = if hooks_line.is_match(body) {
            hooks_line.replace(body, "hooks = true").into_owned()
        } else {
            format!("hooks = true\n{body}")
        };
        format!("{}{}{}", &old[..m.end()], body, &rest[body_len..])
    } else {
        let sep = if old.is_empty() || old.ends_with("\n\n") {
            ""
        } else {
            "\n"
        };
        format!("{old}{sep}[features]\nhooks = true\n")
    };
    write_if_changed(&path, &new, &old, dry_run, "codex config.toml")
}

/// The command agents will run: this very binary, by absolute path.
fn hook_command() -> Result<String, String> {
    let exe = env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|e| format!("cannot locate this executable: {e}"))?;
    let mut exe = exe
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_string();
    if cfg!(windows) {
        exe = exe.replace('\\', "/");
    }
    Ok(format!("\"{exe}\""))
}

pub fn run(args: &[String]) -> Result<(), String> {
    let (mut only, mut uninstall, mut dry_run) = (Vec::new(), false, false);
    for a in args {
        match a.as_str() {
            "--claude" => only.push("claude"),
            "--codex" => only.push("codex"),
            "--uninstall" => uninstall = true,
            "--dry-run" => dry_run = true,
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(());
            }
            other => return Err(format!("unknown option {other}\n\n{USAGE}")),
        }
    }
    let targets: Vec<&Agent> = if only.is_empty() {
        AGENTS
            .iter()
            .filter(|a| config_dir(a).is_some_and(|d| d.is_dir()))
            .collect()
    } else {
        AGENTS.iter().filter(|a| only.contains(&a.name)).collect()
    };
    if targets.is_empty() {
        return Err(
            "neither ~/.claude nor ~/.codex found; pass --claude or --codex to create one".into(),
        );
    }
    let command = hook_command()?;
    println!(
        "{} hook {command}",
        if uninstall { "Removing" } else { "Installing" }
    );
    for agent in targets {
        let dir = config_dir(agent).ok_or("cannot find the home directory")?;
        update_hooks_json(agent, &dir, &command, uninstall, dry_run)?;
        if agent.name == "codex" && !uninstall {
            enable_codex_hooks_feature(&dir, dry_run)?;
        }
    }
    if !dry_run {
        println!("Restart running sessions to load the hook.");
        if !uninstall {
            println!("Codex may ask you to review/trust the new hook (/hooks) on next start.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = env::temp_dir().join(format!("ms-install-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn commands(dir: &Path) -> Vec<String> {
        let v: Value =
            serde_json::from_str(&fs::read_to_string(dir.join("settings.json")).unwrap()).unwrap();
        v["hooks"][EVENT]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["hooks"][0]["command"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn install_is_idempotent_and_keeps_other_hooks_and_formatting() {
        let d = tmp("idem");
        let original = "{\n    \"theme\": \"dark\",\n    \"hooks\": {\n        \"PreToolUse\": [\n            {\"hooks\": [{\"type\": \"command\", \"command\": \"other\"}]}\n        ]\n    }\n}\n";
        fs::write(d.join("settings.json"), original).unwrap();
        update_hooks_json(&AGENTS[0], &d, "\"/bin/mask-secrets\"", false, false).unwrap();
        let first = fs::read_to_string(d.join("settings.json")).unwrap();
        assert!(
            first.starts_with("{\n    \"theme\": \"dark\""),
            "indent and key order kept: {first}"
        );
        assert_eq!(commands(&d), ["other", "\"/bin/mask-secrets\""]);
        update_hooks_json(&AGENTS[0], &d, "\"/bin/mask-secrets\"", false, false).unwrap();
        assert_eq!(
            fs::read_to_string(d.join("settings.json")).unwrap(),
            first,
            "second run changes nothing"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn reinstall_replaces_in_place_and_uninstall_removes_only_ours() {
        let d = tmp("replace");
        let start = json!({"hooks": {"PreToolUse": [
            {"hooks": [{"type": "command", "command": "python3 -I \"/x/mask-secrets.py\""}]},
            {"hooks": [{"type": "command", "command": "after"}]},
        ]}});
        fs::write(d.join("settings.json"), start.to_string()).unwrap();
        update_hooks_json(&AGENTS[0], &d, "\"/new/mask-secrets\"", false, false).unwrap();
        assert_eq!(
            commands(&d),
            ["\"/new/mask-secrets\"", "after"],
            "replaced where it was"
        );
        update_hooks_json(&AGENTS[0], &d, "\"/new/mask-secrets\"", true, false).unwrap();
        assert_eq!(commands(&d), ["after"]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn uninstall_leaves_no_empty_hooks_object_and_invalid_json_is_refused() {
        let d = tmp("empty");
        update_hooks_json(&AGENTS[1], &d, "\"/b/mask-secrets\"", false, false).unwrap();
        update_hooks_json(&AGENTS[1], &d, "\"/b/mask-secrets\"", true, false).unwrap();
        let v: Value =
            serde_json::from_str(&fs::read_to_string(d.join("hooks.json")).unwrap()).unwrap();
        assert!(v.get("hooks").is_none(), "{v}");
        fs::write(d.join("settings.json"), "{bad").unwrap();
        assert!(update_hooks_json(&AGENTS[0], &d, "\"/b/mask-secrets\"", false, false).is_err());
        assert_eq!(fs::read_to_string(d.join("settings.json")).unwrap(), "{bad");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn codex_feature_flag_is_added_or_fixed() {
        let d = tmp("toml");
        fs::write(
            d.join("config.toml"),
            "model = \"x\"\n\n[features]\napps = false\nhooks = false\n\n[other]\na = 1\n",
        )
        .unwrap();
        enable_codex_hooks_feature(&d, false).unwrap();
        assert_eq!(
            fs::read_to_string(d.join("config.toml")).unwrap(),
            "model = \"x\"\n\n[features]\napps = false\nhooks = true\n\n[other]\na = 1\n"
        );
        fs::write(d.join("config.toml"), "[projects.\"/x\"]\nt = 1\n").unwrap();
        enable_codex_hooks_feature(&d, false).unwrap();
        assert_eq!(
            fs::read_to_string(d.join("config.toml")).unwrap(),
            "[projects.\"/x\"]\nt = 1\n\n[features]\nhooks = true\n"
        );
        let _ = fs::remove_dir_all(&d);
    }
}
