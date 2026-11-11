//! Shared Claude/Codex PreToolUse hook: keep .properties and .env values out of the conversation.
//!
//! PreToolUse cannot rewrite tool output, so when an agent tries to read one of these files the
//! call is denied and, where a single file is involved, the masked content (KEY=****) is returned
//! in the deny reason instead. See the README for what is covered and the known limits.

pub mod bash;
pub mod install;
pub mod mask;
pub mod pathx;
pub mod tokenize;
pub mod walk;

use bash::{GREP_TOOL_ADVICE, analyze_bash, candidates_in_word, search_exposure};
use mask::{MASK, is_secret_file, is_target, render};
use pathx::{glob, has_magic, is_dir, relpath, resolve};
use regex::Regex;
use serde_json::{Map, Value, json};
use std::panic::{AssertUnwindSafe, catch_unwind};
use walk::Budget;

const MAX_PREVIEW_FILES: usize = 5;
const SHELL_TOOLS: [&str; 4] = ["Bash", "exec_command", "shell_command", "shell"];

type Evaluation = (Vec<String>, Vec<String>, String);
/// The Python exception name the original hook would have raised (only used in the fail-closed message).
type Failure = &'static str;

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

fn get<'a>(inp: &'a Value, key: &str) -> Result<Option<&'a Value>, Failure> {
    inp.as_object().map(|o| o.get(key)).ok_or("AttributeError")
}

/// `inp.get(key) or default`, requiring a string when set.
fn get_str(inp: &Value, key: &str) -> Result<Option<String>, Failure> {
    match get(inp, key)? {
        v if !truthy(v) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        _ => Err("TypeError"),
    }
}

fn iter_strings<'a>(v: &'a Value, depth: usize, out: &mut Vec<&'a str>) {
    if depth > 6 {
        return;
    }
    match v {
        Value::String(s) => out.push(s),
        Value::Object(o) => o.values().for_each(|x| iter_strings(x, depth + 1, out)),
        Value::Array(a) => a.iter().for_each(|x| iter_strings(x, depth + 1, out)),
        _ => {}
    }
}

fn dedup(v: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    v.into_iter().filter(|x| seen.insert(x.clone())).collect()
}

fn expand(token: &str, cwd: &str) -> Vec<String> {
    let full = resolve(token, cwd);
    let paths = if has_magic(&full) {
        glob(&full)
    } else {
        vec![full]
    };
    paths.into_iter().filter(|p| is_secret_file(p)).collect()
}

fn grep_tool_targets(
    inp: &Value,
    cwd: &str,
    budget: &mut Budget,
) -> Result<(Vec<String>, Vec<String>), Failure> {
    let mut targets = Vec::new();
    for key in ["path", "glob"] {
        if let Some(v) = get_str(inp, key)?
            && is_target(&v)
        {
            targets.extend(expand(&v, cwd));
        }
    }
    let targets = dedup(targets);
    let mut issues = Vec::new();
    let content_mode = get(inp, "output_mode")?.and_then(Value::as_str) == Some("content");
    if targets.is_empty() && content_mode {
        let root = resolve(
            &get_str(inp, "path")?.unwrap_or_else(|| cwd.to_string()),
            cwd,
        );
        if is_dir(&root) {
            let glob_value = get_str(inp, "glob")?.unwrap_or_default();
            let (inc, exc) = if glob_value.is_empty() {
                (vec![], vec![])
            } else if let Some(rest) = glob_value.strip_prefix('!') {
                (vec![], vec![rest.trim_start_matches('!').to_string()])
            } else {
                (vec![glob_value], vec![])
            };
            let narrowed = truthy(get(inp, "type")?);
            if let Some(msg) = search_exposure(
                "content search",
                &[root],
                &inc,
                &exc,
                narrowed,
                cwd,
                budget,
                GREP_TOOL_ADVICE,
            ) {
                issues.push(msg);
            }
        }
    }
    Ok((targets, issues))
}

pub fn evaluate(data: &Value) -> Result<Evaluation, Failure> {
    let obj = data.as_object().ok_or("AttributeError")?;
    let tool = obj.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let empty = Value::Object(Map::new());
    let inp = match obj.get("tool_input") {
        v if truthy(v) => v.unwrap(),
        _ => &empty,
    };
    let mut cwd = match obj.get("cwd") {
        v if !truthy(v) => std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| ".".into()),
        Some(Value::String(s)) => s.clone(),
        _ => return Err("TypeError"),
    };
    // Codex shell calls can run in a directory different from the session cwd.
    if SHELL_TOOLS.contains(&tool) {
        let workdir = match get_str(inp, "workdir")? {
            Some(w) => Some(w),
            None => get_str(inp, "cwd")?,
        };
        if let Some(w) = workdir {
            cwd = resolve(&w, &cwd);
        }
    }
    let mut budget = Budget::new();
    let mut targets: Vec<String> = Vec::new();
    let mut issues: Vec<String> = Vec::new();

    if tool == "Read" {
        if let Some(fp) = get_str(inp, "file_path")? {
            let p = resolve(&fp, &cwd);
            if is_secret_file(&p) {
                targets = vec![p];
            }
        }
    } else if tool == "Grep" {
        (targets, issues) = grep_tool_targets(inp, &cwd, &mut budget)?;
    } else if SHELL_TOOLS.contains(&tool) {
        let command = match get_str(inp, "command")? {
            Some(c) => Some(c),
            None => get_str(inp, "cmd")?,
        };
        if let Some(command) = command {
            (targets, issues) = analyze_bash(&command, &cwd, &mut budget);
        }
    } else if tool.starts_with("mcp__") {
        let mut strings = Vec::new();
        iter_strings(inp, 0, &mut strings);
        for s in strings {
            let mut cands = vec![s.to_string()];
            cands.extend(candidates_in_word(s));
            for cand in cands {
                if is_target(&cand) {
                    targets.extend(expand(&cand, &cwd));
                }
            }
        }
        targets = dedup(targets);
    }
    Ok((targets, issues, cwd))
}

fn deny_with(reason: &str) -> String {
    json!({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }})
    .to_string()
}

fn deny(paths: &[String], cwd: &str, issues: &[String]) -> Option<String> {
    let mut blocks = Vec::new();
    for p in paths.iter().take(MAX_PREVIEW_FILES) {
        if let Some(body) = render(p) {
            let rel = if p.starts_with(cwd) {
                relpath(p, cwd)
            } else {
                p.clone()
            };
            blocks.push(format!("=== {rel} (values masked) ===\n{body}"));
        }
    }
    if paths.len() > MAX_PREVIEW_FILES {
        blocks.push(format!(
            "... and {} more secret file(s) not previewed",
            paths.len() - MAX_PREVIEW_FILES
        ));
    }
    let mut parts: Vec<String> = Vec::new();
    if !blocks.is_empty() {
        parts.push(format!(
            "Blocked: reading .env / .properties files directly is disabled to keep secret values out of the \
conversation. Here is the masked content instead (KEY={MASK}). Do NOT retry the raw read or \
work around this hook; if you need an actual value, ask the user.\n\n{}",
            blocks.join("\n\n")
        ));
    } else if !paths.is_empty() {
        // Unlike the Python hook (which stays silent when a file cannot be previewed), never let a
        // secret file through just because it could not be rendered, e.g. a non-UTF-8 file name.
        parts.push("Blocked: reading .env / .properties files directly is disabled to keep secret values out of the \
conversation, and the masked preview could not be produced. If you need an actual value, ask the user."
            .to_string());
    }
    parts.extend(issues.iter().cloned());
    if parts.is_empty() {
        None
    } else {
        Some(deny_with(&parts.join("\n\n")))
    }
}

/// Run the hook on one PreToolUse payload. `Some(json)` is a deny decision; `None` lets the call through.
pub fn run(raw: &str) -> Option<String> {
    let data: Value = serde_json::from_str(raw).ok()?;
    let outcome = catch_unwind(AssertUnwindSafe(|| evaluate(&data)));
    let failure = match outcome {
        Ok(Ok((targets, issues, cwd))) => {
            return if targets.is_empty() && issues.is_empty() {
                None
            } else {
                deny(&targets, &cwd, &issues)
            };
        }
        Ok(Err(name)) => name,
        Err(_) => "InternalError",
    };
    // Fail closed when the request touches a secret file name.
    let mentions = Regex::new(r"(?i)\.properties|\.env").unwrap().is_match(raw);
    mentions.then(|| {
        deny_with(&format!(
            "Blocked: the secret-masking hook hit an internal error ({failure}) on a request that mentions a \
.properties/.env file, so it was denied to be safe. Ask the user to check the mask-secrets hook."
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ms-lib-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn call(tool: &str, input: Value, cwd: &std::path::Path) -> Option<String> {
        run(&json!({"tool_name": tool, "tool_input": input, "cwd": cwd}).to_string())
    }

    #[test]
    fn read_env_is_denied_with_masked_preview() {
        let d = tmp("read");
        fs::write(d.join(".env"), "TOKEN=FAKE_SECRET\n").unwrap();
        let out = call("Read", json!({"file_path": ".env"}), &d).expect("denied");
        assert!(
            out.contains("TOKEN=****") && !out.contains("FAKE_SECRET"),
            "{out}"
        );
        assert!(call("Read", json!({"file_path": "other.txt"}), &d).is_none());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn malformed_input_fails_closed_only_when_a_secret_is_mentioned() {
        let d = tmp("fail");
        let bad = |input: Value| {
            run(&json!({"tool_name": "Bash", "tool_input": input, "cwd": d}).to_string())
        };
        assert!(bad(json!([".env"])).unwrap().contains("internal error"));
        assert!(bad(json!(["ls"])).is_none());
        assert!(run("not json").is_none());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn hash_does_not_hide_later_commands() {
        let d = tmp("hash");
        fs::write(d.join(".env"), "TOKEN=FAKE_SECRET\n").unwrap();
        for cmd in [
            "echo a#b && cat .env",
            "echo ok # note\ncat .env",
            "cat .env # tail",
        ] {
            assert!(call("Bash", json!({"command": cmd}), &d).is_some(), "{cmd}");
        }
        assert!(
            call(
                "Bash",
                json!({"command": "echo '# cat .env is text' > /dev/null"}),
                &d
            )
            .is_none()
        );
        let _ = fs::remove_dir_all(&d);
    }
}
