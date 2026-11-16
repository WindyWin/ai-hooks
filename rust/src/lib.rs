//! Shared Claude/Codex PreToolUse hook: keep .properties and .env values out of the conversation.
//!
//! PreToolUse cannot rewrite tool output, so when an agent tries to read one of these files the
//! call is denied and, where a single file is involved, the masked content (KEY=****) is returned
//! in the deny reason instead. See the README for what is covered and the known limits.

pub mod bash;
pub mod install;
pub mod mask;
pub mod pathx;
pub mod scrub;
pub mod stats;
pub mod tokenize;
pub mod tui;
pub mod walk;

use bash::{
    CAT_NOTICE, GIT_MASK_NOTICE, GREP_TOOL_ADVICE, Rewrite, SCRUB_NOTICE, analyze_bash,
    candidates_in_word, preprocessor, readonly_search_pipeline, rewrite_command, rg_notice,
    search_exposure,
};
use mask::{MASK, is_secret_file, is_target, render};
pub use mask::{mask_as, masked_view};
use pathx::{glob, has_magic, is_dir, relpath, resolve};
use regex::Regex;
use serde_json::{Map, Value, json};
use std::panic::{AssertUnwindSafe, catch_unwind};
use walk::Budget;

const MAX_PREVIEW_FILES: usize = 5;
const SHELL_TOOLS: [&str; 4] = ["Bash", "exec_command", "shell_command", "shell"];

/// secret files to deny, other reasons to deny, effective cwd, and an rg command rewritten to skip secrets.
type Evaluation = (Vec<String>, Vec<String>, String, Option<String>);
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
    let mut rewritten: Option<(Value, Rewrite)> = None;
    let codex = obj.contains_key("turn_id");

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
            // Bash tool: instead of blocking, make rg / git / grep print the secret files masked (see
            // rewrite_command). Codex cannot rewrite without approving the call, so there only for rg
            // commands that cannot change anything. The rewritten command is analysed again with a fresh
            // budget (a tree too large to verify does not matter for masked rg or git, but the rest of the
            // command still has to finish and come out clean), and the original block stands when it does not.
            if tool == "Bash"
                && (!issues.is_empty() || !targets.is_empty())
                && get_str(inp, "command")?.as_deref() == Some(command.as_str())
                && let Some(pre) = preprocessor()
                && (!codex || readonly_search_pipeline(&command))
                && let Some(candidate) = rewrite_command(&command, &cwd, &pre, codex)
                && {
                    let mut fresh = Budget::new();
                    let (t, i) = analyze_bash(&candidate.command, &cwd, &mut fresh);
                    t.is_empty() && i.is_empty() && !fresh.incomplete
                }
                && let Some(mut updated) = inp.as_object().cloned()
            {
                updated.insert("command".into(), Value::String(candidate.command.clone()));
                rewritten = Some((Value::Object(updated), candidate));
            }
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
    Ok((
        targets,
        issues,
        cwd,
        rewritten.map(|(v, kinds)| rewrite_output(v, codex, &kinds)),
    ))
}

fn rewrite_output(updated_input: Value, codex: bool, kinds: &Rewrite) -> String {
    let hook = if codex {
        // Codex only accepts updatedInput together with an allow.
        json!({
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": updated_input,
        })
    } else {
        // Claude: the normal permission flow still decides.
        let notice = [
            (kinds.rg, rg_notice()),
            (kinds.git, GIT_MASK_NOTICE.to_string()),
            (kinds.scrub, SCRUB_NOTICE.to_string()),
            (kinds.cat, CAT_NOTICE.to_string()),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, text)| text)
        .collect::<Vec<_>>()
        .join(" ");
        json!({
            "hookEventName": "PreToolUse",
            "additionalContext": notice,
            "updatedInput": updated_input,
        })
    };
    json!({ "hookSpecificOutput": hook }).to_string()
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

/// Run the hook on one PreToolUse payload. `Some(json)` is a deny decision (or an rg rewrite); `None` lets the call through.
pub fn run(raw: &str) -> Option<String> {
    let data: Value = serde_json::from_str(raw).ok()?;
    let outcome = catch_unwind(AssertUnwindSafe(|| evaluate(&data)));
    let failure = match outcome {
        Ok(Ok((targets, issues, cwd, rewritten))) => {
            return if rewritten.is_some() {
                rewritten
            } else if targets.is_empty() && issues.is_empty() {
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

    fn call_codex(tool: &str, input: Value, cwd: &std::path::Path) -> Option<String> {
        run(
            &json!({"tool_name": tool, "tool_input": input, "cwd": cwd, "turn_id": "t1"})
                .to_string(),
        )
    }

    #[test]
    fn rg_is_rewritten_to_search_secret_files_masked_on_claude() {
        let d = tmp("rg");
        fs::write(d.join(".env"), "TOKEN=FAKE_SECRET\n").unwrap();
        let flags = bash::rg_mask_flags(&preprocessor().unwrap());
        let out = call(
            "Bash",
            json!({"command": "rg TOKEN && ls", "description": "x"}),
            &d,
        )
        .expect("rewritten");
        let v: Value = serde_json::from_str(&out).unwrap();
        let hook = &v["hookSpecificOutput"];
        assert!(hook.get("permissionDecision").is_none(), "{out}");
        assert!(
            hook["additionalContext"]
                .as_str()
                .unwrap()
                .contains("KEY=****")
        );
        assert_eq!(hook["updatedInput"]["description"], "x");
        assert_eq!(
            hook["updatedInput"]["command"],
            format!("rg {flags} TOKEN && ls")
        );
        // an include glob is harmless once the files are masked
        let out = call("Bash", json!({"command": "rg TOKEN -g '*.env'"}), &d).expect("rewritten");
        assert!(
            out.contains("updatedInput") && !out.contains("deny"),
            "{out}"
        );
        // nested / complex forms and a user-supplied --pre keep the block
        for cmd in [
            "bash -c 'rg TOKEN'",
            "echo $(rg TOKEN)",
            "rg TOKEN --pre cat",
            "rg TOKEN -L",
            "rg TOKEN; grep -rho x .",
        ] {
            let out = call("Bash", json!({"command": cmd}), &d).expect(cmd);
            assert!(out.contains("\"deny\""), "{cmd}: {out}");
        }
        let out = call("exec_command", json!({"cmd": "rg TOKEN"}), &d).unwrap();
        assert!(out.contains("\"deny\""), "{out}");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn grep_is_piped_through_the_scrub_filter_and_git_gets_textconv() {
        let d = tmp("masked");
        fs::write(d.join(".env"), "TOKEN=FAKE_SECRET\n").unwrap();
        let pre = preprocessor().unwrap();
        let rewritten = |cmd: &str| -> Option<String> {
            let out = call("Bash", json!({"command": cmd}), &d)?;
            let v: Value = serde_json::from_str(&out).unwrap();
            v["hookSpecificOutput"]["updatedInput"]["command"]
                .as_str()
                .map(String::from)
        };
        let scrub = format!(" | {} --scrub", bash::shell_quote(&pre));
        assert_eq!(
            rewritten("grep -rn TOKEN .").unwrap(),
            format!("grep -rn TOKEN .{scrub}")
        );
        assert_eq!(
            rewritten("grep -rc TOKEN . | head").unwrap(),
            format!(
                "grep -rc TOKEN . | {} --scrub --counts | head",
                bash::shell_quote(&pre)
            )
        );
        // output shapes the filter does not understand, and the Codex agent, keep the block
        for cmd in [
            "grep -rho TOKEN .",
            "grep -rn --color=always x .",
            "ag -o x",
            "grep -R x .",
        ] {
            let out = call("Bash", json!({"command": cmd}), &d).expect(cmd);
            assert!(out.contains("\"deny\""), "{cmd}: {out}");
        }
        let out = call_codex("Bash", json!({"command": "grep -rn TOKEN ."}), &d).expect("denied");
        assert!(out.contains("\"deny\""), "{out}");
        // quiet searches print nothing
        assert!(call("Bash", json!({"command": "grep -rq TOKEN ."}), &d).is_none());
        // an agent-written filter only counts when it is right behind a search whose output it understands
        assert!(
            call(
                "Bash",
                json!({"command": format!("grep -rn x .{scrub}")}),
                &d
            )
            .is_none()
        );
        let out = call(
            "Bash",
            json!({"command": format!("grep -rho x .{scrub}")}),
            &d,
        )
        .expect("denied");
        assert!(out.contains("\"deny\""), "{out}");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn codex_rg_rewrite_comes_with_an_allow_and_only_for_read_only_pipelines() {
        let d = tmp("rg-codex");
        fs::write(d.join(".env"), "TOKEN=FAKE_SECRET\n").unwrap();
        let flags = bash::rg_mask_flags(&preprocessor().unwrap());
        let out = call_codex(
            "Bash",
            json!({"command": "rg -c TOKEN 2>&1 | sort -rn | head -n 5"}),
            &d,
        )
        .expect("rewritten");
        let v: Value = serde_json::from_str(&out).unwrap();
        let hook = &v["hookSpecificOutput"];
        assert_eq!(hook["permissionDecision"], "allow", "{out}");
        assert_eq!(
            hook["updatedInput"]["command"],
            format!("rg {flags} -c TOKEN 2>&1 | sort -rn | head -n 5")
        );
        for cmd in [
            "rg x && rm -rf build",
            "rg x > out.txt",
            "rg x | xargs cat",
            "rg x | sort -o out",
            "FOO=1 rg x",
            "rg x &",
            "rg $HOME",
            "rg x | uniq in out",
            "rg x 2> err.log",
        ] {
            let out = call_codex("Bash", json!({"command": cmd}), &d).expect(cmd);
            assert!(out.contains("\"deny\""), "{cmd}: {out}");
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn preprocessor_view_masks_secret_files_and_passes_templates() {
        let d = tmp("pre");
        let (env, tpl) = (d.join(".env"), d.join(".env.example"));
        fs::write(&env, "# c\nTOKEN=FAKE_SECRET\nEMPTY=\n").unwrap();
        fs::write(&tpl, "TOKEN=example\n").unwrap();
        let view = masked_view(env.to_str().unwrap()).unwrap();
        assert_eq!(
            String::from_utf8(view).unwrap(),
            "# c\nTOKEN=****\nEMPTY=\n"
        );
        let view = masked_view(tpl.to_str().unwrap()).unwrap();
        assert_eq!(String::from_utf8(view).unwrap(), "TOKEN=example\n");
        assert!(masked_view(d.join("missing.env").to_str().unwrap()).is_none());
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

    /// The command the hook would run instead (Claude), None when it lets the call through or blocks it.
    fn rewritten_to(cmd: &str, d: &std::path::Path) -> Option<String> {
        let out = call("Bash", json!({"command": cmd}), d)?;
        let v: Value = serde_json::from_str(&out).unwrap();
        v["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .map(String::from)
    }

    #[test]
    fn direct_reads_of_a_secret_file_go_through_the_masked_view() {
        let d = tmp("cat");
        fs::write(d.join(".env"), "TOKEN=FAKE_SECRET\n").unwrap();
        fs::write(d.join("app.properties"), "password=FAKE_P\n").unwrap();
        fs::write(d.join("plain.txt"), "hello\n").unwrap();
        let hook = bash::shell_quote(&preprocessor().unwrap());
        for (cmd, want) in [
            ("cat .env", format!("{hook} --cat .env | cat")),
            ("head -1 .env", format!("{hook} --cat .env | head -1")),
            ("sed -n 1p .env", format!("{hook} --cat .env | sed -n 1p")),
            (
                "tail -n 2 .env 2>/dev/null",
                format!("{hook} --cat .env | tail -n 2 2>/dev/null"),
            ),
            ("grep TOKEN .env", format!("{hook} --cat .env | grep TOKEN")),
            (
                "awk '{print $1}' .env",
                format!("{hook} --cat .env | awk '{{print $1}}'"),
            ),
            (
                "cat .env app.properties",
                format!("{hook} --cat .env app.properties | cat"),
            ),
            (
                "cat -n .env && ls",
                format!("{hook} --cat .env | cat -n && ls"),
            ),
            (
                "if cat .env; then ls; fi",
                format!("if {hook} --cat .env | cat; then ls; fi"),
            ),
        ] {
            assert_eq!(
                rewritten_to(cmd, &d).as_deref(),
                Some(want.as_str()),
                "{cmd}"
            );
        }
        // what cannot be fed through the masked view stays blocked
        for cmd in [
            "cat .env plain.txt && head .env plain.txt",
            "head -1 .env plain.txt",
            "cat < .env",
            "cat .env > copy",
            "sed -i s/a/b/ .env",
            "sed -f script.sed .env",
            "sort -o out .env",
            "tail -f .env",
            "grep -r TOKEN .env",
            "FOO=1 cat .env",
            "sudo cat .env",
            "command cat .env",
            "bash -c 'cat .env'",
            "echo $(cat .env)",
            "less .env",
            "python3 -c 'print(open(\".env\").read())'",
            "cat $PWD/.env .env",
        ] {
            let out = call("Bash", json!({"command": cmd}), &d).expect(cmd);
            assert!(out.contains("\"deny\""), "{cmd}: {out}");
        }
        // the Codex agent keeps the block: it can only rewrite together with an approval
        let out = call_codex("Bash", json!({"command": "cat .env"}), &d).expect("denied");
        assert!(out.contains("\"deny\""), "{out}");
        // files that are not secrets are left alone
        assert!(call("Bash", json!({"command": "cat plain.txt | head"}), &d).is_none());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn the_cat_entry_point_prints_what_it_is_asked_to_and_masked() {
        let d = tmp("catview");
        let (env, plain) = (d.join(".env"), d.join("plain.txt"));
        fs::write(&env, "TOKEN=FAKE_SECRET\n").unwrap();
        fs::write(&plain, "FAKE_PLAIN\n").unwrap();
        let hook = bash::shell_quote(&preprocessor().unwrap());
        for cmd in [
            format!("{hook} --cat .env"),
            format!("{hook} --cat plain.txt .env"),
            format!("{hook} --cat .env | head -1"),
            format!("if {hook} --cat .env; then ls; fi"),
        ] {
            assert!(call("Bash", json!({"command": cmd}), &d).is_none(), "{cmd}");
        }
        // only the exact entry point counts, not a command that merely mentions it
        for cmd in [
            format!("{hook} --cat .env; cat .env"),
            format!("sudo {hook} --cat .env"),
            format!("echo {hook} --cat; cat .env"),
        ] {
            let out = call("Bash", json!({"command": cmd}), &d).expect("not plain");
            assert!(
                out.contains("updatedInput") || out.contains("\"deny\""),
                "{out}"
            );
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn find_exec_prints_masked_files_or_is_blocked() {
        let d = tmp("find");
        fs::write(d.join(".env"), "TOKEN=FAKE_SECRET\n").unwrap();
        fs::write(d.join("a.txt"), "x\n").unwrap();
        let hook = bash::shell_quote(&preprocessor().unwrap());
        for (cmd, want) in [
            (
                r"find . -name .env -exec cat {} \;",
                format!(r"find . -name .env -exec {hook} --cat {{}} \;"),
            ),
            (
                "find . -type f -exec cat {} +",
                format!("find . -type f -exec {hook} --cat {{}} +"),
            ),
            (
                "find . -type f -exec grep -H TOKEN {} +",
                format!("find . -type f -exec grep -H TOKEN {{}} + | {hook} --scrub"),
            ),
            (
                "find . -type f -exec grep TOKEN {} +",
                format!("find . -type f -exec grep -H TOKEN {{}} + | {hook} --scrub"),
            ),
            (
                r"find . -type f -exec grep -c TOKEN {} \;",
                format!(r"find . -type f -exec grep -H -c TOKEN {{}} \; | {hook} --scrub --counts"),
            ),
            (
                r"find . -type f -execdir cat {} \; 2>/dev/null",
                format!(r"find . -type f -execdir {hook} --cat {{}} \; 2>/dev/null"),
            ),
        ] {
            assert_eq!(
                rewritten_to(cmd, &d).as_deref(),
                Some(want.as_str()),
                "{cmd}"
            );
        }
        // shapes that cannot be guaranteed stay blocked
        for cmd in [
            "find . -type f -exec head -1 {} +",
            r"find . -type f -ok head -1 {} \;",
            "find . -type f -exec grep -h TOKEN {} +",
            "find . -type f -exec sh -c 'cat \"$0\"' {} \\;",
            r"find . \( -name '*.txt' -o -name .env \) -exec head {} \;",
            "find . -type f -exec cat {}",
            "find . -type f -exec",
            "find . -type f -exec cp {} /tmp/x +",
        ] {
            let out = call("Bash", json!({"command": cmd}), &d).expect(cmd);
            assert!(out.contains("\"deny\""), "{cmd}: {out}");
        }
        // an -exec that cannot print anything, or only reaches files that are not secret, passes
        for cmd in [
            r"find . -type f -exec ls -l {} \;",
            "find . -name '*.txt' -exec head -1 {} +",
            "find . -name '*.txt' -exec cat {} +",
            "find . -type f -print",
        ] {
            assert!(call("Bash", json!({"command": cmd}), &d).is_none(), "{cmd}");
        }
        let out = call_codex(
            "Bash",
            json!({"command": "find . -type f -exec cat {} +"}),
            &d,
        )
        .expect("denied");
        assert!(out.contains("\"deny\""), "{out}");
        let _ = fs::remove_dir_all(&d);
    }
}
