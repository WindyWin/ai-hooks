//! Bounded directory walk, so the hook always finishes inside the agents' timeout.

use crate::mask::is_target;
use crate::pathx::{is_dir, join};
use std::fs;
use std::time::{Duration, Instant};

pub const WALK_BUDGET_SECONDS: f64 = 2.0;
pub const WALK_MAX_ENTRIES: usize = 60_000;
const SKIP_DIRS: [&str; 2] = [".git", "node_modules"];

pub struct Budget {
    deadline: Instant,
    max_entries: usize,
    pub entries: usize,
    pub incomplete: bool,
}

impl Budget {
    pub fn new() -> Self {
        Self::with_limits(
            Duration::from_secs_f64(WALK_BUDGET_SECONDS),
            WALK_MAX_ENTRIES,
        )
    }

    pub fn with_limits(time: Duration, max_entries: usize) -> Self {
        Budget {
            deadline: Instant::now() + time,
            max_entries,
            entries: 0,
            incomplete: false,
        }
    }

    pub fn exhausted(&mut self) -> bool {
        if !self.incomplete && (Instant::now() > self.deadline || self.entries > self.max_entries) {
            self.incomplete = true;
        }
        self.incomplete
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new()
    }
}

/// Secret-looking files under `root` (like `os.walk`: symlinked directories are listed but not
/// followed; `.git` and `node_modules` are skipped). Stops early when the budget runs out.
pub fn walk_targets(
    root: &str,
    budget: &mut Budget,
    matcher: Option<&dyn Fn(&str) -> bool>,
) -> Vec<String> {
    let mut hits = Vec::new();
    if !is_dir(root) {
        return hits;
    }
    let mut stack = vec![root.to_string()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        let mut subdirs: Vec<String> = Vec::new();
        let mut files: Vec<String> = Vec::new();
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(ft) = entry.file_type() else { continue };
            let (is_directory, descend) = if ft.is_symlink() {
                (is_dir(&join(&dir, &name)), false)
            } else {
                (ft.is_dir(), ft.is_dir())
            };
            if is_directory {
                if SKIP_DIRS.contains(&name.as_str()) {
                    continue;
                }
                subdirs.push(if descend {
                    join(&dir, &name)
                } else {
                    String::new()
                });
                budget.entries += 1;
            } else {
                files.push(name);
            }
        }
        budget.entries += files.len();
        if budget.exhausted() {
            break;
        }
        for name in files {
            if is_target(&name) && matcher.is_none_or(|m| m(&name)) {
                hits.push(join(&dir, &name));
            }
        }
        // Reverse so the stack visits subdirectories in listing order (pre-order, like os.walk).
        stack.extend(subdirs.into_iter().rev().filter(|s| !s.is_empty()));
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_nested_secrets_and_skips_git() {
        let tmp = std::env::temp_dir().join(format!("ms-walk-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("a/b")).unwrap();
        fs::create_dir_all(tmp.join(".git")).unwrap();
        fs::write(tmp.join("a/b/.env"), "X=1").unwrap();
        fs::write(tmp.join(".git/.env"), "X=1").unwrap();
        fs::write(tmp.join("a/plain.txt"), "x").unwrap();
        let hits = walk_targets(tmp.to_str().unwrap(), &mut Budget::new(), None);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].ends_with("a/b/.env"));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn exhausted_budget_marks_incomplete() {
        let tmp = std::env::temp_dir().join(format!("ms-walk2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join("f"), "x").unwrap();
        let mut budget = Budget::with_limits(Duration::from_secs(2), 0);
        walk_targets(tmp.to_str().unwrap(), &mut budget, None);
        assert!(budget.incomplete);
        let _ = fs::remove_dir_all(&tmp);
    }
}
