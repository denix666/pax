use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::{ExecError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerType {
    Package,
    Path,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerOp {
    Install,
    Upgrade,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookWhen {
    PreTransaction,
    PostTransaction,
}

#[derive(Debug, Clone)]
pub struct Trigger {
    pub trigger_type: TriggerType,
    pub operations: Vec<TriggerOp>,
    pub targets: Vec<String>,
    pub excludes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct HookAction {
    pub description: Option<String>,
    pub when: HookWhen,
    pub exec: String,
    pub needs_targets: bool,
}

#[derive(Debug, Clone)]
pub struct Hook {
    pub name: String,
    pub triggers: Vec<Trigger>,
    pub action: HookAction,
}

pub fn load_hooks(hook_dirs: &[PathBuf]) -> Vec<Hook> {
    let system_dir = PathBuf::from("/usr/share/libalpm/hooks");
    let mut dirs: Vec<&Path> = hook_dirs.iter().map(|p| p.as_path()).collect();
    if dirs.is_empty() {
        dirs.push(&system_dir);
    }

    let mut hooks = Vec::new();
    let mut seen_files = std::collections::HashSet::new();

    for dir in &dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut files: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext == "hook")
            })
            .collect();
        files.sort_by_key(|e| e.file_name());

        for entry in files {
            let name = entry.file_name().to_string_lossy().to_string();
            if !seen_files.insert(name.clone()) {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if let Some(hook) = parse_hook(&name, &content) {
                    hooks.push(hook);
                }
            }
        }
    }

    // Also always include the system dir
    if !dirs.iter().any(|d| *d == system_dir.as_path()) {
        if let Ok(entries) = std::fs::read_dir(&system_dir) {
            let mut files: Vec<_> = entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .is_some_and(|ext| ext == "hook")
                })
                .collect();
            files.sort_by_key(|e| e.file_name());

            for entry in files {
                let name = entry.file_name().to_string_lossy().to_string();
                if !seen_files.insert(name.clone()) {
                    continue;
                }
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    if let Some(hook) = parse_hook(&name, &content) {
                        hooks.push(hook);
                    }
                }
            }
        }
    }

    hooks.sort_by(|a, b| a.name.cmp(&b.name));
    hooks
}

fn parse_hook(name: &str, content: &str) -> Option<Hook> {
    let mut triggers = Vec::new();
    let mut action_desc = None;
    let mut action_when = HookWhen::PostTransaction;
    let mut action_exec = None;
    let mut needs_targets = false;

    let mut current_trigger: Option<Trigger> = None;
    let mut in_action = false;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line == "[Trigger]" {
            if let Some(t) = current_trigger.take() {
                triggers.push(t);
            }
            in_action = false;
            current_trigger = Some(Trigger {
                trigger_type: TriggerType::Package,
                operations: Vec::new(),
                targets: Vec::new(),
                excludes: Vec::new(),
            });
            continue;
        }

        if line == "[Action]" {
            if let Some(t) = current_trigger.take() {
                triggers.push(t);
            }
            in_action = true;
            continue;
        }

        if let Some(ref mut trigger) = current_trigger {
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                match key {
                    "Type" => {
                        trigger.trigger_type = match value {
                            "Path" | "File" => TriggerType::Path,
                            _ => TriggerType::Package,
                        };
                    }
                    "Operation" => {
                        let op = match value {
                            "Install" => Some(TriggerOp::Install),
                            "Upgrade" => Some(TriggerOp::Upgrade),
                            "Remove" => Some(TriggerOp::Remove),
                            _ => None,
                        };
                        if let Some(op) = op {
                            trigger.operations.push(op);
                        }
                    }
                    "Target" => {
                        if let Some(excluded) = value.strip_prefix('!') {
                            trigger.excludes.push(excluded.to_string());
                        } else {
                            trigger.targets.push(value.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        if in_action {
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                match key {
                    "Description" => action_desc = Some(value.to_string()),
                    "When" => {
                        action_when = match value {
                            "PreTransaction" => HookWhen::PreTransaction,
                            _ => HookWhen::PostTransaction,
                        };
                    }
                    "Exec" => action_exec = Some(value.to_string()),
                    _ => {}
                }
            } else if line == "NeedsTargets" {
                needs_targets = true;
            }
        }
    }

    if let Some(t) = current_trigger {
        triggers.push(t);
    }

    let exec = action_exec?;

    Some(Hook {
        name: name.to_string(),
        triggers,
        action: HookAction {
            description: action_desc,
            when: action_when,
            exec,
            needs_targets,
        },
    })
}

pub struct TransactionPackages {
    pub installed: Vec<String>,
    pub upgraded: Vec<String>,
    pub removed: Vec<String>,
    pub installed_files: Vec<String>,
    pub upgraded_files: Vec<String>,
    pub removed_files: Vec<String>,
}

pub fn run_hooks(
    hooks: &[Hook],
    when: &HookWhen,
    tx_pkgs: &TransactionPackages,
) -> Result<()> {
    for hook in hooks {
        if hook.action.when != *when {
            continue;
        }

        let matched = match_hook(hook, tx_pkgs);
        if matched.is_empty() {
            continue;
        }

        if let Some(ref desc) = hook.action.description {
            eprintln!(":: {desc}");
        }

        run_hook_action(&hook.action, &matched, &hook.name)?;
    }

    Ok(())
}

fn match_hook(hook: &Hook, tx_pkgs: &TransactionPackages) -> Vec<String> {
    let mut matched = Vec::new();

    for trigger in &hook.triggers {
        match trigger.trigger_type {
            TriggerType::Package => {
                for target in &trigger.targets {
                    for op in &trigger.operations {
                        let pkgs = match op {
                            TriggerOp::Install => &tx_pkgs.installed,
                            TriggerOp::Upgrade => &tx_pkgs.upgraded,
                            TriggerOp::Remove => &tx_pkgs.removed,
                        };
                        for pkg in pkgs {
                            if glob_match(target, pkg) {
                                matched.push(pkg.clone());
                            }
                        }
                    }
                }
            }
            TriggerType::Path => {
                for op in &trigger.operations {
                    let files = match op {
                        TriggerOp::Install => &tx_pkgs.installed_files,
                        TriggerOp::Upgrade => &tx_pkgs.upgraded_files,
                        TriggerOp::Remove => &tx_pkgs.removed_files,
                    };
                    for file in files {
                        let matches_target = trigger.targets.iter().any(|t| glob_match(t, file));
                        let excluded = trigger.excludes.iter().any(|e| glob_match(e, file));
                        if matches_target && !excluded {
                            matched.push(file.clone());
                        }
                    }
                }
            }
        }
    }

    matched.sort();
    matched.dedup();
    matched
}

fn run_hook_action(action: &HookAction, targets: &[String], hook_name: &str) -> Result<()> {
    let parts: Vec<&str> = action.exec.splitn(2, ' ').collect();
    let (cmd, args_str) = if parts.len() > 1 {
        (parts[0], Some(parts[1]))
    } else {
        (parts[0], None)
    };

    let mut command = if let Some(args) = args_str {
        let mut c = Command::new("sh");
        c.arg("-c").arg(format!("{} {}", cmd, args));
        c
    } else {
        Command::new(cmd)
    };

    if action.needs_targets {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }

    command.stdout(Stdio::inherit()).stderr(Stdio::inherit());

    let mut child = command.spawn().map_err(|e| ExecError::Hook {
        name: hook_name.to_string(),
        message: e.to_string(),
    })?;

    if action.needs_targets {
        if let Some(ref mut stdin) = child.stdin {
            for target in targets {
                if target.starts_with('/') {
                    let _ = writeln!(stdin, "{target}");
                } else {
                    let _ = writeln!(stdin, "/{target}");
                }
            }
        }
        drop(child.stdin.take());
    }

    let status = child.wait().map_err(|e| ExecError::Hook {
        name: hook_name.to_string(),
        message: e.to_string(),
    })?;

    if !status.success() {
        eprintln!(
            "warning: hook failed: {}: exit code {}",
            hook_name,
            status.code().unwrap_or(-1)
        );
    }

    Ok(())
}

fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == text {
        return true;
    }
    if !pattern.contains('*') && !pattern.contains('?') {
        return pattern == text;
    }
    glob_match_recursive(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_recursive(pattern: &[u8], text: &[u8]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }

    match pattern[0] {
        b'*' => {
            // '*' matches any sequence except '/' in path components, but for alpm hooks
            // '*' matches everything including '/'
            for i in 0..=text.len() {
                if glob_match_recursive(&pattern[1..], &text[i..]) {
                    return true;
                }
            }
            false
        }
        b'?' => {
            if text.is_empty() {
                return false;
            }
            glob_match_recursive(&pattern[1..], &text[1..])
        }
        c => {
            if text.is_empty() || text[0] != c {
                return false;
            }
            glob_match_recursive(&pattern[1..], &text[1..])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match() {
        assert!(glob_match("usr/lib/modules/*/", "usr/lib/modules/6.1.0/"));
        assert!(glob_match("*.conf", "test.conf"));
        assert!(glob_match("usr/share/haskell/register/*.sh", "usr/share/haskell/register/foo.sh"));
        assert!(!glob_match("usr/lib/modules/*/?*", "usr/lib/modules/6.1.0/"));
        assert!(glob_match("usr/lib/modules/*/?*", "usr/lib/modules/6.1.0/vmlinuz"));
        assert!(glob_match("glibc", "glibc"));
        assert!(!glob_match("glibc", "glibc-ng"));
    }

    #[test]
    fn test_parse_hook() {
        let content = r#"[Trigger]
Type = Path
Operation = Install
Operation = Upgrade
Target = usr/lib/modules/*/
Target = !usr/lib/modules/*/?*

[Action]
Description = Updating module dependencies...
When = PostTransaction
Exec = /usr/share/libalpm/scripts/depmod
NeedsTargets
"#;
        let hook = parse_hook("60-depmod.hook", content).unwrap();
        assert_eq!(hook.triggers.len(), 1);
        assert_eq!(hook.triggers[0].trigger_type, TriggerType::Path);
        assert_eq!(hook.triggers[0].operations.len(), 2);
        assert_eq!(hook.triggers[0].targets, vec!["usr/lib/modules/*/"]);
        assert_eq!(hook.triggers[0].excludes, vec!["usr/lib/modules/*/?*"]);
        assert!(hook.action.needs_targets);
        assert_eq!(hook.action.when, HookWhen::PostTransaction);
    }

    #[test]
    fn test_parse_hook_multiple_triggers() {
        let content = r#"[Trigger]
Type = Path
Operation = Install
Operation = Upgrade
Target = usr/lib/initcpio/*

[Trigger]
Type = Package
Operation = Install
Target = mkinitcpio

[Action]
Description = Updating initcpios...
When = PostTransaction
Exec = /usr/share/libalpm/scripts/mkinitcpio install
NeedsTargets
"#;
        let hook = parse_hook("90-mkinitcpio.hook", content).unwrap();
        assert_eq!(hook.triggers.len(), 2);
        assert_eq!(hook.triggers[0].trigger_type, TriggerType::Path);
        assert_eq!(hook.triggers[1].trigger_type, TriggerType::Package);
    }

    #[test]
    fn test_match_package_trigger() {
        let tx = TransactionPackages {
            installed: vec!["glibc".to_string()],
            upgraded: vec![],
            removed: vec![],
            installed_files: vec![],
            upgraded_files: vec![],
            removed_files: vec![],
        };
        let content = r#"[Trigger]
Type = Package
Operation = Install
Operation = Upgrade
Target = glibc

[Action]
When = PostTransaction
Exec = /usr/bin/locale-gen
"#;
        let hook = parse_hook("test.hook", content).unwrap();
        let matched = match_hook(&hook, &tx);
        assert_eq!(matched, vec!["glibc"]);
    }
}
