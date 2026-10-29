use std::collections::BTreeMap;
use std::ffi::CString;
use std::path::{Path, PathBuf};

use pax_core::package::Dependency;

use crate::error::{ExecError, Result};
use crate::log::PaxLogger;
use crate::scriptlet::{command_in_root, command_output};

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
    /// Ordered patterns, including leading `!` exclusions. Last match wins.
    pub targets: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct HookAction {
    pub description: Option<String>,
    pub when: HookWhen,
    pub exec: String,
    pub needs_targets: bool,
    pub abort_on_fail: bool,
    pub depends: Vec<Dependency>,
}

#[derive(Debug, Clone)]
pub struct Hook {
    pub name: String,
    pub triggers: Vec<Trigger>,
    pub action: HookAction,
}

/// HookDir paths are host paths, not paths relative to RootDir (pacman.conf(5)).
/// The system directory is always included; explicit HookDirs replace the
/// default /etc/pacman.d/hooks. Later directories have higher priority.
pub fn load_hooks(hook_dirs: &[PathBuf]) -> Vec<Hook> {
    let mut dirs = vec![PathBuf::from("/usr/share/libalpm/hooks")];
    if hook_dirs.is_empty() {
        dirs.push(PathBuf::from("/etc/pacman.d/hooks"));
    } else {
        dirs.extend_from_slice(hook_dirs);
    }
    load_hook_directories(&dirs)
}

fn load_hook_directories(dirs: &[PathBuf]) -> Vec<Hook> {
    let mut files = BTreeMap::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.path().extension().is_some_and(|ext| ext == "hook") {
                // Select the winning file before parsing: an empty /dev/null
                // override must also suppress the lower-priority hook.
                files.insert(entry.file_name(), entry.path());
            }
        }
    }
    let mut hooks: Vec<_> = files
        .into_iter()
        .filter_map(|(name, path)| {
            let content = std::fs::read_to_string(path).ok()?;
            parse_hook(&name.to_string_lossy(), &content)
        })
        .collect();
    hooks.sort_by(|a, b| {
        a.name
            .strip_suffix(".hook")
            .unwrap_or(&a.name)
            .cmp(b.name.strip_suffix(".hook").unwrap_or(&b.name))
    });
    hooks
}

fn parse_hook(name: &str, content: &str) -> Option<Hook> {
    let mut triggers = Vec::new();
    let mut description = None;
    let mut when = None;
    let mut exec = None;
    let mut needs_targets = false;
    let mut abort_on_fail = false;
    let mut depends = Vec::new();
    let mut current_trigger: Option<Trigger> = None;
    let mut trigger_has_type = false;
    let mut in_action = false;
    let mut seen_action = false;

    for line in content.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[Trigger]" || line == "[Action]" {
            if let Some(trigger) = current_trigger.take() {
                if !trigger_has_type || trigger.operations.is_empty() || trigger.targets.is_empty()
                {
                    return None;
                }
                triggers.push(trigger);
            }
            in_action = line == "[Action]";
            if in_action {
                if seen_action {
                    return None;
                }
                seen_action = true;
            } else {
                trigger_has_type = false;
                current_trigger = Some(Trigger {
                    trigger_type: TriggerType::Package,
                    operations: Vec::new(),
                    targets: Vec::new(),
                });
            }
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some((key, value)) => (key.trim(), Some(value.trim())),
            None => (line, None),
        };
        if let Some(trigger) = current_trigger.as_mut() {
            let value = value?;
            match key {
                "Type" => {
                    trigger.trigger_type = match value {
                        "Package" => TriggerType::Package,
                        "Path" | "File" => TriggerType::Path,
                        _ => return None,
                    };
                    trigger_has_type = true;
                }
                "Operation" => trigger.operations.push(match value {
                    "Install" => TriggerOp::Install,
                    "Upgrade" => TriggerOp::Upgrade,
                    "Remove" => TriggerOp::Remove,
                    _ => return None,
                }),
                "Target" if !value.is_empty() => trigger.targets.push(value.to_string()),
                _ => return None,
            }
        } else if in_action {
            match (key, value) {
                ("Description", Some(value)) => description = Some(value.to_string()),
                ("When", Some(value)) => {
                    when = Some(match value {
                        "PreTransaction" => HookWhen::PreTransaction,
                        "PostTransaction" => HookWhen::PostTransaction,
                        _ => return None,
                    })
                }
                ("Exec", Some(value)) => {
                    split_exec(value)?;
                    exec = Some(value.to_string());
                }
                ("Depends", Some(value)) if !value.is_empty() => {
                    let dependency = Dependency::parse(value).ok()?;
                    if dependency.name.is_empty() {
                        return None;
                    }
                    depends.push(dependency);
                }
                ("NeedsTargets", None) => needs_targets = true,
                ("AbortOnFail", None) => abort_on_fail = true,
                _ => return None,
            }
        } else {
            return None;
        }
    }
    if let Some(trigger) = current_trigger {
        if !trigger_has_type || trigger.operations.is_empty() || trigger.targets.is_empty() {
            return None;
        }
        triggers.push(trigger);
    }
    if triggers.is_empty() {
        return None;
    }
    Some(Hook {
        name: name.to_string(),
        triggers,
        action: HookAction {
            description,
            when: when?,
            exec: exec?,
            needs_targets,
            abort_on_fail,
            depends,
        },
    })
}

#[derive(Default)]
pub struct TransactionPackages {
    pub installed: Vec<String>,
    pub upgraded: Vec<String>,
    pub removed: Vec<String>,
    pub installed_files: Vec<String>,
    pub upgraded_files: Vec<String>,
    pub removed_files: Vec<String>,
}

/// `dependency_satisfied` must check the installed database at this hook phase,
/// including version constraints and versioned/unversioned package provides.
/// It must not assume that packages scheduled for installation already exist.
pub fn run_hooks(
    hooks: &[Hook],
    when: &HookWhen,
    tx_pkgs: &TransactionPackages,
    root_dir: &Path,
    dependency_satisfied: &dyn Fn(&Dependency) -> bool,
    logger: &mut PaxLogger,
) -> Result<()> {
    for hook in hooks {
        if hook.action.when != *when {
            continue;
        }
        let matched = match_hook(hook, tx_pkgs);
        if matched.is_empty() {
            continue;
        }

        let result = (|| {
            for dependency in &hook.action.depends {
                if !dependency_satisfied(dependency) {
                    return Err(ExecError::Hook {
                        name: hook.name.clone(),
                        message: format!("unsatisfied dependency: {dependency}"),
                    });
                }
            }
            if let Some(desc) = &hook.action.description {
                eprintln!(":: {desc}");
            }
            logger.log_hook(&hook.name);
            run_hook_action(&hook.action, &matched, &hook.name, root_dir, logger)
        })();
        if let Err(error) = result {
            eprintln!("warning: {error}");
            logger.log_warning(&error.to_string());
            if *when == HookWhen::PreTransaction && hook.action.abort_on_fail {
                return Err(error);
            }
        }
    }
    Ok(())
}

fn match_hook(hook: &Hook, tx_pkgs: &TransactionPackages) -> Vec<String> {
    let mut matched = Vec::new();
    for trigger in &hook.triggers {
        for op in &trigger.operations {
            let candidates = match (&trigger.trigger_type, op) {
                (TriggerType::Package, TriggerOp::Install) => &tx_pkgs.installed,
                (TriggerType::Package, TriggerOp::Upgrade) => &tx_pkgs.upgraded,
                (TriggerType::Package, TriggerOp::Remove) => &tx_pkgs.removed,
                (TriggerType::Path, TriggerOp::Install) => &tx_pkgs.installed_files,
                (TriggerType::Path, TriggerOp::Upgrade) => &tx_pkgs.upgraded_files,
                (TriggerType::Path, TriggerOp::Remove) => &tx_pkgs.removed_files,
            };
            for candidate in candidates {
                let mut selected = false;
                for target in &trigger.targets {
                    let (pattern, include) = match target.strip_prefix('!') {
                        Some(pattern) => (pattern, false),
                        None => (target.as_str(), true),
                    };
                    if glob_match(pattern, candidate) {
                        selected = include;
                    }
                }
                if selected {
                    matched.push(candidate.clone());
                }
            }
        }
    }
    matched.sort();
    matched.dedup();
    matched
}

fn run_hook_action(
    action: &HookAction,
    targets: &[String],
    hook_name: &str,
    root_dir: &Path,
    logger: &mut PaxLogger,
) -> Result<()> {
    let run = || -> std::io::Result<std::process::Output> {
        let argv = split_exec(&action.exec).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid Exec arguments")
        })?;
        let mut command = command_in_root(&argv[0], root_dir)?;
        command.args(&argv[1..]);
        let input = action.needs_targets.then(|| targets_input(targets));
        command_output(&mut command, input.as_deref())
    };
    let output = run().map_err(|error| ExecError::Hook {
        name: hook_name.to_string(),
        message: error.to_string(),
    })?;
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        if !text.is_empty() {
            eprint!("{text}");
            logger.log_hook_output(hook_name, &text);
        }
    }
    if !output.status.success() {
        return Err(ExecError::Hook {
            name: hook_name.to_string(),
            message: output.status.to_string(),
        });
    }
    Ok(())
}

fn targets_input(targets: &[String]) -> Vec<u8> {
    let mut input = Vec::new();
    for target in targets {
        input.extend_from_slice(target.as_bytes());
        input.push(b'\n');
    }
    input
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let (Ok(pattern), Ok(text)) = (CString::new(pattern), CString::new(text)) else {
        return false;
    };
    // libalpm uses fnmatch with flags=0: wildcards cross '/' and match dotfiles,
    // bracket expressions, POSIX character classes and backslash escapes apply.
    unsafe { libc::fnmatch(pattern.as_ptr(), text.as_ptr(), 0) == 0 }
}

/// Split Exec without shell evaluation. Quotes group whitespace; backslash
/// escapes the next character outside single quotes. Empty quoted args survive.
fn split_exec(exec: &str) -> Option<Vec<String>> {
    let mut args = Vec::new();
    let mut arg = String::new();
    let mut quote = None;
    let mut started = false;
    let mut chars = exec.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\0' => return None,
            '\\' if quote != Some('\'') => {
                let escaped = chars.next()?;
                if escaped == '\0' {
                    return None;
                }
                arg.push(escaped);
                started = true;
            }
            '\'' | '"' if quote.is_none() => {
                quote = Some(ch);
                started = true;
            }
            '\'' | '"' if quote == Some(ch) => quote = None,
            ch if ch.is_ascii_whitespace() && quote.is_none() => {
                if started {
                    args.push(std::mem::take(&mut arg));
                    started = false;
                }
            }
            ch => {
                arg.push(ch);
                started = true;
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    if started {
        args.push(arg);
    }
    if args.first().is_none_or(String::is_empty) {
        return None;
    }
    Some(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hook(exec: &str, flags: &str, when: &str) -> Hook {
        parse_hook("test.hook", &format!(
            "[Trigger]\nType = Package\nOperation = Install\nTarget = *\n[Action]\nWhen = {when}\nExec = {exec}\n{flags}\n"
        )).unwrap()
    }

    #[test]
    fn fnmatch_shell_patterns() {
        assert!(glob_match("usr/*", "usr/lib/.hidden/file"));
        assert!(glob_match("pkg[0-9]", "pkg7"));
        assert!(glob_match("pkg[!0-9]", "pkga"));
        assert!(glob_match("[[:digit:]]", "7"));
        assert!(glob_match(r"literal\*", "literal*"));
        assert!(!glob_match("pkg[0-9]", "pkga"));
        assert!(!glob_match("pkg[", "pkg1"));
    }

    #[test]
    fn ordered_package_and_path_exclusions() {
        for kind in ["Package", "Path"] {
            let content = format!(
                "[Trigger]\nType = {kind}\nOperation = Install\nTarget = *\nTarget = !foo*\nTarget = foo-keep\n[Action]\nWhen = PostTransaction\nExec = /bin/true\n"
            );
            let hook = parse_hook("test.hook", &content).unwrap();
            let candidates = vec!["foo-drop".into(), "foo-keep".into(), "other".into()];
            let tx = TransactionPackages {
                installed: candidates.clone(),
                installed_files: candidates,
                ..Default::default()
            };
            assert_eq!(match_hook(&hook, &tx), vec!["foo-keep", "other"]);
        }
    }

    #[test]
    fn matched_targets_are_sorted_unique_across_triggers() {
        let mut hook = hook("/bin/true", "NeedsTargets", "PostTransaction");
        hook.triggers.push(hook.triggers[0].clone());
        let tx = TransactionPackages {
            installed: vec!["z".into(), "a".into(), "z".into()],
            ..Default::default()
        };
        assert_eq!(match_hook(&hook, &tx), vec!["a", "z"]);
    }

    #[test]
    fn needs_targets_preserves_names_and_relative_paths() {
        assert_eq!(
            targets_input(&["glibc".into(), "usr/lib/file".into(), "/already".into()]),
            b"glibc\nusr/lib/file\n/already\n"
        );
    }

    #[test]
    fn exec_is_argv_not_shell() {
        assert_eq!(
            split_exec(r#"/bin/tool "two words" '' 'literal $x' a\ b ; $(id)"#).unwrap(),
            vec![
                "/bin/tool",
                "two words",
                "",
                "literal $x",
                "a b",
                ";",
                "$(id)"
            ]
        );
        assert!(split_exec("/bin/tool 'unterminated").is_none());
        assert!(split_exec("/bin/tool \\").is_none());
        assert!(split_exec(" ").is_none());
    }

    #[test]
    fn later_directory_overrides_and_dev_null_disables() {
        let base = tempfile::tempdir().unwrap();
        let override_dir = tempfile::tempdir().unwrap();
        let content = "[Trigger]\nType = Package\nOperation = Install\nTarget = *\n[Action]\nWhen = PostTransaction\nExec = /bin/true\n";
        std::fs::write(base.path().join("test.hook"), content).unwrap();
        std::fs::write(
            override_dir.path().join("test.hook"),
            content.replace("/bin/true", "/bin/false"),
        )
        .unwrap();
        let dirs = [base.path().to_path_buf(), override_dir.path().to_path_buf()];
        assert_eq!(load_hook_directories(&dirs)[0].action.exec, "/bin/false");
        std::fs::remove_file(override_dir.path().join("test.hook")).unwrap();
        std::os::unix::fs::symlink("/dev/null", override_dir.path().join("test.hook")).unwrap();
        assert!(load_hook_directories(&dirs).is_empty());
    }

    #[test]
    fn abort_on_fail_only_aborts_pre_transaction() {
        let tx = TransactionPackages {
            installed: vec!["test".into()],
            ..Default::default()
        };
        for (when, flag, aborts) in [
            (HookWhen::PreTransaction, "", false),
            (HookWhen::PreTransaction, "AbortOnFail", true),
            (HookWhen::PostTransaction, "AbortOnFail", false),
        ] {
            let when_name = if when == HookWhen::PreTransaction {
                "PreTransaction"
            } else {
                "PostTransaction"
            };
            let hook = hook("/bin/false", flag, when_name);
            assert_eq!(
                run_hooks(
                    &[hook],
                    &when,
                    &tx,
                    Path::new("/"),
                    &|_| true,
                    &mut PaxLogger::none()
                )
                .is_err(),
                aborts
            );
        }
    }

    #[test]
    fn depends_checked_before_spawning() {
        let hook = hook(
            "/must/not/run",
            "Depends = provider>=2\nAbortOnFail",
            "PreTransaction",
        );
        let tx = TransactionPackages {
            installed: vec!["test".into()],
            ..Default::default()
        };
        let error = run_hooks(
            &[hook],
            &HookWhen::PreTransaction,
            &tx,
            Path::new("/"),
            &|dep| {
                assert_eq!(dep.to_string(), "provider>=2");
                false
            },
            &mut PaxLogger::none(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("unsatisfied dependency"));
    }

    #[test]
    fn ordinary_failure_does_not_skip_later_hooks() {
        let hooks = [
            hook("/bin/false", "", "PreTransaction"),
            hook("/bin/true", "Depends = checked", "PreTransaction"),
        ];
        let checked = std::cell::Cell::new(false);
        let tx = TransactionPackages {
            installed: vec!["test".into()],
            ..Default::default()
        };
        run_hooks(
            &hooks,
            &HookWhen::PreTransaction,
            &tx,
            Path::new("/"),
            &|_| {
                checked.set(true);
                true
            },
            &mut PaxLogger::none(),
        )
        .unwrap();
        assert!(checked.get());
    }

    #[test]
    fn required_fields_are_validated() {
        assert!(parse_hook("empty.hook", "").is_none());
        assert!(parse_hook("bad.hook", "[Trigger]\nOperation = Install\nTarget = *\n[Action]\nWhen = PostTransaction\nExec = /bin/true").is_none());
        assert!(
            parse_hook(
                "bad.hook",
                "[Action]\nWhen = PostTransaction\nExec = /bin/true"
            )
            .is_none()
        );
    }
}
