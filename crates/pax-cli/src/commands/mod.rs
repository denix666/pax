pub fn privilege_escalation_tool() -> Option<String> {
    if let Ok(tool) = std::env::var("PAX_SUDO") {
        return Some(tool);
    }
    for candidate in &["sudo", "doas"] {
        if std::process::Command::new("which")
            .arg(candidate)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Some(candidate.to_string());
        }
    }
    None
}

pub fn ensure_root() {
    if (unsafe { libc::geteuid() }) == 0 {
        return;
    }
    let Some(tool) = privilege_escalation_tool() else {
        eprintln!("error: this operation requires root privileges");
        eprintln!("  install sudo or doas, or set PAX_SUDO to your privilege escalation tool");
        std::process::exit(1);
    };
    let pax_bin = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("pax"));
    let args: Vec<String> = std::env::args().skip(1).collect();
    let status = std::process::Command::new(&tool)
        .arg(&pax_bin)
        .args(&args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();
    std::process::exit(match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(_) => 1,
    });
}

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use pax_core::config::SigLevel;

pub(crate) fn confirm(prompt: &str) -> anyhow::Result<bool> {
    print!("{prompt} ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_lowercase();
    Ok(answer.is_empty() || answer == "y" || answer == "yes")
}

pub(crate) fn confirm_default_no(prompt: &str) -> anyhow::Result<bool> {
    print!("{prompt} ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}

pub(crate) struct SyncInfo {
    pub compressed_size: u64,
    pub installed_size: u64,
    pub repository: String,
    pub filename: String,
    pub sha256sum: Option<String>,
    pub sig_level: SigLevel,
}

pub(crate) fn collect_old_install_scripts(
    db_path: &Path,
    tx: &pax_resolver::Transaction,
) -> HashMap<String, String> {
    let mut scripts = HashMap::new();
    for upgrade in &tx.upgrades {
        let path = db_path
            .join("local")
            .join(format!("{}-{}", upgrade.name, upgrade.old_version))
            .join("install");
        if let Ok(content) = std::fs::read_to_string(&path) {
            scripts.insert(upgrade.name.clone(), content);
        }
    }
    scripts
}

pub(crate) fn collect_old_backup_md5(
    db_path: &Path,
    tx: &pax_resolver::Transaction,
) -> HashMap<String, HashMap<String, String>> {
    let mut result = HashMap::new();
    for upgrade in &tx.upgrades {
        let path = db_path
            .join("local")
            .join(format!("{}-{}", upgrade.name, upgrade.old_version))
            .join("files");
        if let Ok(content) = std::fs::read_to_string(&path) {
            let mut md5s = HashMap::new();
            let mut in_backup = false;
            for line in content.lines() {
                if line == "%BACKUP%" {
                    in_backup = true;
                    continue;
                }
                if line.starts_with('%') || line.is_empty() {
                    in_backup = false;
                    continue;
                }
                if in_backup {
                    if let Some((p, m)) = line.split_once('\t') {
                        md5s.insert(p.to_string(), m.to_string());
                    }
                }
            }
            result.insert(upgrade.name.clone(), md5s);
        }
    }
    result
}

pub(crate) fn dirs_build_base() -> PathBuf {
    if let Ok(cache) = std::env::var("XDG_CACHE_HOME") {
        PathBuf::from(cache).join("pax/aur")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".cache/pax/aur")
    } else {
        PathBuf::from("/tmp/pax-aur")
    }
}

pub mod aur;
pub mod aur_search;
pub mod aur_upgrade;
pub mod clean;
pub mod files;
pub mod info;
pub mod install;
pub mod localinstall;
pub mod owner;
pub mod query;
pub mod remove;
pub mod search;
pub mod sync;
pub mod upgrade;
