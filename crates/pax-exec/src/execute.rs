use std::collections::HashMap;
use std::path::{Path, PathBuf};

use pax_core::package::{InstallReason, Validation};
use pax_resolver::Transaction;

use crate::download::DownloadedPackage;
use crate::error::{ExecError, Result};
use crate::extract::extract_package;
use crate::hooks::{load_hooks, run_hooks, HookWhen, TransactionPackages};
use crate::register::{register_package, remove_db_entry};
use crate::scriptlet::{run_scriptlet, ScriptletOp};

pub struct InstallContext<'a> {
    pub root_dir: &'a Path,
    pub db_path: &'a Path,
    pub downloaded: &'a [DownloadedPackage],
    pub old_install_scripts: &'a HashMap<String, String>,
    pub old_backup_md5: &'a HashMap<String, HashMap<String, String>>,
    pub hook_dirs: &'a [PathBuf],
}

pub fn execute_transaction(tx: &Transaction, ctx: &InstallContext) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(ExecError::NotRoot);
    }

    let hooks = load_hooks(ctx.hook_dirs);

    let mut installed_pkgs = Vec::new();
    let mut upgraded_pkgs = Vec::new();
    let mut removed_pkgs = Vec::new();
    let mut installed_files: Vec<String> = Vec::new();
    let mut upgraded_files: Vec<String> = Vec::new();
    let mut removed_files: Vec<String> = Vec::new();

    // Collect what will change for hook matching
    for install in &tx.installs {
        installed_pkgs.push(install.name.clone());
    }
    for upgrade in &tx.upgrades {
        upgraded_pkgs.push(upgrade.name.clone());
    }
    for removal in &tx.removals {
        removed_pkgs.push(removal.name.clone());
    }

    let pre_tx = TransactionPackages {
        installed: installed_pkgs.clone(),
        upgraded: upgraded_pkgs.clone(),
        removed: removed_pkgs.clone(),
        installed_files: vec![],
        upgraded_files: vec![],
        removed_files: vec![],
    };
    run_hooks(&hooks, &HookWhen::PreTransaction, &pre_tx)?;

    let pkg_map: HashMap<&str, &DownloadedPackage> = ctx
        .downloaded
        .iter()
        .map(|d| (d.name.as_str(), d))
        .collect();

    for upgrade in &tx.upgrades {
        let Some(downloaded) = pkg_map.get(upgrade.name.as_str()) else {
            continue;
        };

        if let Some(old_script) = ctx.old_install_scripts.get(&upgrade.name) {
            run_scriptlet(
                old_script,
                ScriptletOp::PreUpgrade,
                &upgrade.new_version.to_string(),
                Some(&upgrade.old_version.to_string()),
                ctx.root_dir,
                &upgrade.name,
            )?;
        }

        let old_files = read_file_list(ctx.db_path, &upgrade.name, &upgrade.old_version.to_string());

        let backup_md5 = ctx
            .old_backup_md5
            .get(&upgrade.name)
            .cloned()
            .unwrap_or_default();

        let metadata = extract_package(&downloaded.path, ctx.root_dir, &backup_md5)?;

        remove_old_files(ctx.db_path, ctx.root_dir, &upgrade.name, &upgrade.old_version.to_string())?;

        let validation = vec![Validation::Sha256];
        let reason = get_existing_reason(ctx.db_path, &upgrade.name, &upgrade.old_version.to_string());

        remove_db_entry(ctx.db_path, &upgrade.name, &upgrade.old_version.to_string())?;
        register_package(ctx.db_path, &metadata, reason, &validation)?;

        upgraded_files.extend(metadata.files.iter().cloned());
        removed_files.extend(old_files);

        if let Some(ref install) = metadata.install {
            run_scriptlet(
                install,
                ScriptletOp::PostUpgrade,
                &upgrade.new_version.to_string(),
                Some(&upgrade.old_version.to_string()),
                ctx.root_dir,
                &upgrade.name,
            )?;
        }
    }

    for install in &tx.installs {
        let Some(downloaded) = pkg_map.get(install.name.as_str()) else {
            continue;
        };

        let metadata = extract_package(&downloaded.path, ctx.root_dir, &HashMap::new())?;

        if let Some(ref script) = metadata.install {
            run_scriptlet(
                script,
                ScriptletOp::PreInstall,
                &install.version.to_string(),
                None,
                ctx.root_dir,
                &install.name,
            )?;
        }

        let reason = if install.explicit {
            InstallReason::Explicit
        } else {
            InstallReason::Dependency
        };
        let validation = vec![Validation::Sha256];

        register_package(ctx.db_path, &metadata, reason, &validation)?;

        installed_files.extend(metadata.files.iter().cloned());

        if let Some(ref script) = metadata.install {
            run_scriptlet(
                script,
                ScriptletOp::PostInstall,
                &install.version.to_string(),
                None,
                ctx.root_dir,
                &install.name,
            )?;
        }
    }

    for removal in &tx.removals {
        let old_files = read_file_list(ctx.db_path, &removal.name, &removal.version.to_string());
        remove_old_files(ctx.db_path, ctx.root_dir, &removal.name, &removal.version.to_string())?;
        remove_db_entry(ctx.db_path, &removal.name, &removal.version.to_string())?;
        removed_files.extend(old_files);
    }

    let post_tx = TransactionPackages {
        installed: installed_pkgs,
        upgraded: upgraded_pkgs,
        removed: removed_pkgs,
        installed_files,
        upgraded_files,
        removed_files,
    };
    run_hooks(&hooks, &HookWhen::PostTransaction, &post_tx)?;

    Ok(())
}

fn read_file_list(db_path: &Path, name: &str, version: &str) -> Vec<String> {
    let files_path = db_path
        .join("local")
        .join(format!("{name}-{version}"))
        .join("files");

    let Ok(content) = std::fs::read_to_string(&files_path) else {
        return Vec::new();
    };

    let mut files = Vec::new();
    let mut in_files = false;
    for line in content.lines() {
        if line == "%FILES%" {
            in_files = true;
            continue;
        }
        if line.starts_with('%') || line.is_empty() {
            in_files = false;
            continue;
        }
        if in_files {
            files.push(line.to_string());
        }
    }
    files
}

fn remove_old_files(db_path: &Path, root_dir: &Path, name: &str, version: &str) -> Result<()> {
    let mut files = read_file_list(db_path, name, version);

    files.sort();
    files.reverse();

    for file in &files {
        let path = root_dir.join(file);
        if path.is_file() || path.is_symlink() {
            let _ = std::fs::remove_file(&path);
        } else if path.is_dir() {
            let _ = std::fs::remove_dir(&path);
        }
    }

    Ok(())
}

fn get_existing_reason(db_path: &Path, name: &str, version: &str) -> InstallReason {
    let desc_path = db_path
        .join("local")
        .join(format!("{name}-{version}"))
        .join("desc");

    if let Ok(content) = std::fs::read_to_string(&desc_path) {
        if content.contains("%REASON%\n1\n") {
            return InstallReason::Dependency;
        }
    }
    InstallReason::Explicit
}
