use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;
use pax_core::version::Version;
use pax_exec::{execute_transaction, read_pkginfo, DownloadedPackage, InstallContext};
use pax_resolver::{InstallAction, Transaction, UpgradeAction};

pub fn run(db: &mut DatabaseHandle, files: &[PathBuf], noconfirm: bool) -> Result<()> {
    if files.is_empty() {
        eprintln!("error: no targets specified");
        std::process::exit(1);
    }

    for file in files {
        if !file.exists() {
            eprintln!("error: file not found: {}", file.display());
            std::process::exit(1);
        }
    }

    db.local()?;

    let mut installs = Vec::new();
    let mut upgrades = Vec::new();
    let mut total_installed_size: u64 = 0;
    let mut downloaded = Vec::with_capacity(files.len());

    for file in files {
        let info = read_pkginfo(file).map_err(|e| anyhow::anyhow!("{e}"))?;
        let version = Version::parse(&info.version)
            .map_err(|e| anyhow::anyhow!("{}: invalid version: {e}", file.display()))?;
        let canonical = file.canonicalize()?;

        let local_ver = db.local_info(&info.name)?.map(|p| p.info.version.clone());

        if let Some(old_version) = local_ver {
            upgrades.push(UpgradeAction {
                name: info.name.clone(),
                old_version,
                new_version: version,
                repository: "local".to_string(),
                download_size: 0,
            });
        } else {
            total_installed_size += info.installed_size;
            installs.push(InstallAction {
                name: info.name.clone(),
                version,
                repository: "local".to_string(),
                download_size: 0,
                installed_size: info.installed_size,
                explicit: true,
            });
        }

        downloaded.push(DownloadedPackage {
            name: info.name,
            path: canonical,
        });
    }

    if installs.is_empty() && upgrades.is_empty() {
        println!("there is nothing to do");
        return Ok(());
    }

    if !installs.is_empty() {
        println!("\n{}", "Packages to install:".bold());
        for inst in &installs {
            println!(
                "  {}/{} {}",
                "local".purple(),
                inst.name.bold(),
                inst.version.green(),
            );
        }
    }

    if !upgrades.is_empty() {
        println!("\n{}", "Packages to upgrade:".bold());
        for upg in &upgrades {
            println!(
                "  {}/{} {} -> {}",
                "local".purple(),
                upg.name.bold(),
                upg.old_version.red(),
                upg.new_version.green(),
            );
        }
    }

    let total_count = installs.len() + upgrades.len();
    println!("\nTotal packages: {}", total_count.to_string().bold());

    if !noconfirm {
        print!("\nProceed with installation? [Y/n] ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        let answer = answer.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Installation cancelled.");
            return Ok(());
        }
    }

    let tx = Transaction {
        installs,
        upgrades,
        removals: vec![],
        total_download_size: 0,
        total_installed_size,
    };

    let old_install_scripts = collect_old_install_scripts(&db.config.db_path, &tx);
    let old_backup_md5 = collect_old_backup_md5(&db.config.db_path, &tx);

    let ctx = InstallContext {
        root_dir: &db.config.root_dir,
        db_path: &db.config.db_path,
        downloaded: &downloaded,
        old_install_scripts: &old_install_scripts,
        old_backup_md5: &old_backup_md5,
        hook_dirs: &db.config.hook_dirs,
    };

    execute_transaction(&tx, &ctx).map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("{total_count} package(s) installed successfully.");

    Ok(())
}

fn collect_old_install_scripts(
    db_path: &Path,
    tx: &Transaction,
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

fn collect_old_backup_md5(
    db_path: &Path,
    tx: &Transaction,
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
