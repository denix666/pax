use std::path::PathBuf;

use anyhow::Result;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;
use pax_core::version::Version;
use pax_exec::{execute_transaction, read_pkginfo, DownloadedPackage, InstallContext};
use pax_resolver::{InstallAction, Transaction, UpgradeAction};

use super::{collect_old_backup_md5, collect_old_install_scripts, confirm};

pub fn run(db: &mut DatabaseHandle, files: &[PathBuf], noconfirm: bool) -> Result<()> {
    super::ensure_root();

    let _lock = pax_alpm::DbLock::acquire(&db.config.db_path)
        .map_err(|e| anyhow::anyhow!("failed to acquire db lock: {e}"))?;

    if files.is_empty() {
        anyhow::bail!("no targets specified");
    }

    for file in files {
        if !file.exists() {
            anyhow::bail!("file not found: {}", file.display());
        }
    }

    db.local()?;

    let mut pkg_info_list = Vec::with_capacity(files.len());
    for file in files {
        let info = read_pkginfo(file).map_err(|e| anyhow::anyhow!("{e}"))?;
        let version = Version::parse(&info.version)
            .map_err(|e| anyhow::anyhow!("{}: invalid version: {e}", file.display()))?;
        let local_ver = db.local_info(&info.name)?.map(|p| p.info.version.clone());
        pkg_info_list.push((info, version, local_ver));
    }

    let mut install_count = 0usize;
    let mut upgrade_count = 0usize;

    for (info, version, local_ver) in &pkg_info_list {
        if let Some(old_ver) = local_ver {
            if upgrade_count == 0 {
                println!("\n{}", "Packages to upgrade:".bold());
            }
            println!(
                "  {}/{} {} -> {}",
                "local".purple(),
                info.name.bold(),
                old_ver.red(),
                version.green(),
            );
            upgrade_count += 1;
        } else {
            if install_count == 0 {
                println!("\n{}", "Packages to install:".bold());
            }
            println!(
                "  {}/{} {}",
                "local".purple(),
                info.name.bold(),
                version.green(),
            );
            install_count += 1;
        }
    }

    let total_count = install_count + upgrade_count;
    println!("\nTotal packages: {}", total_count.to_string().bold());

    if !noconfirm && !confirm("\nProceed with installation? [Y/n]")? {
        println!("Installation cancelled.");
        return Ok(());
    }

    install_pkg_files(db, files)?;

    println!("{total_count} package(s) installed successfully.");

    Ok(())
}

pub fn install_pkg_files(db: &mut DatabaseHandle, files: &[PathBuf]) -> Result<()> {
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
            total_installed_size += info.installed_size;
            upgrades.push(UpgradeAction {
                name: info.name.clone(),
                old_version,
                new_version: version,
                repository: "local".to_string(),
                download_size: 0,
                installed_size: info.installed_size,
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

    let tx = Transaction {
        installs,
        upgrades,
        removals: vec![],
        total_download_size: 0,
        total_installed_size,
    };

    if tx.is_empty() {
        return Ok(());
    }

    let old_install_scripts = collect_old_install_scripts(&db.config.db_path, &tx);
    let old_backup_md5 = collect_old_backup_md5(&db.config.db_path, &tx);

    let ctx = InstallContext {
        root_dir: &db.config.root_dir,
        db_path: &db.config.db_path,
        downloaded: &downloaded,
        old_install_scripts: &old_install_scripts,
        old_backup_md5: &old_backup_md5,
        hook_dirs: &db.config.hook_dirs,
        check_space: db.config.check_space,
    };

    execute_transaction(&tx, &ctx).map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(())
}

