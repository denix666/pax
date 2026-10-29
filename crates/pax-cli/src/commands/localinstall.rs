use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::Result;
use pax_alpm::db::DatabaseHandle;
use pax_exec::{DownloadedPackage, InstallContext, execute_transaction, read_pkginfo};
use pax_resolver::{ConcretePool, ResolveOptions, build_transaction, resolve, topological_sort};

use super::{collect_old_backup_md5, collect_old_install_scripts, confirm};
use crate::output::print_transaction;

pub fn run(db: &mut DatabaseHandle, files: &[PathBuf], noconfirm: bool) -> Result<()> {
    install_files(db, files, !noconfirm)
}

/// Also used by AUR installation, so locking and validation belong in this entry point.
pub fn install_pkg_files(db: &mut DatabaseHandle, files: &[PathBuf]) -> Result<()> {
    install_files(db, files, false)
}

fn validate_architecture(package: &str, arch: &str, configured: &str) -> Result<()> {
    let expected = if configured.is_empty() || configured == "auto" {
        std::env::consts::ARCH
    } else {
        configured
    };
    if arch != "any" && arch != expected {
        anyhow::bail!("{package}: architecture {arch} is incompatible with {expected}");
    }
    Ok(())
}

fn install_files(db: &mut DatabaseHandle, files: &[PathBuf], ask_confirmation: bool) -> Result<()> {
    super::ensure_root();
    if files.is_empty() {
        anyhow::bail!("no targets specified");
    }

    let _lock = pax_alpm::DbLock::acquire(&db.config.db_path)
        .map_err(|e| anyhow::anyhow!("failed to acquire db lock: {e}"))?;
    db.invalidate();
    let mut pool = ConcretePool::new(HashSet::new());
    for pkg in db.installed_packages()? {
        pool.add_local(pkg.info.clone());
    }

    let mut downloaded = Vec::with_capacity(files.len());
    let mut targets = Vec::with_capacity(files.len());
    let mut sizes = HashMap::with_capacity(files.len());
    let policy = db.config.local_file_sig_level;
    for file in files {
        let canonical = file
            .canonicalize()
            .map_err(|e| anyhow::anyhow!("{}: {e}", file.display()))?;
        let mut signature = file.as_os_str().to_os_string();
        signature.push(".sig");
        let signature = PathBuf::from(signature);
        let signature = match std::fs::symlink_metadata(&signature) {
            Ok(_) => Some(signature),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        pax_exec::verify::verify_signature(
            &canonical,
            signature.as_deref(),
            &db.config.gpg_dir,
            policy.package,
            policy.package_trust,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;

        let metadata = read_pkginfo(&canonical).map_err(|e| anyhow::anyhow!("{e}"))?;
        let info = metadata.info;
        validate_architecture(&info.name, &info.arch, &db.config.architecture)?;
        if sizes
            .insert(
                info.name.clone(),
                (0, metadata.installed_size, "local".to_string()),
            )
            .is_some()
        {
            anyhow::bail!("multiple incoming files for package {}", info.name);
        }
        targets.push(info.name.clone());
        downloaded.push(DownloadedPackage {
            name: info.name.clone(),
            path: canonical,
        });
        pool.add_sync(info, 0);
    }

    let mut resolved = resolve(
        &pool,
        &targets,
        &ResolveOptions {
            reinstall: true,
            apply_replacements: false,
        },
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    topological_sort(&pool, &mut resolved);
    let mut tx = build_transaction(
        &pool,
        &resolved,
        &targets,
        &|name| {
            sizes
                .get(name)
                .map(|(_, size, _)| (0, *size))
                .unwrap_or((0, 0))
        },
        true,
    );
    for install in &mut tx.installs {
        install.repository = "local".to_string();
    }
    for upgrade in &mut tx.upgrades {
        upgrade.repository = "local".to_string();
    }
    if tx.is_empty() {
        return Ok(());
    }
    print_transaction(&tx, &sizes);
    if ask_confirmation && !confirm("\nProceed with installation? [Y/n]")? {
        println!("Installation cancelled.");
        return Ok(());
    }

    let old_install_scripts = collect_old_install_scripts(&db.config.db_path, &tx);
    let old_backup_md5 = collect_old_backup_md5(&db.config.db_path, &tx);
    let mut logger = pax_exec::PaxLogger::open(&db.config.log_file);
    let mut ctx = InstallContext {
        root_dir: &db.config.root_dir,
        db_path: &db.config.db_path,
        downloaded: &downloaded,
        old_install_scripts: &old_install_scripts,
        old_backup_md5: &old_backup_md5,
        hook_dirs: &db.config.hook_dirs,
        check_space: db.config.check_space,
        logger: &mut logger,
    };
    let result = execute_transaction(&tx, &mut ctx);
    db.invalidate();
    result.map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "{} package(s) installed successfully.",
        tx.installs.len() + tx.upgrades.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_architecture;

    #[test]
    fn local_architecture_accepts_any_and_configured_architecture() {
        assert!(validate_architecture("app", "any", "aarch64").is_ok());
        assert!(validate_architecture("app", "aarch64", "aarch64").is_ok());
        assert!(validate_architecture("app", "x86_64", "aarch64").is_err());
        assert!(validate_architecture("app", "", "aarch64").is_err());
    }
}
