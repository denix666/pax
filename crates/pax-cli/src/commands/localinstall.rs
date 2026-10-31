use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::Result;
use pax_alpm::db::DatabaseHandle;
use pax_core::config::SigConfig;
use pax_core::version::Version;
use pax_exec::{DownloadedPackage, InstallContext, execute_transaction, read_pkginfo};
use pax_resolver::{ConcretePool, ResolveOptions, build_transaction, resolve, topological_sort};

use super::{collect_old_backup_md5, collect_old_install_scripts, confirm};
use crate::output::print_transaction;

pub fn run(db: &mut DatabaseHandle, files: &[PathBuf], noconfirm: bool) -> Result<()> {
    install_files(db, files, !noconfirm, None).map(|_| ())
}

/// Also used by AUR installation, so locking and validation belong in this entry point.
pub fn install_pkg_files(db: &mut DatabaseHandle, files: &[PathBuf]) -> Result<()> {
    install_files(db, files, false, None).map(|_| ())
}

pub struct DowngradeFile {
    pub path: PathBuf,
    pub name: String,
    pub version: Version,
    pub installed_version: Version,
    pub policy: SigConfig,
}

/// Returns false when confirmation is declined. The database lock is released on return,
/// so callers updating IgnorePkg after success must acquire the config writer lock separately.
pub fn install_downgrade_files(
    db: &mut DatabaseHandle,
    files: &[DowngradeFile],
    noconfirm: bool,
) -> Result<bool> {
    let paths: Vec<_> = files.iter().map(|file| file.path.clone()).collect();
    install_files(db, &paths, !noconfirm, Some(files))
}

fn validate_downgrade(file: &DowngradeFile, installed: Option<&Version>) -> Result<()> {
    let installed = installed
        .ok_or_else(|| anyhow::anyhow!("{}: package is no longer installed", file.name))?;
    if installed != &file.installed_version {
        anyhow::bail!(
            "{}: installed version changed from {} to {}; select the downgrade again",
            file.name,
            file.installed_version,
            installed
        );
    }
    if file.version >= *installed {
        anyhow::bail!(
            "{}: selected version {} is not older than installed version {}",
            file.name,
            file.version,
            installed
        );
    }
    Ok(())
}

fn validate_downgrade_archive(file: &DowngradeFile, name: &str, version: &Version) -> Result<()> {
    if name != file.name || version != &file.version {
        anyhow::bail!(
            "{}: archive contains {} {}, expected {} {}",
            file.path.display(),
            name,
            version,
            file.name,
            file.version
        );
    }
    Ok(())
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

fn install_files(
    db: &mut DatabaseHandle,
    files: &[PathBuf],
    ask_confirmation: bool,
    downgrades: Option<&[DowngradeFile]>,
) -> Result<bool> {
    super::ensure_root();
    if files.is_empty() {
        anyhow::bail!("no targets specified");
    }

    let _lock = pax_alpm::DbLock::acquire(&db.config.db_path)
        .map_err(|e| anyhow::anyhow!("failed to acquire db lock: {e}"))?;
    db.invalidate();
    if let Some(downgrades) = downgrades {
        for file in downgrades {
            validate_downgrade(
                file,
                db.local_info(&file.name)?.map(|pkg| &pkg.info.version),
            )?;
        }
    }
    let mut pool = ConcretePool::new(HashSet::new());
    for pkg in db.installed_packages()? {
        pool.add_local(pkg.info.clone());
    }

    let mut downloaded = Vec::with_capacity(files.len());
    let mut targets = Vec::with_capacity(files.len());
    let mut sizes = HashMap::with_capacity(files.len());
    for (index, file) in files.iter().enumerate() {
        let downgrade = downgrades.map(|files| &files[index]);
        let policy = downgrade
            .map(|file| file.policy)
            .unwrap_or(db.config.local_file_sig_level);
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
        if let Some(downgrade) = downgrade {
            validate_downgrade_archive(downgrade, &info.name, &info.version)?;
        }
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
        return Ok(true);
    }
    print_transaction(&tx, &sizes);
    if ask_confirmation && !confirm("\nProceed with installation? [Y/n]")? {
        println!("Installation cancelled.");
        return Ok(false);
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
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn downgrade() -> DowngradeFile {
        DowngradeFile {
            path: PathBuf::from("app-1-1-any.pkg.tar.zst"),
            name: "app".into(),
            version: Version::parse("1-1").unwrap(),
            installed_version: Version::parse("2-1").unwrap(),
            policy: SigConfig::default(),
        }
    }

    #[test]
    fn downgrade_rejects_removed_or_changed_installed_package() {
        let file = downgrade();
        assert!(validate_downgrade(&file, Some(&file.installed_version)).is_ok());
        assert!(validate_downgrade(&file, None).is_err());
        for version in ["1-1", "3-1"] {
            let changed = Version::parse(version).unwrap();
            let error = validate_downgrade(&file, Some(&changed)).unwrap_err();
            assert!(error.to_string().contains("installed version changed"));
        }
    }

    #[test]
    fn downgrade_requires_strictly_older_version_including_epoch_and_release() {
        for (selected, installed, valid) in [
            ("1-1", "2-1", true),
            ("2-1", "2-2", true),
            ("9-1", "1:1-1", true),
            ("2-1", "2-1", false),
            ("2-2", "2-1", false),
            ("1:1-1", "9-1", false),
        ] {
            let mut file = downgrade();
            file.version = Version::parse(selected).unwrap();
            file.installed_version = Version::parse(installed).unwrap();
            assert_eq!(
                validate_downgrade(&file, Some(&file.installed_version)).is_ok(),
                valid,
                "{selected} against {installed}"
            );
        }
    }

    #[test]
    fn downgrade_archive_must_match_selected_name_and_version() {
        let file = downgrade();
        assert!(validate_downgrade_archive(&file, "app", &file.version).is_ok());
        assert!(validate_downgrade_archive(&file, "other", &file.version).is_err());
        assert!(validate_downgrade_archive(&file, "app", &file.installed_version).is_err());
    }

    #[test]
    fn multiple_downgrades_resolve_together_in_dependency_order() {
        use pax_alpm::desc::{desc_to_package_info, parse_desc};

        let mut pool = ConcretePool::new(HashSet::new());
        let mut targets = Vec::new();
        for (name, depends) in [("app", "%DEPENDS%\nlib=1-1\n\n"), ("lib", "")] {
            for version in ["2-1", "1-1"] {
                let desc =
                    format!("%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%ARCH%\nany\n\n{depends}");
                let info = desc_to_package_info(&parse_desc(&desc)).unwrap();
                if version == "2-1" {
                    pool.add_local(info);
                } else {
                    pool.add_sync(info, 0);
                }
            }
            targets.push(name.to_string());
        }
        let mut resolved = resolve(
            &pool,
            &targets,
            &ResolveOptions {
                reinstall: true,
                apply_replacements: false,
            },
        )
        .unwrap();
        topological_sort(&pool, &mut resolved);
        let tx = build_transaction(&pool, &resolved, &targets, &|_| (0, 0), true);
        assert!(tx.installs.is_empty());
        assert!(tx.removals.is_empty());
        assert_eq!(tx.upgrades.len(), 2);
        assert_eq!(tx.package_order, ["lib", "app"]);
        assert!(
            tx.upgrades
                .iter()
                .all(|action| action.new_version < action.old_version)
        );
    }

    #[test]
    fn local_architecture_accepts_any_and_configured_architecture() {
        assert!(validate_architecture("app", "any", "aarch64").is_ok());
        assert!(validate_architecture("app", "aarch64", "aarch64").is_ok());
        assert!(validate_architecture("app", "x86_64", "aarch64").is_err());
        assert!(validate_architecture("app", "", "aarch64").is_err());
    }
}
