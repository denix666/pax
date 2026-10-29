use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use pax_alpm::local::LocalDb;
use pax_core::package::{InstallReason, Validation};
use pax_resolver::pool::package_satisfies_dependency;
use pax_resolver::{RemovalReason, Transaction};

use crate::download::DownloadedPackage;
use crate::error::{ExecError, Result};
use crate::extract::{extract_package, read_archive_file_list, read_install_script, read_pkginfo};
use crate::hooks::{HookWhen, TransactionPackages, load_hooks, run_hooks};
use crate::log::PaxLogger;
use crate::register::{register_package, remove_db_entry};
use crate::removal::{RemovalTarget, remove_package, remove_package_paths};
use crate::scriptlet::{ScriptletOp, run_scriptlet};

pub struct InstallContext<'a> {
    pub root_dir: &'a Path,
    pub db_path: &'a Path,
    pub downloaded: &'a [DownloadedPackage],
    pub old_install_scripts: &'a HashMap<String, String>,
    pub old_backup_md5: &'a HashMap<String, HashMap<String, String>>,
    pub hook_dirs: &'a [PathBuf],
    pub check_space: bool,
    pub logger: &'a mut PaxLogger,
}

struct IncomingPackage<'a> {
    downloaded: &'a DownloadedPackage,
    files: Vec<String>,
    install_script: Option<String>,
}

pub fn execute_transaction(tx: &Transaction, ctx: &mut InstallContext) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(ExecError::NotRoot);
    }

    // Inspect every archive and action before hooks or any filesystem mutation.
    let incoming = prepare_incoming(tx, ctx.downloaded)?;
    for package in incoming.values() {
        crate::extract::validate_package_archive(&package.downloaded.path, ctx.root_dir)?;
    }
    for (name, version) in tx
        .upgrades
        .iter()
        .map(|action| (&action.name, &action.old_version))
        .chain(
            tx.removals
                .iter()
                .map(|action| (&action.name, &action.version)),
        )
    {
        crate::removal::validate_removal_paths(
            ctx.root_dir,
            &read_file_list(ctx.db_path, name, &version.to_string()),
        )?;
    }
    check_file_conflicts(ctx.root_dir, ctx.db_path, &incoming, tx)?;
    if ctx.check_space {
        check_disk_space(ctx.root_dir, ctx.db_path, tx)?;
    }
    let incoming_files: HashSet<String> = incoming
        .values()
        .flat_map(|pkg| pkg.files.iter().cloned())
        .collect();
    let old_files: HashSet<String> = tx
        .upgrades
        .iter()
        .flat_map(|upgrade| {
            read_file_list(ctx.db_path, &upgrade.name, &upgrade.old_version.to_string())
        })
        .chain(tx.removals.iter().flat_map(|removal| {
            read_file_list(ctx.db_path, &removal.name, &removal.version.to_string())
        }))
        .collect();
    let hook_packages = transaction_packages(tx, &old_files, &incoming_files);

    ctx.logger.log_transaction_start();
    run_transaction_hooks(ctx, &HookWhen::PreTransaction, &hook_packages)?;

    // Replacements/conflicts must leave the filesystem before incoming packages arrive.
    for removal in &tx.removals {
        if let RemovalReason::Conflict { with } = &removal.reason {
            eprintln!(
                "warning: removing {} (conflicts with {})",
                removal.name, with
            );
        }
        let version = removal.version.to_string();
        remove_package(
            &RemovalTarget {
                name: removal.name.clone(),
                version: version.clone(),
            },
            ctx.root_dir,
            ctx.db_path,
            ctx.logger,
        )?;
        ctx.logger.log_removed(&removal.name, &version);
    }

    for name in &tx.package_order {
        let package = &incoming[name.as_str()];
        if let Some(upgrade) = tx.upgrades.iter().find(|upgrade| &upgrade.name == name) {
            let old_version = upgrade.old_version.to_string();
            let new_version = upgrade.new_version.to_string();
            let reason = get_existing_reason(ctx.db_path, name, &old_version);
            if let Some(script) = &package.install_script {
                run_scriptlet(
                    script,
                    ScriptletOp::PreUpgrade,
                    &new_version,
                    Some(&old_version),
                    ctx.root_dir,
                    name,
                    ctx.logger,
                )?;
            }

            let old_entry = ctx
                .db_path
                .join("local")
                .join(format!("{name}-{old_version}"));
            // Retain paths taken over by any incoming package, irrespective of execution order.
            remove_package_paths(&old_entry, ctx.root_dir, &incoming_files)?;
            let backup_md5 = ctx.old_backup_md5.get(name).cloned().unwrap_or_default();
            let metadata = extract_package(&package.downloaded.path, ctx.root_dir, &backup_md5)?;
            for warning in &metadata.warnings {
                ctx.logger.log_warning(warning);
            }
            register_package(
                ctx.db_path,
                &metadata,
                reason,
                &[Validation::Sha256],
                ctx.root_dir,
            )?;
            if old_version != new_version {
                remove_db_entry(ctx.db_path, name, &old_version)?;
            }
            ctx.logger.log_upgraded(name, &old_version, &new_version);
            if let Some(script) = &metadata.install {
                run_scriptlet(
                    script,
                    ScriptletOp::PostUpgrade,
                    &new_version,
                    Some(&old_version),
                    ctx.root_dir,
                    name,
                    ctx.logger,
                )?;
            }
        } else if let Some(install) = tx.installs.iter().find(|install| &install.name == name) {
            let version = install.version.to_string();
            if let Some(script) = &package.install_script {
                run_scriptlet(
                    script,
                    ScriptletOp::PreInstall,
                    &version,
                    None,
                    ctx.root_dir,
                    name,
                    ctx.logger,
                )?;
            }
            let metadata =
                extract_package(&package.downloaded.path, ctx.root_dir, &HashMap::new())?;
            for warning in &metadata.warnings {
                ctx.logger.log_warning(warning);
            }
            let reason = if install.explicit {
                InstallReason::Explicit
            } else {
                InstallReason::Dependency
            };
            register_package(
                ctx.db_path,
                &metadata,
                reason,
                &[Validation::Sha256],
                ctx.root_dir,
            )?;
            ctx.logger.log_installed(name, &version);
            if let Some(script) = &metadata.install {
                run_scriptlet(
                    script,
                    ScriptletOp::PostInstall,
                    &version,
                    None,
                    ctx.root_dir,
                    name,
                    ctx.logger,
                )?;
            }
        }
    }

    ctx.logger.log_transaction_completed();
    // Reload hook definitions so hooks installed or removed by this transaction take effect.
    run_transaction_hooks(ctx, &HookWhen::PostTransaction, &hook_packages)?;
    Ok(())
}

fn invalid_transaction(message: impl Into<String>) -> ExecError {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into()).into()
}

fn prepare_incoming<'a>(
    tx: &Transaction,
    downloaded: &'a [DownloadedPackage],
) -> Result<HashMap<&'a str, IncomingPackage<'a>>> {
    let mut expected = HashMap::new();
    for (name, version) in tx
        .installs
        .iter()
        .map(|action| (&action.name, &action.version))
        .chain(
            tx.upgrades
                .iter()
                .map(|action| (&action.name, &action.new_version)),
        )
    {
        if expected
            .insert(name.as_str(), version.to_string())
            .is_some()
        {
            return Err(invalid_transaction(format!(
                "duplicate incoming action: {name}"
            )));
        }
    }
    let mut ordered = HashSet::new();
    for name in &tx.package_order {
        if !expected.contains_key(name.as_str()) || !ordered.insert(name.as_str()) {
            return Err(invalid_transaction(format!(
                "invalid package order entry: {name}"
            )));
        }
    }
    if ordered.len() != expected.len() {
        return Err(invalid_transaction(
            "package order does not contain every incoming action",
        ));
    }

    let mut incoming = HashMap::new();
    for package in downloaded {
        let version = expected.get(package.name.as_str()).ok_or_else(|| {
            invalid_transaction(format!("unexpected downloaded package: {}", package.name))
        })?;
        let metadata = read_pkginfo(&package.path)?;
        if metadata.name != package.name || &metadata.version != version {
            return Err(invalid_transaction(format!(
                "archive identity mismatch for {}: expected {} {}, found {} {}",
                package.path.display(),
                package.name,
                version,
                metadata.name,
                metadata.version,
            )));
        }
        let prepared = IncomingPackage {
            downloaded: package,
            files: read_archive_file_list(&package.path)?,
            install_script: read_install_script(&package.path)?,
        };
        if incoming.insert(package.name.as_str(), prepared).is_some() {
            return Err(invalid_transaction(format!(
                "duplicate download: {}",
                package.name
            )));
        }
    }
    for name in expected.keys() {
        if !incoming.contains_key(name) {
            return Err(ExecError::Download {
                pkg: (*name).to_string(),
                message: "missing downloaded archive for transaction action".to_string(),
            });
        }
    }
    Ok(incoming)
}

fn transaction_packages(
    tx: &Transaction,
    old_files: &HashSet<String>,
    incoming_files: &HashSet<String>,
) -> TransactionPackages {
    let mut installed_files: Vec<_> = incoming_files.difference(old_files).cloned().collect();
    let mut upgraded_files: Vec<_> = incoming_files.intersection(old_files).cloned().collect();
    let mut removed_files: Vec<_> = old_files.difference(incoming_files).cloned().collect();
    installed_files.sort();
    upgraded_files.sort();
    removed_files.sort();
    TransactionPackages {
        installed: tx
            .installs
            .iter()
            .map(|action| action.name.clone())
            .collect(),
        upgraded: tx
            .upgrades
            .iter()
            .map(|action| action.name.clone())
            .collect(),
        removed: tx
            .removals
            .iter()
            .map(|action| action.name.clone())
            .collect(),
        installed_files,
        upgraded_files,
        removed_files,
    }
}

fn run_transaction_hooks(
    ctx: &mut InstallContext,
    when: &HookWhen,
    packages: &TransactionPackages,
) -> Result<()> {
    let hooks = load_hooks(ctx.hook_dirs);
    let local = LocalDb::open(ctx.db_path)?;
    run_hooks(
        &hooks,
        when,
        packages,
        ctx.root_dir,
        &|dependency| {
            local
                .packages()
                .any(|pkg| package_satisfies_dependency(&pkg.info, dependency))
        },
        ctx.logger,
    )
}

fn read_file_list(db_path: &Path, name: &str, version: &str) -> Vec<String> {
    let files_path = db_path
        .join("local")
        .join(format!("{name}-{version}"))
        .join("files");
    let Ok(content) = std::fs::read_to_string(&files_path) else {
        return Vec::new();
    };
    parse_file_list(&content)
}

fn parse_file_list(content: &str) -> Vec<String> {
    let mut files = Vec::new();
    let mut in_files = false;
    for line in content.lines() {
        if line == "%FILES%" {
            in_files = true;
        } else if line.starts_with('%') || line.is_empty() {
            in_files = false;
        } else if in_files {
            files.push(line.to_string());
        }
    }
    files
}

fn check_disk_space(root_dir: &Path, db_path: &Path, tx: &Transaction) -> Result<()> {
    let total_new: u64 = tx
        .installs
        .iter()
        .map(|i| i.installed_size)
        .chain(tx.upgrades.iter().map(|u| u.installed_size))
        .sum();
    let freed: u64 = tx
        .upgrades
        .iter()
        .filter_map(|u| read_old_installed_size(db_path, &u.name, &u.old_version.to_string()))
        .sum();
    let needed = total_new.saturating_sub(freed);
    if needed == 0 {
        return Ok(());
    }
    let c_path = match std::ffi::CString::new(root_dir.to_string_lossy().as_bytes()) {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return Ok(());
    }
    let available = stat.f_bavail as u64 * stat.f_frsize as u64;
    if available < needed {
        return Err(ExecError::InsufficientSpace {
            needed: needed / (1024 * 1024),
            available: available / (1024 * 1024),
            path: root_dir.display().to_string(),
        });
    }
    Ok(())
}

fn check_file_conflicts(
    root_dir: &Path,
    db_path: &Path,
    incoming: &HashMap<&str, IncomingPackage<'_>>,
    tx: &Transaction,
) -> Result<()> {
    let mut old_owners: HashMap<String, Vec<(String, bool)>> = HashMap::new();
    let local_dir = db_path.join("local");
    match std::fs::read_dir(&local_dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let content = std::fs::read_to_string(entry.path().join("desc"))?;
                let Some(name) = parse_name_from_desc(&content) else {
                    continue;
                };
                let content = std::fs::read_to_string(entry.path().join("files"))?;
                for file in parse_file_list(&content) {
                    old_owners
                        .entry(file.trim_end_matches('/').to_string())
                        .or_default()
                        .push((name.clone(), file.ends_with('/')));
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let changing: HashSet<_> = tx
        .upgrades
        .iter()
        .map(|action| action.name.as_str())
        .chain(tx.removals.iter().map(|action| action.name.as_str()))
        .collect();
    let mut incoming_owners: HashMap<&str, (&str, bool)> = HashMap::new();
    let mut conflicts = Vec::new();
    for (name, package) in incoming {
        for file in &package.files {
            let directory = file.ends_with('/');
            let path = file.trim_end_matches('/');
            if let Some((owner, other_directory)) = incoming_owners.get(path) {
                if !(directory && *other_directory) {
                    conflicts.push(format!("  {name}: /{path} also supplied by {owner}"));
                }
            } else {
                incoming_owners.insert(path, (*name, directory));
            }
            let owners = old_owners.get(path);
            if let Some(owners) = owners {
                for (owner, old_directory) in owners {
                    if !changing.contains(owner.as_str()) && !(directory && *old_directory) {
                        conflicts.push(format!("  {name}: /{path} already owned by {owner}"));
                    }
                }
            }
            match std::fs::symlink_metadata(root_dir.join(path)) {
                Ok(metadata) => {
                    if directory && metadata.is_dir() {
                        continue;
                    }
                    let vacated = owners.is_some_and(|owners| {
                        owners
                            .iter()
                            .all(|(owner, _)| changing.contains(owner.as_str()))
                    });
                    if !vacated {
                        conflicts.push(format!("  {name}: /{path} already exists in filesystem"));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    // Also catch a file from one archive used as a parent directory by another.
    for (path, (name, _)) in &incoming_owners {
        let mut parent = Path::new(path).parent();
        while let Some(directory) = parent {
            if let Some((owner, false)) = directory
                .to_str()
                .and_then(|path| incoming_owners.get(path))
            {
                conflicts.push(format!(
                    "  {name}: /{path} has non-directory parent supplied by {owner}"
                ));
            }
            parent = directory.parent();
        }
    }
    conflicts.sort();
    conflicts.dedup();
    if conflicts.is_empty() {
        Ok(())
    } else {
        Err(ExecError::FileConflict(conflicts.join("\n")))
    }
}

fn read_old_installed_size(db_path: &Path, name: &str, version: &str) -> Option<u64> {
    let desc_path = db_path
        .join("local")
        .join(format!("{name}-{version}"))
        .join("desc");
    let content = std::fs::read_to_string(&desc_path).ok()?;
    let mut found = false;
    for line in content.lines() {
        if line == "%SIZE%" {
            found = true;
        } else if found {
            return line.parse().ok();
        }
    }
    None
}

fn parse_name_from_desc(content: &str) -> Option<String> {
    content
        .lines()
        .skip_while(|line| *line != "%NAME%")
        .nth(1)
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pax_core::version::Version;
    use pax_resolver::{InstallAction, UpgradeAction};

    fn transaction(names: &[&str]) -> Transaction {
        Transaction {
            installs: names
                .iter()
                .map(|name| InstallAction {
                    name: (*name).into(),
                    version: Version::parse("1-1").unwrap(),
                    repository: "test".into(),
                    download_size: 0,
                    installed_size: 0,
                    explicit: true,
                })
                .collect(),
            upgrades: vec![],
            removals: vec![],
            package_order: names.iter().map(|name| (*name).into()).collect(),
            total_download_size: 0,
            total_installed_size: 0,
        }
    }

    fn archive(dir: &Path, label: &str, name: &str, version: &str) -> DownloadedPackage {
        let path = dir.join(format!("{label}.pkg.tar"));
        let mut builder = tar::Builder::new(std::fs::File::create(&path).unwrap());
        let info = format!("pkgname = {name}\npkgver = {version}\narch = any\n");
        for (path, contents) in [
            (".PKGINFO", info.as_bytes()),
            ("file", b"contents".as_slice()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        }
        builder.finish().unwrap();
        DownloadedPackage {
            name: label.into(),
            path,
        }
    }

    #[test]
    fn validates_every_archive_and_requires_every_download() {
        let temp = tempfile::tempdir().unwrap();
        let tx = transaction(&["first", "second"]);
        let first = archive(temp.path(), "first", "first", "1-1");
        let wrong_name = archive(temp.path(), "second", "unexpected", "1-1");
        assert!(prepare_incoming(&tx, &[first, wrong_name]).is_err());
        let first = archive(temp.path(), "first", "first", "1-1");
        let wrong_version = archive(temp.path(), "second", "second", "2-1");
        assert!(prepare_incoming(&tx, &[first, wrong_version]).is_err());
        let first = archive(temp.path(), "first", "first", "1-1");
        assert!(matches!(
            prepare_incoming(&tx, &[first]),
            Err(ExecError::Download { .. })
        ));
    }

    #[test]
    fn replacement_removal_saves_backup_before_installing_new_file() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        std::fs::create_dir_all(&root).unwrap();
        let old = db.join("local/obsolete-1-1");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("desc"), "%NAME%\nobsolete\n\n%VERSION%\n1-1\n\n").unwrap();
        let baseline = format!("{:x}", md5::compute("original"));
        std::fs::write(
            old.join("files"),
            format!("%FILES%\nfile\n\n%BACKUP%\nfile\t{baseline}\n\n"),
        )
        .unwrap();
        std::fs::write(root.join("file"), "local changes").unwrap();
        let downloaded = [archive(temp.path(), "replacement", "replacement", "1-1")];
        let mut tx = transaction(&["replacement"]);
        tx.removals.push(pax_resolver::RemovalAction {
            name: "obsolete".into(),
            version: Version::parse("1-1").unwrap(),
            reason: RemovalReason::Replaced,
        });
        let empty = HashMap::new();
        let backups = HashMap::new();
        let mut logger = PaxLogger::none();
        let mut ctx = InstallContext {
            root_dir: &root,
            db_path: &db,
            downloaded: &downloaded,
            old_install_scripts: &empty,
            old_backup_md5: &backups,
            hook_dirs: &[],
            check_space: false,
            logger: &mut logger,
        };
        execute_transaction(&tx, &mut ctx).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("file")).unwrap(),
            "contents"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("file.pacsave")).unwrap(),
            "local changes"
        );
        assert!(!old.exists());
        assert!(db.join("local/replacement-1-1/desc").exists());
    }

    #[test]
    fn rejects_incomplete_or_duplicate_execution_order() {
        let mut tx = transaction(&["first", "second"]);
        tx.package_order.pop();
        assert!(prepare_incoming(&tx, &[]).is_err());
        tx.package_order = vec!["first".into(), "first".into()];
        assert!(prepare_incoming(&tx, &[]).is_err());
    }

    #[test]
    fn hook_paths_follow_global_lifecycle_including_directories() {
        let tx = transaction(&["replacement"]);
        let old = HashSet::from(["etc/".into(), "etc/shared".into(), "etc/obsolete".into()]);
        let incoming = HashSet::from(["etc/".into(), "etc/shared".into(), "etc/new".into()]);
        let events = transaction_packages(&tx, &old, &incoming);
        assert_eq!(events.installed_files, ["etc/new"]);
        assert_eq!(events.upgraded_files, ["etc/", "etc/shared"]);
        assert_eq!(events.removed_files, ["etc/obsolete"]);
    }

    #[test]
    fn detects_unowned_files_and_incoming_collisions_but_allows_shared_directories() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        std::fs::create_dir_all(root.join("shared")).unwrap();
        std::fs::create_dir_all(db.join("local")).unwrap();
        let first = DownloadedPackage {
            name: "first".into(),
            path: PathBuf::new(),
        };
        let second = DownloadedPackage {
            name: "second".into(),
            path: PathBuf::new(),
        };
        let mut incoming = HashMap::from([
            (
                "first",
                IncomingPackage {
                    downloaded: &first,
                    files: vec!["shared/".into()],
                    install_script: None,
                },
            ),
            (
                "second",
                IncomingPackage {
                    downloaded: &second,
                    files: vec!["shared/".into()],
                    install_script: None,
                },
            ),
        ]);
        let tx = transaction(&["first", "second"]);
        assert!(check_file_conflicts(&root, &db, &incoming, &tx).is_ok());
        incoming
            .get_mut("first")
            .unwrap()
            .files
            .push("unowned".into());
        std::fs::write(root.join("unowned"), "keep").unwrap();
        assert!(check_file_conflicts(&root, &db, &incoming, &tx).is_err());
        std::fs::remove_file(root.join("unowned")).unwrap();
        incoming
            .get_mut("second")
            .unwrap()
            .files
            .push("unowned".into());
        assert!(check_file_conflicts(&root, &db, &incoming, &tx).is_err());
    }

    #[test]
    fn ownership_transfer_allowed_only_when_old_owner_leaves_final_state() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        std::fs::create_dir_all(&root).unwrap();
        let entry = db.join("local/old-1-1");
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("desc"), "%NAME%\nold\n\n").unwrap();
        std::fs::write(entry.join("files"), "%FILES%\nshared\n\n").unwrap();
        std::fs::write(root.join("shared"), "old").unwrap();
        let new = DownloadedPackage {
            name: "new".into(),
            path: PathBuf::new(),
        };
        let old = DownloadedPackage {
            name: "old".into(),
            path: PathBuf::new(),
        };
        let mut incoming = HashMap::from([
            (
                "new",
                IncomingPackage {
                    downloaded: &new,
                    files: vec!["shared".into()],
                    install_script: None,
                },
            ),
            (
                "old",
                IncomingPackage {
                    downloaded: &old,
                    files: vec![],
                    install_script: None,
                },
            ),
        ]);
        let mut tx = transaction(&["new"]);
        assert!(check_file_conflicts(&root, &db, &incoming, &tx).is_err());
        tx.upgrades.push(UpgradeAction {
            name: "old".into(),
            old_version: Version::parse("1-1").unwrap(),
            new_version: Version::parse("2-1").unwrap(),
            repository: "test".into(),
            download_size: 0,
            installed_size: 0,
        });
        tx.package_order.push("old".into());
        assert!(check_file_conflicts(&root, &db, &incoming, &tx).is_ok());
        incoming.get_mut("old").unwrap().files.push("shared".into());
        assert!(check_file_conflicts(&root, &db, &incoming, &tx).is_err());
    }
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
