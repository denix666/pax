use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use pax_alpm::local::LocalDb;
use pax_core::package::{InstallReason, PackageInfo, Validation};
use pax_resolver::pool::package_satisfies_dependency;
use pax_resolver::{ExecutionStep, RemovalReason, Transaction, execution_plan};

use crate::download::DownloadedPackage;
use crate::error::{ExecError, Result};
use crate::extract::{extract_package, read_archive_file_list, read_install_script, read_pkginfo};
use crate::hooks::{HookWhen, TransactionPackages, load_hooks, run_hooks};
use crate::journal::{Journal, Phase};
use crate::log::PaxLogger;
use crate::register::{register_package, remove_db_entry};
use crate::removal::{RemovalTarget, remove_package_paths, remove_package_recorded};
use crate::scriptlet::{ScriptletOp, run_scriptlet};

pub struct InstallContext<'a> {
    pub root_dir: &'a Path,
    pub db_path: &'a Path,
    pub architecture: &'a str,
    pub downloaded: &'a [DownloadedPackage],
    pub old_install_scripts: &'a HashMap<String, String>,
    pub old_backup_md5: &'a HashMap<String, HashMap<String, String>>,
    pub hook_dirs: &'a [PathBuf],
    pub check_space: bool,
    pub logger: &'a mut PaxLogger,
}

struct IncomingPackage<'a> {
    downloaded: &'a DownloadedPackage,
    info: PackageInfo,
    files: Vec<String>,
    install_script: Option<String>,
}

pub fn execute_transaction(tx: &Transaction, ctx: &mut InstallContext) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(ExecError::NotRoot);
    }

    pax_alpm::lock::ensure_no_active_transaction(ctx.db_path)?;
    // Inspect every archive and action before hooks or any filesystem mutation.
    eprintln!(":: Verifying transaction archives and destinations...");
    for (index, package) in ctx.downloaded.iter().enumerate() {
        eprintln!(
            ":: Checking archive {}/{}: {}",
            index + 1,
            ctx.downloaded.len(),
            package.name
        );
        crate::preflight::validate_archive(&package.path, ctx.root_dir, Some(ctx.architecture))?;
    }
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
            &read_file_list(ctx.db_path, name, &version.to_string())?,
        )?;
    }
    let installed = read_installed_snapshot(ctx.db_path)?;
    let incoming_info: Vec<_> = incoming.values().map(|pkg| pkg.info.clone()).collect();
    let steps = execution_plan(tx, &installed, &incoming_info)?;
    let retained_directories =
        check_file_conflicts(ctx.root_dir, ctx.db_path, &incoming, tx, &steps)?;
    if ctx.check_space {
        check_disk_space(ctx.root_dir, ctx.db_path, tx)?;
    }
    let incoming_files: HashSet<String> = incoming
        .values()
        .flat_map(|pkg| pkg.files.iter().cloned())
        .collect();
    let mut old_files = HashSet::new();
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
        old_files.extend(read_file_list(ctx.db_path, name, &version.to_string())?);
    }
    let mut hook_packages = transaction_packages(tx, &old_files, &incoming_files);
    hook_packages
        .removed_files
        .retain(|path| !retained_directories.contains(path.trim_end_matches('/')));

    let mut operations = Vec::new();
    for step in &steps {
        for name in &step.remove_before {
            let removal = tx
                .removals
                .iter()
                .find(|action| &action.name == name)
                .unwrap();
            let links: Vec<_> = removal
                .links
                .iter()
                .map(|link| format!("{:?} by {}", link.reason, link.incoming))
                .collect();
            operations.push(format!(
                "remove {name} {} ({})",
                removal.version,
                links.join(", ")
            ));
        }
        let name = &step.incoming;
        if let Some(upgrade) = tx.upgrades.iter().find(|action| &action.name == name) {
            operations.push(format!(
                "upgrade {name} {} -> {}",
                upgrade.old_version, upgrade.new_version
            ));
        } else {
            let install = tx
                .installs
                .iter()
                .find(|action| &action.name == name)
                .unwrap();
            operations.push(format!("install {name} {}", install.version));
        }
    }
    let mut journal = Journal::begin(ctx.db_path, ctx.root_dir, operations)?;
    ctx.logger.log_transaction_start();
    let result = apply_transaction(
        tx,
        ctx,
        &incoming,
        &incoming_files,
        &retained_directories,
        &steps,
        &hook_packages,
        &mut journal,
    );
    finish_transaction(result, &mut journal, ctx.db_path, ctx.logger)
}

#[allow(clippy::too_many_arguments)]
fn apply_transaction(
    tx: &Transaction,
    ctx: &mut InstallContext,
    incoming: &HashMap<&str, IncomingPackage<'_>>,
    incoming_files: &HashSet<String>,
    retained_directories: &HashSet<String>,
    steps: &[ExecutionStep],
    hook_packages: &TransactionPackages,
    journal: &mut Journal,
) -> Result<()> {
    let mut failures = Vec::new();
    run_recorded_hooks(
        ctx.root_dir,
        ctx.db_path,
        ctx.hook_dirs,
        &HookWhen::PreTransaction,
        hook_packages,
        ctx.logger,
        journal,
        &mut failures,
    )?;
    eprintln!(":: Applying package changes...");

    // Only retire packages belonging to this incoming slot. A failure must not
    // trigger removal of packages anchored to later, unrelated replacements.
    for step in steps {
        for name in &step.remove_before {
            let removal = tx
                .removals
                .iter()
                .find(|action| &action.name == name)
                .unwrap();
            for link in &removal.links {
                if link.reason == RemovalReason::Conflict {
                    eprintln!(
                        "warning: removing {} (conflicts with {})",
                        removal.name, link.incoming
                    );
                }
            }
            let version = removal.version.to_string();
            remove_package_recorded(
                &RemovalTarget {
                    name: name.clone(),
                    version: version.clone(),
                },
                ctx.root_dir,
                ctx.db_path,
                ctx.logger,
                journal,
                &mut failures,
                retained_directories,
            )?;
            ctx.logger.log_removed(name, &version);
        }
        let name = &step.incoming;
        let package = &incoming[name.as_str()];
        if let Some(upgrade) = tx.upgrades.iter().find(|upgrade| &upgrade.name == name) {
            let old_version = upgrade.old_version.to_string();
            let new_version = upgrade.new_version.to_string();
            let reason = get_existing_reason(ctx.db_path, name, &old_version);
            if let Some(script) = &package.install_script {
                run_recorded_scriptlet(
                    journal,
                    &mut failures,
                    "pre_upgrade",
                    script,
                    ScriptletOp::PreUpgrade,
                    &new_version,
                    Some(&old_version),
                    ctx.root_dir,
                    name,
                    ctx.logger,
                )?;
            }

            let mut retained_paths = incoming_files.clone();
            retained_paths.extend(retained_directories.iter().cloned());
            let old_entry = ctx
                .db_path
                .join("local")
                .join(format!("{name}-{old_version}"));
            // Retain paths taken over by any incoming package, irrespective of execution order.
            journal.step(
                Phase::Applying,
                &format!("{name}: remove obsolete paths from {}", old_entry.display()),
                || remove_package_paths(&old_entry, ctx.root_dir, &retained_paths),
            )?;
            let backup_md5 = ctx.old_backup_md5.get(name).cloned().unwrap_or_default();
            let metadata = journal.step(
                Phase::Applying,
                &format!("{name}: extract {}", package.downloaded.path.display()),
                || extract_package(&package.downloaded.path, ctx.root_dir, &backup_md5),
            )?;
            for warning in &metadata.warnings {
                ctx.logger.log_warning(warning);
            }
            journal.step(
                Phase::Applying,
                &format!("{name}: register {new_version}"),
                || {
                    register_package(
                        ctx.db_path,
                        &metadata,
                        reason,
                        &[Validation::Sha256],
                        ctx.root_dir,
                    )
                },
            )?;
            if old_version != new_version {
                journal.step(
                    Phase::Applying,
                    &format!("{name}: remove database entry {old_version}"),
                    || remove_db_entry(ctx.db_path, name, &old_version),
                )?;
            }
            ctx.logger.log_upgraded(name, &old_version, &new_version);
            if let Some(script) = &metadata.install {
                run_recorded_scriptlet(
                    journal,
                    &mut failures,
                    "post_upgrade",
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
                run_recorded_scriptlet(
                    journal,
                    &mut failures,
                    "pre_install",
                    script,
                    ScriptletOp::PreInstall,
                    &version,
                    None,
                    ctx.root_dir,
                    name,
                    ctx.logger,
                )?;
            }
            let metadata = journal.step(
                Phase::Applying,
                &format!("{name}: extract {}", package.downloaded.path.display()),
                || extract_package(&package.downloaded.path, ctx.root_dir, &HashMap::new()),
            )?;
            for warning in &metadata.warnings {
                ctx.logger.log_warning(warning);
            }
            let reason = if install.explicit {
                InstallReason::Explicit
            } else {
                InstallReason::Dependency
            };
            journal.step(
                Phase::Applying,
                &format!("{name}: register {version}"),
                || {
                    register_package(
                        ctx.db_path,
                        &metadata,
                        reason,
                        &[Validation::Sha256],
                        ctx.root_dir,
                    )
                },
            )?;
            ctx.logger.log_installed(name, &version);
            if let Some(script) = &metadata.install {
                run_recorded_scriptlet(
                    journal,
                    &mut failures,
                    "post_install",
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

    // Never execute all planned post-hooks after a partial filesystem application.
    // This point is reached only after every package has been applied.
    eprintln!(":: Running post-transaction maintenance...");
    run_recorded_hooks(
        ctx.root_dir,
        ctx.db_path,
        ctx.hook_dirs,
        &HookWhen::PostTransaction,
        hook_packages,
        ctx.logger,
        journal,
        &mut failures,
    )?;
    maintenance_result(failures)
}

pub(crate) fn maintenance_result(failures: Vec<String>) -> Result<()> {
    if failures.is_empty() {
        Ok(())
    } else {
        Err(ExecError::MaintenanceIncomplete { failures })
    }
}

pub(crate) fn finish_transaction(
    result: Result<()>,
    journal: &mut Journal,
    db_path: &Path,
    logger: &mut PaxLogger,
) -> Result<()> {
    let result = result.and_then(|()| journal.complete());
    if let Err(error) = result {
        let mut cause = error.to_string();
        if matches!(error, ExecError::MaintenanceIncomplete { .. }) {
            logger.log_transaction_incomplete(&cause);
        } else {
            logger.log_transaction_failed(&cause);
        }
        if let Err(record_error) = journal.failure(&cause) {
            cause.push_str(&format!("\nfailed to persist failure: {record_error}"));
        }
        return Err(ExecError::TransactionIncomplete {
            cause,
            journal: db_path.join("pax-transactions/active.json"),
        });
    }
    logger.log_transaction_completed();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_recorded_scriptlet(
    journal: &mut Journal,
    failures: &mut Vec<String>,
    operation: &str,
    script: &str,
    op: ScriptletOp,
    new_version: &str,
    old_version: Option<&str>,
    root: &Path,
    name: &str,
    logger: &mut PaxLogger,
) -> Result<()> {
    let operation = format!("{name}: {operation} {new_version}");
    journal.intent(Phase::Applying, &operation)?;
    match run_scriptlet(script, op, new_version, old_version, root, name, logger) {
        Ok(()) => journal.applied(&operation),
        Err(error) => {
            let message = error.to_string();
            record_maintenance_failure(journal, &message)?;
            failures.push(message);
            Ok(())
        }
    }
}

fn record_maintenance_failure(journal: &mut Journal, cause: &str) -> Result<()> {
    journal.failure(cause).map_err(|error| {
        std::io::Error::other(format!(
            "{cause}\nfailed to persist maintenance failure: {error}"
        ))
        .into()
    })
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
            info: metadata.info,
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_recorded_hooks(
    root: &Path,
    db_path: &Path,
    hook_dirs: &[PathBuf],
    when: &HookWhen,
    packages: &TransactionPackages,
    logger: &mut PaxLogger,
    journal: &mut Journal,
    failures: &mut Vec<String>,
) -> Result<()> {
    let hooks = load_hooks(hook_dirs);
    let local = LocalDb::open(db_path)?;
    // Record each hook separately so a killed hook can be identified on restart.
    for hook in hooks.iter().filter(|hook| {
        hook.action.when == *when && !crate::hooks::match_hook(hook, packages).is_empty()
    }) {
        let operation = format!("{when:?} hook {}", hook.name);
        journal.intent(Phase::Hooks, &operation)?;
        let errors = run_hooks(
            std::slice::from_ref(hook),
            when,
            packages,
            root,
            &|dependency| {
                local
                    .packages()
                    .any(|pkg| package_satisfies_dependency(&pkg.info, dependency))
            },
            logger,
        )?;
        if errors.is_empty() {
            journal.applied(&operation)?;
        } else {
            record_maintenance_failure(journal, &errors.join("\n"))?;
            failures.extend(errors);
        }
    }
    Ok(())
}

pub(crate) fn read_file_list(db_path: &Path, name: &str, version: &str) -> Result<Vec<String>> {
    crate::extract::validate_identity(name, version)?;
    let files_path = db_path
        .join("local")
        .join(format!("{name}-{version}"))
        .join("files");
    let content = read_file_metadata(&files_path)
        .map_err(|error| std::io::Error::other(format!("{name} {version}: {error}")))?;
    Ok(parse_file_list(&content))
}

pub(crate) fn read_file_metadata(files_path: &Path) -> Result<String> {
    let content = std::fs::read_to_string(files_path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("read package file list {}: {error}", files_path.display()),
        )
    })?;
    let sections = content.lines().filter(|line| *line == "%FILES%").count();
    if sections != 1 {
        // libalpm can write an empty files entry for a payload-free metapackage.
        // An empty list for a nonempty package is not a usable removal plan.
        let empty_package = content.is_empty()
            && files_path.parent().is_some_and(|parent| {
                std::fs::read_to_string(parent.join("desc"))
                    .ok()
                    .is_some_and(|desc| {
                        desc.lines().skip_while(|line| *line != "%SIZE%").nth(1) == Some("0")
                    })
            });
        if !empty_package {
            return Err(invalid_transaction(format!(
                "{}: missing or duplicate %FILES%; cannot verify package contents",
                files_path.display()
            )));
        }
    }
    Ok(content)
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

fn read_installed_snapshot(db_path: &Path) -> Result<Vec<PackageInfo>> {
    let mut packages = Vec::new();
    for entry in std::fs::read_dir(db_path.join("local"))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let desc = entry.path().join("desc");
        let text = std::fs::read_to_string(&desc).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("read installed metadata {}: {error}", desc.display()),
            )
        })?;
        let info = pax_alpm::desc::desc_to_package_info(&pax_alpm::desc::parse_desc(&text))
            .map_err(|error| invalid_transaction(format!("{}: {error}", desc.display())))?;
        crate::extract::validate_identity(&info.name, &info.version.to_string())?;
        if entry.file_name() != std::ffi::OsStr::new(&format!("{}-{}", info.name, info.version)) {
            return Err(invalid_transaction(format!(
                "installed metadata identity does not match {}",
                entry.path().display()
            )));
        }
        packages.push(info);
    }
    Ok(packages)
}

#[derive(Clone)]
struct OwnershipParent {
    resolved: PathBuf,
    symlinks: Vec<String>,
}

struct OwnershipPath {
    resolved: String,
    spelling: String,
    symlinks: Vec<String>,
}

struct PathOwner {
    package: String,
    spelling: String,
    directory: bool,
}

// A marker distinguishes missing ordinary parents (which extraction may create)
// from missing symlink targets. Normalizing a target lexically would hide dangling
// components in paths such as "missing/../real".
enum OwnershipComponent {
    Part(std::ffi::OsString),
    EndLink,
}

fn resolve_ownership_parent(root: &Path, parent: &Path, file: &str) -> Result<OwnershipParent> {
    use std::collections::VecDeque;

    let mut pending: VecDeque<_> = parent
        .components()
        .map(|part| OwnershipComponent::Part(part.as_os_str().to_os_string()))
        .collect();
    let mut resolved = PathBuf::new();
    let mut symlinks = Vec::new();
    let mut link_depth = 0;
    let mut followed = 0;
    let mut missing = false;
    while let Some(component) = pending.pop_front() {
        let part = match component {
            OwnershipComponent::EndLink => {
                link_depth -= 1;
                continue;
            }
            OwnershipComponent::Part(part) => part,
        };
        if part == "." {
            continue;
        }
        if part == ".." {
            if !resolved.pop() {
                return Err(invalid_transaction(format!(
                    "{file}: ownership parent escapes installation root"
                )));
            }
            continue;
        }
        let candidate = resolved.join(&part);
        // Once an ordinary parent is absent, its remaining ordinary children
        // cannot be symlinks. No link target can reach this branch while missing.
        if missing {
            resolved = candidate;
            continue;
        }
        let absolute = root.join(&candidate);
        let metadata = match std::fs::symlink_metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if link_depth != 0 {
                    return Err(invalid_transaction(format!(
                        "{file}: dangling ownership parent target {}",
                        absolute.display()
                    )));
                }
                missing = true;
                resolved = candidate;
                continue;
            }
            Err(error) => {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!(
                        "{file}: inspect ownership parent {}: {error}",
                        absolute.display()
                    ),
                )
                .into());
            }
        };
        if metadata.file_type().is_symlink() {
            followed += 1;
            if followed > 40 {
                return Err(invalid_transaction(format!(
                    "{file}: ownership parent symlink loop or more than 40 links"
                )));
            }
            let link = candidate.to_str().ok_or_else(|| {
                invalid_transaction(format!("{file}: non-UTF-8 ownership symlink path"))
            })?;
            symlinks.push(link.to_string());
            let target = std::fs::read_link(&absolute).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "{file}: read ownership symlink {}: {error}",
                        absolute.display()
                    ),
                )
            })?;
            if target.as_os_str().is_empty() {
                return Err(invalid_transaction(format!(
                    "{file}: empty ownership symlink target at {link}"
                )));
            }
            let target = if target.is_absolute() {
                // Match host-side extraction: an absolute link is traversable
                // only when it names a path within this canonical installation root.
                let target = target.strip_prefix(root).map_err(|_| {
                    invalid_transaction(format!(
                        "{file}: ownership symlink {link} points outside root"
                    ))
                })?;
                resolved.clear();
                target
            } else {
                target.as_path()
            };
            pending.push_front(OwnershipComponent::EndLink);
            for part in target.components().rev() {
                pending.push_front(OwnershipComponent::Part(part.as_os_str().to_os_string()));
            }
            link_depth += 1;
        } else if metadata.is_dir() {
            resolved = candidate;
        } else {
            return Err(invalid_transaction(format!(
                "{file}: ownership parent {} is not a directory",
                absolute.display()
            )));
        }
    }
    Ok(OwnershipParent { resolved, symlinks })
}

fn ownership_path(
    root: &Path,
    file: &str,
    parents: &mut HashMap<PathBuf, OwnershipParent>,
) -> Result<OwnershipPath> {
    let relative = crate::extract::safe_relative_path(Path::new(file))?;
    let name = relative
        .file_name()
        .ok_or_else(|| invalid_transaction(format!("empty ownership path: {file}")))?;
    let parent = relative.parent().unwrap_or(Path::new(""));
    if !parents.contains_key(parent) {
        let resolved = resolve_ownership_parent(root, parent, file)?;
        parents.insert(parent.to_path_buf(), resolved);
    }
    let parent = &parents[parent];
    // Resolve parents, never the final object: removal unlinks a final symlink.
    let resolved = parent.resolved.join(name);
    Ok(OwnershipPath {
        resolved: resolved
            .to_str()
            .ok_or_else(|| invalid_transaction(format!("{file}: non-UTF-8 ownership path")))?
            .to_string(),
        spelling: relative
            .to_str()
            .ok_or_else(|| invalid_transaction(format!("{file}: non-UTF-8 ownership spelling")))?
            .to_string(),
        symlinks: parent.symlinks.clone(),
    })
}

fn retain_parent_directories(path: &str, directories: &mut HashSet<String>) {
    for parent in Path::new(path).ancestors().skip(1) {
        if let Some(parent) = parent.to_str().filter(|path| !path.is_empty()) {
            directories.insert(parent.to_string());
        }
    }
}

fn check_file_conflicts(
    root_dir: &Path,
    db_path: &Path,
    incoming: &HashMap<&str, IncomingPackage<'_>>,
    tx: &Transaction,
    steps: &[ExecutionStep],
) -> Result<HashSet<String>> {
    let positions: HashMap<_, _> = steps
        .iter()
        .enumerate()
        .map(|(index, step)| (step.incoming.as_str(), index))
        .collect();
    let removals: HashMap<_, _> = steps
        .iter()
        .enumerate()
        .flat_map(|(index, step)| {
            step.remove_before
                .iter()
                .map(move |name| (name.as_str(), index))
        })
        .collect();
    let root = root_dir.canonicalize()?;
    if !root.is_dir() {
        return Err(invalid_transaction(format!(
            "ownership root {} is not a directory",
            root.display()
        )));
    }
    let mut parents = HashMap::new();
    let mut directory_aliases = Vec::new();
    let mut old_owners: HashMap<String, Vec<PathOwner>> = HashMap::new();
    let local_dir = db_path.join("local");
    match std::fs::read_dir(&local_dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let content = std::fs::read_to_string(entry.path().join("desc"))?;
                let name = parse_name_from_desc(&content).ok_or_else(|| {
                    invalid_transaction(format!(
                        "missing package name in {}",
                        entry.path().join("desc").display()
                    ))
                })?;
                let content = read_file_metadata(&entry.path().join("files"))?;
                for file in parse_file_list(&content) {
                    let ownership = ownership_path(&root, &file, &mut parents)?;
                    if file.ends_with('/') {
                        directory_aliases.push((
                            file.trim_end_matches('/').to_string(),
                            ownership.resolved.clone(),
                        ));
                    }
                    old_owners
                        .entry(ownership.resolved)
                        .or_default()
                        .push(PathOwner {
                            package: name.clone(),
                            spelling: ownership.spelling,
                            directory: file.ends_with('/'),
                        });
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let upgraded: HashSet<_> = tx
        .upgrades
        .iter()
        .map(|action| action.name.as_str())
        .collect();
    let changing: HashSet<_> = upgraded
        .iter()
        .copied()
        .chain(tx.removals.iter().map(|action| action.name.as_str()))
        .collect();
    let mut retained_directories = HashSet::new();
    for (path, owners) in &old_owners {
        if owners
            .iter()
            .any(|owner| !changing.contains(owner.package.as_str()))
        {
            retain_parent_directories(path, &mut retained_directories);
            if owners
                .iter()
                .any(|owner| owner.directory && !changing.contains(owner.package.as_str()))
            {
                retained_directories.insert(path.clone());
            }
        }
    }
    let mut incoming_owners: HashMap<String, (&str, bool)> = HashMap::new();
    let mut lexical_owners: HashMap<&str, (&str, bool)> = HashMap::new();
    let mut conflicts = Vec::new();
    for (name, package) in incoming {
        for file in &package.files {
            let directory = file.ends_with('/');
            let ownership = ownership_path(&root, file, &mut parents)?;
            // File lists cannot prove that an upgraded symlink keeps its target.
            // Check every traversed link, including links inside other link targets.
            for symlink in &ownership.symlinks {
                if let Some(owners) = old_owners.get(symlink) {
                    for owner in owners {
                        if changing.contains(owner.package.as_str()) {
                            conflicts.push(format!(
                                "  {name}: /{file} traverses parent symlink /{symlink} owned by changing package {}; namespace preservation is not proven",
                                owner.package,
                            ));
                        }
                    }
                }
            }
            let path = ownership.resolved;
            lexical_owners.insert(file.trim_end_matches('/'), (*name, directory));
            if directory {
                directory_aliases.push((file.trim_end_matches('/').to_string(), path.clone()));
                retained_directories.insert(path.clone());
            }
            if let Some((owner, other_directory)) = incoming_owners.get(&path) {
                if !(directory && *other_directory) {
                    conflicts.push(format!("  {name}: /{path} also supplied by {owner}"));
                }
            } else {
                incoming_owners.insert(path.clone(), (*name, directory));
            }
            let owners = old_owners.get(&path);
            if let Some(owners) = owners {
                for owner in owners {
                    if !changing.contains(owner.package.as_str()) && !(directory && owner.directory)
                    {
                        conflicts.push(format!(
                            "  {name}: /{path} already owned by {}",
                            owner.package
                        ));
                    }
                    if !(directory && owner.directory)
                        && upgraded.contains(owner.package.as_str())
                        && owner.spelling != ownership.spelling
                    {
                        conflicts.push(format!(
                            "  {name}: /{} and /{} resolve to /{path}; cross-spelling transfer from upgraded owner {} is unsupported (cleanup and backup handling use lexical paths)",
                            ownership.spelling, owner.spelling, owner.package,
                        ));
                    }
                    if !(directory && owner.directory)
                        && removals.get(owner.package.as_str()).is_some_and(|slot| {
                            positions
                                .get(name)
                                .is_some_and(|incoming_slot| slot > incoming_slot)
                        })
                    {
                        conflicts.push(format!("  {name}: /{path} would be installed before old owner {} is removed; linked removal would delete the new payload", owner.package));
                    }
                }
            }
            match std::fs::symlink_metadata(root.join(&path)) {
                Ok(metadata) => {
                    if directory && metadata.is_dir() {
                        continue;
                    }
                    let vacated = owners.is_some_and(|owners| {
                        owners
                            .iter()
                            .all(|owner| changing.contains(owner.package.as_str()))
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
    // Retained paths also need their implicit parents; lexical checks must remain
    // even when a current filesystem alias resolves two spellings to one path.
    for path in incoming_owners.keys() {
        retain_parent_directories(path, &mut retained_directories);
    }
    for (path, (name, directory)) in &incoming_owners {
        if !directory && retained_directories.contains(path) {
            conflicts.push(format!(
                "  {name}: /{path} must remain a directory for a final-state owner"
            ));
        }
    }
    // Also catch a file from one archive used as a parent directory by another.
    for (path, (name, _)) in &lexical_owners {
        let mut parent = Path::new(path).parent();
        while let Some(directory) = parent {
            if let Some((owner, false)) =
                directory.to_str().and_then(|path| lexical_owners.get(path))
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
        for (alias, resolved) in directory_aliases {
            if retained_directories.contains(&resolved) {
                retained_directories.insert(alias);
            }
        }
        Ok(retained_directories)
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

    fn package_info(name: &str) -> PackageInfo {
        pax_alpm::desc::desc_to_package_info(&pax_alpm::desc::parse_desc(&format!(
            "%NAME%\n{name}\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n"
        )))
        .unwrap()
    }

    fn simple_steps(tx: &Transaction) -> Vec<ExecutionStep> {
        tx.package_order
            .iter()
            .map(|name| ExecutionStep {
                incoming: name.clone(),
                remove_before: vec![],
            })
            .collect()
    }

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

    fn masked_hooks(dir: &Path) -> PathBuf {
        let hooks = dir.join("hooks");
        std::fs::create_dir(&hooks).unwrap();
        if let Ok(entries) = std::fs::read_dir("/usr/share/libalpm/hooks") {
            for entry in entries {
                let entry = entry.unwrap();
                if entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "hook")
                {
                    std::os::unix::fs::symlink("/dev/null", hooks.join(entry.file_name())).unwrap();
                }
            }
        }
        hooks
    }

    #[test]
    fn damaged_outgoing_metadata_is_not_an_empty_removal_plan() {
        let temp = tempfile::tempdir().unwrap();
        let entry = temp.path().join("local/example-1-1");
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("desc"), "%SIZE%\n12\n\n").unwrap();
        for contents in ["", "corrupt", "%FILES%\nfile\n\n%FILES%\nother\n"] {
            std::fs::write(entry.join("files"), contents).unwrap();
            assert!(read_file_list(temp.path(), "example", "1-1").is_err());
        }
        std::fs::write(entry.join("files"), "%FILES%\nfile\n\n").unwrap();
        assert_eq!(
            read_file_list(temp.path(), "example", "1-1").unwrap(),
            ["file"]
        );
        std::fs::write(entry.join("desc"), "%SIZE%\n0\n\n").unwrap();
        std::fs::write(entry.join("files"), "").unwrap();
        assert!(
            read_file_list(temp.path(), "example", "1-1")
                .unwrap()
                .is_empty()
        );
        std::fs::remove_file(entry.join("files")).unwrap();
        assert!(read_file_list(temp.path(), "example", "1-1").is_err());
    }

    #[test]
    fn failure_recording_error_keeps_the_maintenance_cause_and_previous_intent() {
        let temp = tempfile::tempdir().unwrap();
        let mut journal = Journal::begin(temp.path(), temp.path(), vec![]).unwrap();
        journal
            .intent(Phase::Applying, "example: pre_install")
            .unwrap();
        let cause = format!(
            "example: pre_install exit status 42: {}",
            "x".repeat(8 * 1024 * 1024)
        );
        let error = record_maintenance_failure(&mut journal, &cause)
            .unwrap_err()
            .to_string();
        assert!(error.contains("pre_install exit status 42"));
        assert!(error.contains("failed to persist maintenance failure"));
        let record = crate::journal::inspect(temp.path()).unwrap().unwrap();
        assert_eq!(
            record.current_operation.as_deref(),
            Some("example: pre_install")
        );
        assert!(record.failure.is_none());
    }

    #[test]
    fn invalid_later_archive_prevents_hooks_removals_and_first_install() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        let old = db.join("local/obsolete-1-1");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(root.join("old"), "keep").unwrap();
        std::fs::write(old.join("desc"), "%NAME%\nobsolete\n\n%VERSION%\n1-1\n\n").unwrap();
        std::fs::write(old.join("files"), "%FILES%\nold\n\n").unwrap();
        let first = archive(temp.path(), "first", "first", "1-1");
        let second = archive(temp.path(), "second", "second", "1-1");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&second.path)
            .unwrap()
            .set_len(1024)
            .unwrap();
        let downloaded = [first, second];
        let mut tx = transaction(&["first", "second"]);
        tx.removals.push(pax_resolver::RemovalAction {
            name: "obsolete".into(),
            version: Version::parse("1-1").unwrap(),
            links: vec![pax_resolver::RemovalLink {
                incoming: "first".into(),
                reason: RemovalReason::Replaced,
            }],
        });
        let hooks = masked_hooks(temp.path());
        std::fs::write(hooks.join("00-preflight-probe.hook"),
            "[Trigger]\nType = Package\nOperation = Install\nTarget = first\n[Action]\nWhen = PreTransaction\nExec = /must-not-run\nAbortOnFail\n").unwrap();
        let log = temp.path().join("log");
        let mut logger = PaxLogger::open(&log);
        let error = execute_transaction(
            &tx,
            &mut InstallContext {
                root_dir: &root,
                db_path: &db,
                architecture: "auto",
                downloaded: &downloaded,
                old_install_scripts: &HashMap::new(),
                old_backup_md5: &HashMap::new(),
                hook_dirs: &[hooks],
                check_space: false,
                logger: &mut logger,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("preflight"), "{error}");
        assert_eq!(std::fs::read_to_string(root.join("old")).unwrap(), "keep");
        assert!(old.join("desc").exists());
        assert!(!root.join("file").exists());
        assert!(!db.join("local/first-1-1").exists());
        assert!(!db.join("pax-transactions").exists());
        assert!(
            !std::fs::read_to_string(log)
                .unwrap()
                .contains("transaction started")
        );
    }

    #[test]
    fn applied_packages_with_failed_scriptlets_leave_an_active_diagnosis() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        std::fs::create_dir_all(root.join("tmp")).unwrap();
        std::fs::create_dir_all(db.join("local")).unwrap();
        let downloaded = archive(temp.path(), "example", "example", "1-1");
        // Replace the fixture with one whose script cannot run without a chroot shell.
        let mut builder = tar::Builder::new(std::fs::File::create(&downloaded.path).unwrap());
        for (path, bytes) in [
            (".PKGINFO", "pkgname = example\npkgver = 1-1\narch = any\n"),
            (".INSTALL", "pre_install() { :; }\npost_install() { :; }\n"),
            ("file", "payload"),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, path, bytes.as_bytes())
                .unwrap();
        }
        builder.finish().unwrap();
        let hooks = masked_hooks(temp.path());
        std::fs::write(hooks.join("00-unmatched.hook"),
            "[Trigger]\nType = Package\nOperation = Install\nTarget = unrelated\n[Action]\nWhen = PostTransaction\nExec = /must-not-run\n").unwrap();
        let log = temp.path().join("log");
        let mut logger = PaxLogger::open(&log);
        let error = execute_transaction(
            &transaction(&["example"]),
            &mut InstallContext {
                root_dir: &root,
                db_path: &db,
                architecture: "auto",
                downloaded: &[downloaded],
                old_install_scripts: &HashMap::new(),
                old_backup_md5: &HashMap::new(),
                hook_dirs: &[hooks],
                check_space: false,
                logger: &mut logger,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("maintenance is incomplete"), "{error}");
        assert_eq!(
            std::fs::read_to_string(root.join("file")).unwrap(),
            "payload"
        );
        assert!(db.join("local/example-1-1/desc").exists());
        let record = crate::journal::inspect(&db).unwrap().unwrap();
        let failures = record.failure.unwrap();
        assert!(failures.contains("pre_install"));
        assert!(failures.contains("post_install"));
        assert!(
            !record
                .completed_operations
                .iter()
                .any(|step| step.contains("unmatched"))
        );
        assert!(pax_alpm::DbLock::acquire_with_timeout(&db, std::time::Duration::ZERO).is_err());
        let log = std::fs::read_to_string(log).unwrap();
        assert!(log.contains("transaction incomplete"));
        assert!(!log.contains("transaction completed"));
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
            links: vec![pax_resolver::RemovalLink {
                incoming: "replacement".into(),
                reason: RemovalReason::Replaced,
            }],
        });
        let empty = HashMap::new();
        let backups = HashMap::new();
        let mut logger = PaxLogger::none();
        let hooks = [masked_hooks(temp.path())];
        let mut ctx = InstallContext {
            root_dir: &root,
            db_path: &db,
            architecture: "auto",
            downloaded: &downloaded,
            old_install_scripts: &empty,
            old_backup_md5: &backups,
            hook_dirs: &hooks,
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
                    info: package_info("first"),
                    files: vec!["shared/".into()],
                    install_script: None,
                },
            ),
            (
                "second",
                IncomingPackage {
                    downloaded: &second,
                    info: package_info("second"),
                    files: vec!["shared/".into()],
                    install_script: None,
                },
            ),
        ]);
        let tx = transaction(&["first", "second"]);
        assert!(check_file_conflicts(&root, &db, &incoming, &tx, &simple_steps(&tx)).is_ok());
        incoming
            .get_mut("first")
            .unwrap()
            .files
            .push("unowned".into());
        std::fs::write(root.join("unowned"), "keep").unwrap();
        assert!(check_file_conflicts(&root, &db, &incoming, &tx, &simple_steps(&tx)).is_err());
        std::fs::remove_file(root.join("unowned")).unwrap();
        incoming
            .get_mut("second")
            .unwrap()
            .files
            .push("unowned".into());
        assert!(check_file_conflicts(&root, &db, &incoming, &tx, &simple_steps(&tx)).is_err());
    }

    #[test]
    fn late_removal_cannot_delete_an_earlier_incoming_file_through_an_alias() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        std::fs::create_dir_all(root.join("dir")).unwrap();
        std::os::unix::fs::symlink("dir", root.join("alias")).unwrap();
        let entry = db.join("local/old-1-1");
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("desc"), "%NAME%\nold\n\n").unwrap();
        std::fs::write(entry.join("files"), "%FILES%\ndir/\ndir/shared\n\n").unwrap();
        std::fs::write(root.join("dir/shared"), "keep").unwrap();
        let early = DownloadedPackage {
            name: "early".into(),
            path: PathBuf::new(),
        };
        let late = DownloadedPackage {
            name: "late".into(),
            path: PathBuf::new(),
        };
        let incoming = HashMap::from([
            (
                "early",
                IncomingPackage {
                    downloaded: &early,
                    info: package_info("early"),
                    files: vec!["alias/shared".into()],
                    install_script: None,
                },
            ),
            (
                "late",
                IncomingPackage {
                    downloaded: &late,
                    info: package_info("late"),
                    files: vec!["later".into()],
                    install_script: None,
                },
            ),
        ]);
        let mut tx = transaction(&["early", "late"]);
        tx.removals.push(pax_resolver::RemovalAction {
            name: "old".into(),
            version: Version::parse("1-1").unwrap(),
            links: vec![pax_resolver::RemovalLink {
                incoming: "late".into(),
                reason: RemovalReason::Replaced,
            }],
        });
        let mut steps = simple_steps(&tx);
        steps[1].remove_before.push("old".into());
        let error = check_file_conflicts(&root, &db, &incoming, &tx, &steps)
            .unwrap_err()
            .to_string();
        assert!(error.contains("dir/shared"), "{error}");
        assert!(error.contains("before old owner old is removed"), "{error}");
        steps[1].remove_before.clear();
        steps[0].remove_before.push("old".into());
        let directories = check_file_conflicts(&root, &db, &incoming, &tx, &steps).unwrap();
        assert!(directories.contains("dir"));
        assert_eq!(
            std::fs::read_to_string(root.join("dir/shared")).unwrap(),
            "keep"
        );
    }

    fn alias_test_entry(db: &Path, name: &str, files: &str) -> PathBuf {
        let entry = db.join(format!("local/{name}-1-1"));
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(
            entry.join("desc"),
            format!("%NAME%\n{name}\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n"),
        )
        .unwrap();
        std::fs::write(entry.join("files"), files).unwrap();
        entry
    }

    fn alias_test_upgrade(name: &str) -> UpgradeAction {
        UpgradeAction {
            name: name.into(),
            old_version: Version::parse("1-1").unwrap(),
            new_version: Version::parse("2-1").unwrap(),
            repository: "test".into(),
            download_size: 0,
            installed_size: 0,
        }
    }

    #[test]
    fn upgraded_owner_cross_spelling_transfer_is_rejected_in_both_directions_and_orders() {
        for old_uses_alias in [false, true] {
            for (same_name, old_first) in [(true, false), (false, false), (false, true)] {
                let temp = tempfile::tempdir().unwrap();
                let root = temp.path().join("root");
                let db = temp.path().join("db");
                std::fs::create_dir_all(root.join("real")).unwrap();
                std::os::unix::fs::symlink("real", root.join("alias")).unwrap();
                std::fs::write(root.join("real/shared"), "local changes").unwrap();
                std::fs::write(root.join("real/shared.pacsave"), "previous save").unwrap();
                let (old_spelling, new_spelling) = if old_uses_alias {
                    ("alias/shared", "real/shared")
                } else {
                    ("real/shared", "alias/shared")
                };
                let baseline = format!("{:x}", md5::compute("original"));
                let files =
                    format!("%FILES%\n{old_spelling}\n\n%BACKUP%\n{old_spelling}\t{baseline}\n\n");
                let entry = alias_test_entry(&db, "old", &files);
                let old = DownloadedPackage {
                    name: "old".into(),
                    path: PathBuf::new(),
                };
                let new = DownloadedPackage {
                    name: "new".into(),
                    path: PathBuf::new(),
                };
                let mut incoming = HashMap::from([(
                    "old",
                    IncomingPackage {
                        downloaded: &old,
                        info: package_info("old"),
                        files: if same_name {
                            vec![new_spelling.into()]
                        } else {
                            vec![]
                        },
                        install_script: None,
                    },
                )]);
                let mut tx = transaction(&[]);
                tx.upgrades.push(alias_test_upgrade("old"));
                tx.package_order.push("old".into());
                if !same_name {
                    incoming.insert(
                        "new",
                        IncomingPackage {
                            downloaded: &new,
                            info: package_info("new"),
                            files: vec![new_spelling.into()],
                            install_script: None,
                        },
                    );
                    tx.installs = transaction(&["new"]).installs;
                    if old_first {
                        tx.package_order.push("new".into());
                    } else {
                        tx.package_order.insert(0, "new".into());
                    }
                }
                let message = check_file_conflicts(&root, &db, &incoming, &tx, &simple_steps(&tx))
                    .unwrap_err()
                    .to_string();
                for expected in [
                    "cross-spelling transfer",
                    "upgraded owner old",
                    old_spelling,
                    new_spelling,
                ] {
                    assert!(message.contains(expected), "{message}");
                }
                if same_name {
                    // Identical spelling through the same stable alias remains supported.
                    incoming.get_mut("old").unwrap().files = vec![old_spelling.into()];
                    assert!(
                        check_file_conflicts(&root, &db, &incoming, &tx, &simple_steps(&tx))
                            .is_ok()
                    );
                }
                assert_eq!(
                    std::fs::read_to_string(root.join("real/shared")).unwrap(),
                    "local changes"
                );
                assert_eq!(
                    std::fs::read_to_string(root.join("real/shared.pacsave")).unwrap(),
                    "previous save"
                );
                assert!(!root.join("real/shared.pacnew").exists());
                assert!(!root.join("real/shared.pacsave.1").exists());
                assert_eq!(std::fs::read_to_string(entry.join("files")).unwrap(), files);
                assert_eq!(
                    std::fs::read_link(root.join("alias")).unwrap(),
                    Path::new("real")
                );
                assert!(!db.join("pax-transactions").exists());
            }
        }
    }

    #[test]
    fn changing_symlink_inside_an_alias_target_is_rejected_for_upgrade_and_removal() {
        for upgrade in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let db = temp.path().join("db");
            std::fs::create_dir_all(root.join("real")).unwrap();
            std::fs::create_dir_all(root.join("links")).unwrap();
            std::os::unix::fs::symlink("links/alias2", root.join("alias1")).unwrap();
            std::os::unix::fs::symlink("../real", root.join("links/alias2")).unwrap();
            let files = "%FILES%\nlinks/alias2\n\n";
            let entry = alias_test_entry(&db, "old", files);
            let early = DownloadedPackage {
                name: "early".into(),
                path: PathBuf::new(),
            };
            let later_name = if upgrade { "old" } else { "late" };
            let late = DownloadedPackage {
                name: later_name.into(),
                path: PathBuf::new(),
            };
            let incoming = HashMap::from([
                (
                    "early",
                    IncomingPackage {
                        downloaded: &early,
                        info: package_info("early"),
                        files: vec![
                            "alias1/implicit/first".into(),
                            "alias1/implicit/second".into(),
                        ],
                        install_script: None,
                    },
                ),
                (
                    later_name,
                    IncomingPackage {
                        downloaded: &late,
                        info: package_info(later_name),
                        files: vec!["late-file".into()],
                        install_script: None,
                    },
                ),
            ]);
            let mut tx = transaction(&["early"]);
            if upgrade {
                tx.upgrades.push(alias_test_upgrade("old"));
            } else {
                tx.installs.extend(transaction(&["late"]).installs);
                tx.removals.push(pax_resolver::RemovalAction {
                    name: "old".into(),
                    version: Version::parse("1-1").unwrap(),
                    links: vec![pax_resolver::RemovalLink {
                        incoming: "late".into(),
                        reason: RemovalReason::Replaced,
                    }],
                });
            }
            tx.package_order.push(later_name.into());
            let mut steps = simple_steps(&tx);
            if !upgrade {
                steps[1].remove_before.push("old".into());
            }
            let message = check_file_conflicts(&root, &db, &incoming, &tx, &steps)
                .unwrap_err()
                .to_string();
            for expected in [
                "alias1/implicit/first",
                "alias1/implicit/second",
                "parent symlink /links/alias2",
                "changing package old",
            ] {
                assert!(message.contains(expected), "{message}");
            }
            assert_eq!(
                std::fs::read_link(root.join("alias1")).unwrap(),
                Path::new("links/alias2")
            );
            assert_eq!(
                std::fs::read_link(root.join("links/alias2")).unwrap(),
                Path::new("../real")
            );
            assert_eq!(std::fs::read_to_string(entry.join("files")).unwrap(), files);
            assert!(!root.join("real/implicit").exists());
            assert!(!root.join("late-file").exists());
            assert!(!db.join("pax-transactions").exists());
        }
    }

    #[test]
    fn unchanged_and_unowned_alias_chains_allow_implicit_parents() {
        for owned in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let db = temp.path().join("db");
            std::fs::create_dir_all(root.join("real")).unwrap();
            std::fs::create_dir_all(db.join("local")).unwrap();
            std::os::unix::fs::symlink("alias2", root.join("alias1")).unwrap();
            std::os::unix::fs::symlink("real", root.join("alias2")).unwrap();
            if owned {
                alias_test_entry(&db, "stable", "%FILES%\nalias1\nalias2\n\n");
            }
            let download = DownloadedPackage {
                name: "new".into(),
                path: PathBuf::new(),
            };
            let incoming = HashMap::from([(
                "new",
                IncomingPackage {
                    downloaded: &download,
                    info: package_info("new"),
                    files: vec![
                        "alias1/implicit/file".into(),
                        "alias1/implicit/other".into(),
                    ],
                    install_script: None,
                },
            )]);
            let tx = transaction(&["new"]);
            let directories =
                check_file_conflicts(&root, &db, &incoming, &tx, &simple_steps(&tx)).unwrap();
            assert!(directories.contains("real"));
            assert!(directories.contains("real/implicit"));
            assert_eq!(
                std::fs::read_link(root.join("alias1")).unwrap(),
                Path::new("alias2")
            );
            assert_eq!(
                std::fs::read_link(root.join("alias2")).unwrap(),
                Path::new("real")
            );
            assert!(!root.join("real/implicit").exists());
        }
    }

    #[test]
    fn ownership_parent_cache_preserves_every_link_and_leaves_final_symlinks_unresolved() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("real/sub")).unwrap();
        std::os::unix::fs::symlink("alias2", root.join("alias1")).unwrap();
        std::os::unix::fs::symlink("real/sub/..", root.join("alias2")).unwrap();
        let mut parents = HashMap::new();
        for file in ["first", "second"] {
            let path =
                ownership_path(&root, &format!("./alias1/implicit/{file}"), &mut parents).unwrap();
            assert_eq!(path.resolved, format!("real/implicit/{file}"));
            assert_eq!(path.spelling, format!("alias1/implicit/{file}"));
            assert_eq!(path.symlinks, ["alias1", "alias2"]);
            assert_eq!(parents.len(), 1);
        }
        let link = ownership_path(&root, "alias1", &mut parents).unwrap();
        assert_eq!(link.resolved, "alias1");
        assert!(link.symlinks.is_empty());
        std::os::unix::fs::symlink(root.join("alias1"), root.join("absolute")).unwrap();
        let path = ownership_path(&root, "absolute/file", &mut parents).unwrap();
        assert_eq!(path.resolved, "real/file");
        assert_eq!(path.symlinks, ["absolute", "alias1", "alias2"]);
        assert!(!root.join("real/implicit").exists());
    }

    #[test]
    fn ownership_parent_rejects_dangling_non_directory_escaping_and_looping_links() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), "outside").unwrap();
        std::fs::write(root.join("plain"), "keep").unwrap();
        for (name, target) in [
            ("dangling", "missing"),
            ("dangling-dotdot", "missing/../real"),
            ("non-directory", "plain"),
            ("escape", "../outside"),
            ("self-loop", "self-loop"),
            ("loop-a", "loop-b"),
            ("loop-b", "loop-a"),
        ] {
            std::os::unix::fs::symlink(target, root.join(name)).unwrap();
        }
        std::os::unix::fs::symlink(&outside, root.join("absolute-escape")).unwrap();
        let mut parents = HashMap::new();
        for parent in [
            "dangling",
            "dangling-dotdot",
            "non-directory",
            "plain",
            "escape",
            "absolute-escape",
            "self-loop",
            "loop-a",
        ] {
            let path = format!("{parent}/implicit/file");
            assert!(
                ownership_path(&root, &path, &mut parents).is_err(),
                "{path}"
            );
        }
        for path in ["", ".", "../outside/sentinel", "/absolute"] {
            assert!(ownership_path(&root, path, &mut parents).is_err(), "{path}");
        }
        assert!(parents.is_empty());
        assert_eq!(std::fs::read_to_string(root.join("plain")).unwrap(), "keep");
        assert_eq!(
            std::fs::read_to_string(outside.join("sentinel")).unwrap(),
            "outside"
        );
        assert!(!root.join("missing").exists());
        assert!(!root.join("real/implicit").exists());
    }

    fn alias_test_archive(
        dir: &Path,
        name: &str,
        version: &str,
        payload: &str,
    ) -> DownloadedPackage {
        let path = dir.join(format!("{name}-{version}.pkg.tar"));
        let mut builder = tar::Builder::new(std::fs::File::create(&path).unwrap());
        let info = format!("pkgname = {name}\npkgver = {version}\narch = any\n");
        for (path, contents) in [
            (".PKGINFO", info.as_bytes()),
            (payload, b"new payload".as_slice()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        }
        builder.finish().unwrap();
        DownloadedPackage {
            name: name.into(),
            path,
        }
    }

    #[test]
    fn alias_blockers_stop_execution_before_hooks_journal_or_backup_changes() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        for scenario in ["transfer", "same-name", "parent-removal", "parent-upgrade"] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let db = temp.path().join("db");
            std::fs::create_dir_all(root.join("real")).unwrap();
            std::os::unix::fs::symlink("alias2", root.join("alias1")).unwrap();
            std::os::unix::fs::symlink("real", root.join("alias2")).unwrap();
            std::fs::write(root.join("real/shared"), "local changes").unwrap();
            std::fs::write(root.join("real/shared.pacsave"), "previous save").unwrap();
            let baseline = format!("{:x}", md5::compute("original"));
            let files = if scenario.starts_with("parent-") {
                "%FILES%\nalias2\n\n".into()
            } else {
                format!("%FILES%\nreal/shared\n\n%BACKUP%\nreal/shared\t{baseline}\n\n")
            };
            let entry = alias_test_entry(&db, "old", &files);
            let desc = std::fs::read(entry.join("desc")).unwrap();
            let (tx, downloaded) = if scenario == "same-name" {
                let mut tx = transaction(&[]);
                tx.upgrades.push(alias_test_upgrade("old"));
                tx.package_order.push("old".into());
                (
                    tx,
                    vec![alias_test_archive(
                        temp.path(),
                        "old",
                        "2-1",
                        "alias1/shared",
                    )],
                )
            } else {
                let mut tx = transaction(&["early"]);
                let early_path = if scenario == "transfer" {
                    "alias1/shared"
                } else {
                    "alias1/implicit/file"
                };
                let early = alias_test_archive(temp.path(), "early", "1-1", early_path);
                if scenario == "parent-removal" {
                    tx.installs.extend(transaction(&["late"]).installs);
                    tx.package_order.push("late".into());
                    tx.removals.push(pax_resolver::RemovalAction {
                        name: "old".into(),
                        version: Version::parse("1-1").unwrap(),
                        links: vec![pax_resolver::RemovalLink {
                            incoming: "late".into(),
                            reason: RemovalReason::Replaced,
                        }],
                    });
                    (
                        tx,
                        vec![
                            early,
                            alias_test_archive(temp.path(), "late", "1-1", "late-file"),
                        ],
                    )
                } else {
                    tx.upgrades.push(alias_test_upgrade("old"));
                    tx.package_order.push("old".into());
                    (
                        tx,
                        vec![
                            early,
                            alias_test_archive(temp.path(), "old", "2-1", "late-file"),
                        ],
                    )
                }
            };
            let hooks = masked_hooks(temp.path());
            std::fs::write(hooks.join("00-alias-probe.hook"),
                "[Trigger]\nType = Package\nOperation = Install\nOperation = Upgrade\nTarget = *\n[Action]\nWhen = PreTransaction\nExec = /must-not-run\nAbortOnFail\n").unwrap();
            let log = temp.path().join("log");
            let mut logger = PaxLogger::open(&log);
            let error = execute_transaction(
                &tx,
                &mut InstallContext {
                    root_dir: &root,
                    db_path: &db,
                    architecture: "auto",
                    downloaded: &downloaded,
                    old_install_scripts: &HashMap::new(),
                    old_backup_md5: &HashMap::new(),
                    hook_dirs: &[hooks],
                    check_space: false,
                    logger: &mut logger,
                },
            )
            .unwrap_err();
            assert!(
                matches!(&error, ExecError::FileConflict(_)),
                "{scenario}: {error}"
            );
            let expected = if scenario.starts_with("parent-") {
                "parent symlink /alias2"
            } else {
                "cross-spelling transfer"
            };
            assert!(error.to_string().contains(expected), "{scenario}: {error}");
            assert_eq!(
                std::fs::read_to_string(root.join("real/shared")).unwrap(),
                "local changes"
            );
            assert_eq!(
                std::fs::read_to_string(root.join("real/shared.pacsave")).unwrap(),
                "previous save"
            );
            assert!(!root.join("real/shared.pacnew").exists());
            assert!(!root.join("real/shared.pacsave.1").exists());
            assert!(!root.join("real/implicit").exists());
            assert!(!root.join("late-file").exists());
            assert_eq!(
                std::fs::read_link(root.join("alias1")).unwrap(),
                Path::new("alias2")
            );
            assert_eq!(
                std::fs::read_link(root.join("alias2")).unwrap(),
                Path::new("real")
            );
            assert_eq!(std::fs::read(entry.join("desc")).unwrap(), desc);
            assert_eq!(std::fs::read_to_string(entry.join("files")).unwrap(), files);
            assert_eq!(std::fs::read_dir(db.join("local")).unwrap().count(), 1);
            assert!(!db.join("pax-transactions").exists());
            assert!(
                !std::fs::read_to_string(log)
                    .unwrap()
                    .contains("transaction started")
            );
        }
    }

    #[test]
    fn shared_directory_of_an_unchanged_owner_survives_replacement_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        std::fs::create_dir_all(root.join("shared")).unwrap();
        for name in ["old", "retained"] {
            let entry = db.join(format!("local/{name}-1-1"));
            std::fs::create_dir_all(&entry).unwrap();
            std::fs::write(entry.join("desc"), format!("%NAME%\n{name}\n\n")).unwrap();
            std::fs::write(entry.join("files"), "%FILES%\nshared/\n\n").unwrap();
        }
        let new = DownloadedPackage {
            name: "new".into(),
            path: PathBuf::new(),
        };
        let incoming = HashMap::from([(
            "new",
            IncomingPackage {
                downloaded: &new,
                info: package_info("new"),
                files: vec!["file".into()],
                install_script: None,
            },
        )]);
        let mut tx = transaction(&["new"]);
        tx.removals.push(pax_resolver::RemovalAction {
            name: "old".into(),
            version: Version::parse("1-1").unwrap(),
            links: vec![pax_resolver::RemovalLink {
                incoming: "new".into(),
                reason: RemovalReason::Replaced,
            }],
        });
        let mut steps = simple_steps(&tx);
        steps[0].remove_before.push("old".into());
        let directories = check_file_conflicts(&root, &db, &incoming, &tx, &steps).unwrap();
        let removed = remove_package_paths(&db.join("local/old-1-1"), &root, &directories).unwrap();
        assert!(removed.is_empty());
        assert!(root.join("shared").is_dir());
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
                    info: package_info("new"),
                    files: vec!["shared".into()],
                    install_script: None,
                },
            ),
            (
                "old",
                IncomingPackage {
                    downloaded: &old,
                    info: package_info("old"),
                    files: vec![],
                    install_script: None,
                },
            ),
        ]);
        let mut tx = transaction(&["new"]);
        assert!(check_file_conflicts(&root, &db, &incoming, &tx, &simple_steps(&tx)).is_err());
        tx.upgrades.push(UpgradeAction {
            name: "old".into(),
            old_version: Version::parse("1-1").unwrap(),
            new_version: Version::parse("2-1").unwrap(),
            repository: "test".into(),
            download_size: 0,
            installed_size: 0,
        });
        tx.package_order.push("old".into());
        assert!(check_file_conflicts(&root, &db, &incoming, &tx, &simple_steps(&tx)).is_ok());
        incoming.get_mut("old").unwrap().files.push("shared".into());
        assert!(check_file_conflicts(&root, &db, &incoming, &tx, &simple_steps(&tx)).is_err());
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
