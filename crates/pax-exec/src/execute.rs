use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use pax_alpm::local::LocalDb;
use pax_core::package::{InstallReason, PackageInfo};
use pax_resolver::pool::package_satisfies_dependency;
use pax_resolver::{ExecutionStep, RemovalReason, Transaction, execution_plan};

use crate::error::{ExecError, Result};
use crate::extract::{
    PackageMetadata, extract_package, read_archive_file_list, read_install_script,
};
use crate::hooks::{HookWhen, TransactionPackages, collect_hooks, load_hooks, run_hooks};
use crate::log::PaxLogger;
use crate::preflight::{ArchivePlan, below_directory_replacement};
use crate::prepared::PreparedArchive;
use crate::register::{register_package, remove_db_entry};
use crate::removal::{RemovalTarget, remove_package_paths, remove_transaction_package};
use crate::scriptlet::{ScriptletOp, run_scriptlet};

pub struct InstallContext<'a> {
    pub root_dir: &'a Path,
    pub db_path: &'a Path,
    pub architecture: &'a str,
    pub downloaded: &'a [PreparedArchive],
    pub old_install_scripts: &'a HashMap<String, String>,
    pub old_backup_md5: &'a HashMap<String, HashMap<String, String>>,
    pub hook_dirs: &'a [PathBuf],
    pub check_space: bool,
    pub logger: &'a mut PaxLogger,
}

struct IncomingPackage {
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
    let mut archive_plans = HashMap::new();
    for (index, package) in ctx.downloaded.iter().enumerate() {
        eprintln!(
            ":: Checking archive {}/{}: {}",
            index + 1,
            ctx.downloaded.len(),
            package.name()
        );
        package.verify_for_database(ctx.db_path)?;
        let plan = crate::preflight::inspect_transaction_archive(
            package.path(),
            ctx.root_dir,
            Some(ctx.architecture),
        )?;
        archive_plans.insert(package.name(), plan);
    }
    let incoming = prepare_incoming(tx, ctx.downloaded)?;

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
    let installed = read_installed_packages(ctx.db_path)?;
    let incoming_info: Vec<_> = incoming.values().map(|pkg| pkg.info.clone()).collect();
    let steps = execution_plan(tx, &installed, &incoming_info)?;
    let retained_directories = check_file_conflicts_inner(
        ctx.root_dir,
        ctx.db_path,
        &incoming,
        tx,
        &steps,
        Some(&archive_plans),
    )?;
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

    ctx.logger.log_transaction_start();
    let mut failures = Vec::new();
    let result = apply_transaction(
        tx,
        ctx,
        &incoming,
        &incoming_files,
        &retained_directories,
        &steps,
        &hook_packages,
        &mut failures,
    );
    finish_transaction(result, failures, ctx.logger)
}

#[allow(clippy::too_many_arguments)]
fn apply_transaction(
    tx: &Transaction,
    ctx: &mut InstallContext,
    incoming: &HashMap<&str, IncomingPackage>,
    incoming_files: &HashSet<String>,
    retained_directories: &HashSet<String>,
    steps: &[ExecutionStep],
    hook_packages: &TransactionPackages,
    failures: &mut Vec<String>,
) -> Result<()> {
    run_transaction_hooks(
        ctx.root_dir,
        ctx.db_path,
        ctx.hook_dirs,
        &HookWhen::PreTransaction,
        hook_packages,
        ctx.logger,
        failures,
    )?;
    eprintln!(":: Applying package changes...");
    let total = steps.len()
        + steps
            .iter()
            .map(|step| step.remove_before.len())
            .sum::<usize>();
    let mut current = 0;

    // Only retire packages belonging to this incoming slot. A failure must not
    // trigger removal of packages anchored to later, unrelated replacements.
    for step in steps {
        let name = &step.incoming;
        let archive = ctx
            .downloaded
            .iter()
            .find(|archive| archive.name() == name)
            .expect("incoming coverage was validated");
        for removed_name in &step.remove_before {
            let removal = tx
                .removals
                .iter()
                .find(|action| &action.name == removed_name)
                .unwrap();
            let version = removal.version.to_string();
            current += 1;
            eprintln!("({current}/{total}) Removing {removed_name} ({version})...");
            for link in &removal.links {
                if link.reason == RemovalReason::Conflict {
                    eprintln!(
                        "warning: removing {} (conflicts with {})",
                        removal.name, link.incoming
                    );
                }
            }
            remove_transaction_package(
                &RemovalTarget {
                    name: removed_name.clone(),
                    version: version.clone(),
                },
                ctx.root_dir,
                ctx.db_path,
                ctx.logger,
                failures,
                retained_directories,
            )?;
            ctx.logger.log_removed(removed_name, &version);
        }
        let package = &incoming[name.as_str()];
        if let Some(upgrade) = tx.upgrades.iter().find(|upgrade| &upgrade.name == name) {
            let old_version = upgrade.old_version.to_string();
            let new_version = upgrade.new_version.to_string();
            current += 1;
            eprintln!("({current}/{total}) Upgrading {name} ({old_version} -> {new_version})...");
            let reason = get_existing_reason(ctx.db_path, name, &old_version);
            if let Some(script) = &package.install_script {
                run_transaction_scriptlet(
                    failures,
                    script,
                    ScriptletOp::PreUpgrade,
                    &new_version,
                    Some(&old_version),
                    ctx.root_dir,
                    name,
                    ctx.logger,
                );
            }

            let mut retained_paths = incoming_files.clone();
            retained_paths.extend(retained_directories.iter().cloned());
            let old_entry = ctx
                .db_path
                .join("local")
                .join(format!("{name}-{old_version}"));
            // Retain paths taken over by any incoming package, irrespective of execution order.
            remove_package_paths(&old_entry, ctx.root_dir, &retained_paths).map_err(|error| {
                std::io::Error::other(format!(
                    "{name} {old_version}: remove obsolete paths from {}: {error}",
                    old_entry.display()
                ))
            })?;
            let backup_md5 = ctx.old_backup_md5.get(name).cloned().unwrap_or_default();
            let metadata = extract_prepared(archive, ctx.db_path, ctx.root_dir, &backup_md5)?;
            for warning in &metadata.warnings {
                eprintln!("warning: {warning}");
                ctx.logger.log_warning(warning);
            }
            register_package(
                ctx.db_path,
                &metadata,
                reason,
                archive.validations(),
                ctx.root_dir,
            )
            .map_err(|error| {
                std::io::Error::other(format!(
                    "{name}: register {new_version} in {}: {error}",
                    ctx.db_path.display()
                ))
            })?;
            if old_version != new_version {
                remove_db_entry(ctx.db_path, name, &old_version).map_err(|error| {
                    std::io::Error::other(format!(
                        "{name}: remove database entry {old_version} from {}: {error}",
                        ctx.db_path.display()
                    ))
                })?;
            }
            ctx.logger.log_upgraded(name, &old_version, &new_version);
            if let Some(script) = &metadata.install {
                run_transaction_scriptlet(
                    failures,
                    script,
                    ScriptletOp::PostUpgrade,
                    &new_version,
                    Some(&old_version),
                    ctx.root_dir,
                    name,
                    ctx.logger,
                );
            }
        } else if let Some(install) = tx.installs.iter().find(|install| &install.name == name) {
            let version = install.version.to_string();
            current += 1;
            eprintln!("({current}/{total}) Installing {name} ({version})...");
            if let Some(script) = &package.install_script {
                run_transaction_scriptlet(
                    failures,
                    script,
                    ScriptletOp::PreInstall,
                    &version,
                    None,
                    ctx.root_dir,
                    name,
                    ctx.logger,
                );
            }
            let metadata = extract_prepared(archive, ctx.db_path, ctx.root_dir, &HashMap::new())?;
            for warning in &metadata.warnings {
                eprintln!("warning: {warning}");
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
                archive.validations(),
                ctx.root_dir,
            )
            .map_err(|error| {
                std::io::Error::other(format!(
                    "{name}: register {version} in {}: {error}",
                    ctx.db_path.display()
                ))
            })?;
            ctx.logger.log_installed(name, &version);
            if let Some(script) = &metadata.install {
                run_transaction_scriptlet(
                    failures,
                    script,
                    ScriptletOp::PostInstall,
                    &version,
                    None,
                    ctx.root_dir,
                    name,
                    ctx.logger,
                );
            }
        }
    }

    // Never execute all planned post-hooks after a partial filesystem application.
    // This point is reached only after every package has been applied.
    eprintln!(":: Running post-transaction maintenance...");
    run_transaction_hooks(
        ctx.root_dir,
        ctx.db_path,
        ctx.hook_dirs,
        &HookWhen::PostTransaction,
        hook_packages,
        ctx.logger,
        failures,
    )
}

fn extract_prepared(
    archive: &PreparedArchive,
    db_path: &Path,
    root: &Path,
    backups: &HashMap<String, String>,
) -> Result<PackageMetadata> {
    // Hooks and scriptlets ran since preflight; verify the prepared bytes once more.
    archive.verify_for_database(db_path)?;
    // Cleanup has run; no deferred directory is authorized here. In particular,
    // a hook-created child must stop extraction, not trigger recursive removal.
    crate::preflight::inspect_archive(archive.path(), root, None)?;
    extract_package(archive.path(), root, backups).map_err(|error| ExecError::Extraction {
        pkg: archive.name().to_string(),
        message: format!(
            "source {} (prepared {}): {error}",
            archive.source_path().display(),
            archive.path().display()
        ),
    })
}

pub(crate) fn finish_transaction(
    result: Result<()>,
    failures: Vec<String>,
    logger: &mut PaxLogger,
) -> Result<()> {
    match result {
        Ok(()) if failures.is_empty() => {
            logger.log_transaction_completed();
            Ok(())
        }
        Ok(()) => {
            let error = ExecError::MaintenanceIncomplete { failures };
            logger.log_transaction_incomplete(&error.to_string());
            Err(error)
        }
        Err(error) => {
            let mut cause = format!(
                "transaction did not complete; changes may have been partially applied; \
                 inspect package files and database before retrying: {error}"
            );
            if !failures.is_empty() {
                cause.push_str("\nEarlier maintenance failures:\n");
                cause.push_str(&failures.join("\n"));
            }
            logger.log_transaction_failed(&cause);
            Err(std::io::Error::other(cause).into())
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_transaction_scriptlet(
    failures: &mut Vec<String>,
    script: &str,
    op: ScriptletOp,
    new_version: &str,
    old_version: Option<&str>,
    root: &Path,
    name: &str,
    logger: &mut PaxLogger,
) {
    if let Err(error) = run_scriptlet(script, op, new_version, old_version, root, name, logger) {
        failures.push(error.to_string());
    }
}

fn invalid_transaction(message: impl Into<String>) -> ExecError {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into()).into()
}

fn prepare_incoming<'a>(
    tx: &Transaction,
    downloaded: &'a [PreparedArchive],
) -> Result<HashMap<&'a str, IncomingPackage>> {
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
        let version = expected.get(package.name()).ok_or_else(|| {
            invalid_transaction(format!("unexpected prepared package: {}", package.name()))
        })?;
        let metadata = package.info();
        if &metadata.version != version {
            return Err(invalid_transaction(format!(
                "archive identity mismatch for {}: expected {} {}, found {} {}",
                package.source_path().display(),
                package.name(),
                version,
                metadata.name,
                metadata.version,
            )));
        }
        let prepared = IncomingPackage {
            info: metadata.info.clone(),
            files: read_archive_file_list(package.path())?,
            install_script: read_install_script(package.path())?,
        };
        if incoming.insert(package.name(), prepared).is_some() {
            return Err(invalid_transaction(format!(
                "duplicate prepared archive: {}",
                package.name()
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

pub(crate) fn run_transaction_hooks(
    root: &Path,
    db_path: &Path,
    hook_dirs: &[PathBuf],
    when: &HookWhen,
    packages: &TransactionPackages,
    logger: &mut PaxLogger,
    failures: &mut Vec<String>,
) -> Result<()> {
    let hooks = if *when == HookWhen::PreTransaction {
        load_hooks(root, hook_dirs)?
    } else {
        let (hooks, errors) = collect_hooks(root, hook_dirs);
        for error in errors {
            let message = format!("could not load PostTransaction hooks: {error}");
            eprintln!("warning: {message}");
            logger.log_warning(&message);
            failures.push(message);
        }
        hooks
    };
    let local = LocalDb::open(db_path)?;
    failures.extend(run_hooks(
        &hooks,
        when,
        packages,
        root,
        &|dependency| {
            local
                .packages()
                .any(|pkg| package_satisfies_dependency(&pkg.info, dependency))
        },
        logger,
    )?);
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
        // libalpm writes an empty files entry for payload-free metapackages and
        // may omit their zero %SIZE%. A declared nonzero size still indicates damage.
        let empty_package = content.is_empty()
            && files_path.parent().is_some_and(|parent| {
                std::fs::read_to_string(parent.join("desc"))
                    .ok()
                    .is_some_and(|desc| {
                        let mut lines = desc.lines();
                        if lines.any(|line| line == "%SIZE%") {
                            lines.next() == Some("0")
                        } else {
                            let fields = pax_alpm::desc::parse_desc(&desc);
                            pax_alpm::desc::desc_to_package_info(&fields).is_ok_and(|info| {
                                crate::extract::validate_identity(
                                    &info.name,
                                    &info.version.to_string(),
                                )
                                .is_ok()
                            })
                        }
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

fn read_installed_packages(db_path: &Path) -> Result<Vec<PackageInfo>> {
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
    traversed_directories: Vec<PathBuf>,
}

struct OwnershipPath {
    resolved: String,
    spelling: String,
    symlinks: Vec<String>,
    traversed_directories: Vec<PathBuf>,
}

struct PathOwner {
    package: String,
    spelling: String,
    directory: bool,
    retirement: Option<usize>,
}

// A marker distinguishes missing ordinary parents (which extraction may create)
// from missing symlink targets. Normalizing a target lexically would hide dangling
// components in paths such as "missing/../real".
enum OwnershipComponent {
    Part(std::ffi::OsString),
    EndLink,
}

fn resolve_ownership_parent(
    root: &Path,
    parent: &Path,
    file: &str,
    replacements: &HashSet<PathBuf>,
    directories: &HashSet<PathBuf>,
) -> Result<OwnershipParent> {
    use std::collections::VecDeque;

    let mut pending: VecDeque<_> = parent
        .components()
        .map(|part| OwnershipComponent::Part(part.as_os_str().to_os_string()))
        .collect();
    let mut resolved = PathBuf::new();
    let mut symlinks = Vec::new();
    let mut traversed_directories = Vec::new();
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
            traversed_directories.push(candidate.clone());
            resolved = candidate;
            continue;
        }
        if directories.contains(&candidate) {
            traversed_directories.push(candidate.clone());
            resolved = candidate;
            continue;
        }
        let absolute = root.join(&candidate);
        let metadata = match if below_directory_replacement(&candidate, replacements) {
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        } else {
            std::fs::symlink_metadata(&absolute)
        } {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if link_depth != 0 {
                    return Err(invalid_transaction(format!(
                        "{file}: dangling ownership parent target {}",
                        absolute.display()
                    )));
                }
                missing = true;
                traversed_directories.push(candidate.clone());
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
            // Keep namespace dependencies even when a later '..' pops them.
            traversed_directories.push(candidate.clone());
            resolved = candidate;
        } else {
            return Err(invalid_transaction(format!(
                "{file}: ownership parent {} is not a directory",
                absolute.display()
            )));
        }
    }
    Ok(OwnershipParent {
        resolved,
        symlinks,
        traversed_directories,
    })
}

fn ownership_path(
    root: &Path,
    file: &str,
    parents: &mut HashMap<PathBuf, OwnershipParent>,
) -> Result<OwnershipPath> {
    ownership_path_with_directories(root, file, parents, &HashSet::new(), &HashSet::new())
}

fn ownership_path_with_directories(
    root: &Path,
    file: &str,
    parents: &mut HashMap<PathBuf, OwnershipParent>,
    replacements: &HashSet<PathBuf>,
    directories: &HashSet<PathBuf>,
) -> Result<OwnershipPath> {
    let relative = crate::extract::safe_relative_path(Path::new(file))?;
    let name = relative
        .file_name()
        .ok_or_else(|| invalid_transaction(format!("empty ownership path: {file}")))?;
    let parent = relative.parent().unwrap_or(Path::new(""));
    if !parents.contains_key(parent) {
        let resolved = resolve_ownership_parent(root, parent, file, replacements, directories)?;
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
        traversed_directories: parent.traversed_directories.clone(),
    })
}

fn retain_parent_directories(path: &str, directories: &mut HashSet<String>) {
    for parent in Path::new(path).ancestors().skip(1) {
        if let Some(parent) = parent.to_str().filter(|path| !path.is_empty()) {
            directories.insert(parent.to_string());
        }
    }
}

pub(crate) fn retained_removal_directories(
    root_dir: &Path,
    db_path: &Path,
    targets: &[RemovalTarget],
    outgoing_files: &[String],
) -> Result<HashSet<String>> {
    let root = root_dir.canonicalize()?;
    if !root.is_dir() {
        return Err(invalid_transaction(format!(
            "ownership root {} is not a directory",
            root.display()
        )));
    }
    let removing: HashSet<_> = targets
        .iter()
        .map(|target| (target.name.as_str(), target.version.as_str()))
        .collect();
    let mut parents = HashMap::new();
    let mut remaining_directories = HashSet::new();
    for package in read_installed_packages(db_path)? {
        let version = package.version.to_string();
        if removing.contains(&(package.name.as_str(), version.as_str())) {
            continue;
        }
        for file in read_file_list(db_path, &package.name, &version)? {
            let path = ownership_path(&root, &file, &mut parents).map_err(|error| {
                invalid_transaction(format!(
                    "{} {version}: inspect retained ownership of {file}: {error}",
                    package.name
                ))
            })?;
            retain_parent_directories(&path.resolved, &mut remaining_directories);
            if file.ends_with('/') {
                remaining_directories.insert(path.resolved);
            }
        }
    }
    let mut retained = HashSet::new();
    for file in outgoing_files.iter().filter(|file| file.ends_with('/')) {
        let path = ownership_path(&root, file, &mut parents)?;
        if remaining_directories.contains(&path.resolved) {
            // Cleanup uses lexical paths; preserve the outgoing alias spelling.
            retained.insert(file.trim_end_matches('/').to_string());
        }
    }
    Ok(retained)
}

#[cfg(test)]
fn check_file_conflicts(
    root_dir: &Path,
    db_path: &Path,
    incoming: &HashMap<&str, IncomingPackage>,
    tx: &Transaction,
    steps: &[ExecutionStep],
) -> Result<HashSet<String>> {
    check_file_conflicts_inner(root_dir, db_path, incoming, tx, steps, None)
}

fn check_file_conflicts_inner(
    root_dir: &Path,
    db_path: &Path,
    incoming: &HashMap<&str, IncomingPackage>,
    tx: &Transaction,
    steps: &[ExecutionStep],
    plans: Option<&HashMap<&str, ArchivePlan>>,
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
    let mut old_symlink_users: HashMap<String, Vec<(String, String)>> = HashMap::new();
    // Empty conversions have no subtree proof; nonempty ones cannot prove paths
    // resolving outside the traversed candidate either (e.g. through '..').
    let mut old_directory_users: HashMap<PathBuf, Vec<(String, String)>> = HashMap::new();
    let mut old_backups = HashSet::new();
    // Only filter old DB hazards here; this union is never an incoming path view.
    let conversion_candidates: HashSet<PathBuf> = plans
        .into_iter()
        .flat_map(|plans| plans.values())
        .flat_map(|plan| plan.directory_replacements.iter().cloned())
        .collect();
    let leaf_candidates: HashSet<PathBuf> = plans
        .into_iter()
        .flat_map(|plans| plans.values())
        .flat_map(|plan| plan.directory_to_leaf_replacements.iter().cloned())
        .collect();
    let deferred_candidates: HashSet<PathBuf> = plans
        .into_iter()
        .flat_map(|plans| plans.values())
        .flat_map(|plan| plan.deferred_directory_replacements.iter().cloned())
        .collect();
    // Preserve the actual cleanup order, including linked removals within a slot.
    let cleanup_positions: HashMap<_, _> = steps
        .iter()
        .flat_map(|step| {
            step.remove_before
                .iter()
                .chain(std::iter::once(&step.incoming))
        })
        .enumerate()
        .map(|(index, name)| (name.as_str(), index))
        .collect();
    let local_dir = db_path.join("local");
    let retiring_entries: HashMap<_, _> = tx
        .upgrades
        .iter()
        .map(|action| (&action.name, &action.old_version))
        .chain(
            tx.removals
                .iter()
                .map(|action| (&action.name, &action.version)),
        )
        .filter_map(|(name, version)| {
            cleanup_positions
                .get(name.as_str())
                .map(|position| (local_dir.join(format!("{name}-{version}")), *position))
        })
        .collect();
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
                if !conversion_candidates.is_empty() || !leaf_candidates.is_empty() {
                    let mut in_backup = false;
                    for line in content.lines() {
                        if line.starts_with('%') || line.is_empty() {
                            in_backup = line == "%BACKUP%";
                        } else if in_backup {
                            let file = line.split('\t').next().unwrap();
                            let ownership = ownership_path(&root, file, &mut parents)?;
                            for directory in &ownership.traversed_directories {
                                if leaf_candidates.contains(directory)
                                    && (!deferred_candidates.contains(directory)
                                        || !Path::new(&ownership.resolved).starts_with(directory))
                                {
                                    old_directory_users
                                        .entry(directory.clone())
                                        .or_default()
                                        .push((name.clone(), file.to_string()));
                                }
                            }
                            old_backups.insert(ownership.resolved);
                            for symlink in ownership.symlinks {
                                if conversion_candidates.contains(Path::new(&symlink))
                                    || below_directory_replacement(
                                        Path::new(&symlink),
                                        &deferred_candidates,
                                    )
                                {
                                    old_symlink_users
                                        .entry(symlink)
                                        .or_default()
                                        .push((name.clone(), file.to_string()));
                                }
                            }
                        }
                    }
                }
                for file in parse_file_list(&content) {
                    let ownership = ownership_path(&root, &file, &mut parents)?;
                    for directory in &ownership.traversed_directories {
                        if leaf_candidates.contains(directory)
                            && (!deferred_candidates.contains(directory)
                                || !Path::new(&ownership.resolved).starts_with(directory))
                        {
                            old_directory_users
                                .entry(directory.clone())
                                .or_default()
                                .push((name.clone(), file.clone()));
                        }
                    }
                    for symlink in &ownership.symlinks {
                        if conversion_candidates.contains(Path::new(symlink))
                            || below_directory_replacement(Path::new(symlink), &deferred_candidates)
                        {
                            old_symlink_users
                                .entry(symlink.clone())
                                .or_default()
                                .push((name.clone(), file.clone()));
                        }
                    }
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
                            retirement: retiring_entries.get(&entry.path()).copied(),
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
    let mut lexical_owners: HashMap<String, (&str, bool)> = HashMap::new();
    let mut deferred_directories = Vec::new();
    let mut conflicts = Vec::new();
    for (name, package) in incoming {
        // A package sees only its own earlier explicit conversions, never the
        // future namespace of another archive or the old DB's parent cache.
        let plan = plans.and_then(|plans| plans.get(*name));
        // File lists contain destinations, not hardlink sources. Preserve the
        // filesystem dependencies proved while inspecting the whole archive.
        if let Some(plan) = plan {
            for directory in plan
                .directory_to_leaf_replacements
                .difference(&plan.deferred_directory_replacements)
            {
                if let Some(users) = old_directory_users.get(directory) {
                    conflicts.push(format!(
                        "  {name}: /{} cannot become a non-directory: old database paths traverse this directory: {users:?}; cleanup namespace preservation is not proven",
                        directory.display(),
                    ));
                }
            }
            for directory in plan.traversed_directories.intersection(&leaf_candidates) {
                conflicts.push(format!(
                    "  {name}: archive payload or hardlink source traverses directory /{} converted to a non-directory in this transaction; namespace preservation is not proven",
                    directory.display(),
                ));
            }
            for symlink in &plan.traversed_symlinks {
                let symlink = symlink.to_str().ok_or_else(|| {
                    invalid_transaction(format!(
                        "{name}: non-UTF-8 archive symlink dependency {}",
                        symlink.display()
                    ))
                })?;
                if let Some(owners) = old_owners.get(symlink) {
                    for owner in owners {
                        if changing.contains(owner.package.as_str()) {
                            conflicts.push(format!(
                                "  {name}: archive payload or hardlink source traverses filesystem symlink /{symlink} owned by changing package {}; namespace preservation is not proven",
                                owner.package,
                            ));
                        }
                    }
                }
            }
        }
        let mut new_parents = HashMap::new();
        let mut replacements = HashSet::new();
        let mut directories = HashSet::new();
        // Reserve every actual backup's candidate, even if the later three-way
        // decision keeps the old file. Candidates are not package files or hook targets.
        let backup_destinations: Vec<_> = plan
            .into_iter()
            .flat_map(|plan| &plan.backups)
            .map(|path| format!("{path}.pacnew"))
            .collect();
        for (file, backup_destination) in package
            .files
            .iter()
            .map(|file| (file, false))
            .chain(backup_destinations.iter().map(|file| (file, true)))
        {
            let directory = file.ends_with('/');
            let ownership = ownership_path_with_directories(
                &root,
                file,
                &mut new_parents,
                &replacements,
                &directories,
            )?;
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
            if !directory
                && !backup_destination
                && plan.is_some_and(|plan| {
                    plan.deferred_directory_replacements
                        .contains(Path::new(&path))
                })
            {
                deferred_directories.push((*name, path.clone(), ownership.spelling.clone()));
            }
            let conversion = directory
                && plan.is_some_and(|plan| plan.directory_replacements.contains(Path::new(&path)));
            if conversion {
                if !old_owners.get(&path).is_some_and(|owners| {
                    !owners.is_empty()
                        && owners.iter().all(|owner| {
                            !owner.directory && changing.contains(owner.package.as_str())
                        })
                }) {
                    conflicts.push(format!(
                        "  {name}: /{path} symlink-to-directory replacement requires changing old owners with non-directory records"
                    ));
                }
                if let Some(users) = old_symlink_users.get(&path) {
                    for (owner, old_file) in users {
                        conflicts.push(format!(
                            "  {name}: /{path} cannot become a directory: old database path /{old_file} from {owner} traverses this symlink; cleanup and backup namespace preservation is not proven"
                        ));
                    }
                }
                if old_backups.contains(&path) {
                    conflicts.push(format!(
                        "  {name}: /{path} cannot replace a symlink declared as an installed backup"
                    ));
                }
                if replacements.insert(PathBuf::from(&path)) {
                    new_parents.clear();
                }
            }
            // Model only directories created inside this archive's converted
            // subtree; unrelated live aliases must remain visible to the guards.
            if !replacements.is_empty() {
                for parent in Path::new(&path).ancestors().skip(usize::from(!directory)) {
                    if replacements.contains(parent)
                        || below_directory_replacement(parent, &replacements)
                    {
                        directories.insert(parent.to_path_buf());
                    }
                }
            }
            lexical_owners.insert(file.trim_end_matches('/').to_string(), (*name, directory));
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
                    // Another upgraded package is still retained: its cleanup
                    // must not remove a sidecar staged earlier in this transaction.
                    let retained_backup_owner = backup_destination
                        && owner.package != *name
                        && !removals.contains_key(owner.package.as_str());
                    if retained_backup_owner
                        || (!changing.contains(owner.package.as_str())
                            && (conversion || !(directory && owner.directory)))
                    {
                        conflicts.push(format!(
                            "  {name}: /{path} already owned by {}",
                            owner.package
                        ));
                    }
                    if (conversion || !(directory && owner.directory))
                        && upgraded.contains(owner.package.as_str())
                        && owner.spelling != ownership.spelling
                    {
                        conflicts.push(format!(
                            "  {name}: /{} and /{} resolve to /{path}; cross-spelling transfer from upgraded owner {} is unsupported (cleanup and backup handling use lexical paths)",
                            ownership.spelling, owner.spelling, owner.package,
                        ));
                    }
                    if (conversion || !(directory && owner.directory))
                        && removals.get(owner.package.as_str()).is_some_and(|slot| {
                            positions
                                .get(name)
                                .is_some_and(|incoming_slot| slot > incoming_slot)
                        })
                    {
                        conflicts.push(format!("  {name}: /{path} would be installed before old owner {} is removed; linked removal would delete the new payload", owner.package));
                    }
                    if conversion
                        && owner.package != *name
                        && upgraded.contains(owner.package.as_str())
                        && positions.get(owner.package.as_str()).is_some_and(|slot| {
                            positions
                                .get(name)
                                .is_some_and(|incoming_slot| slot > incoming_slot)
                        })
                    {
                        conflicts.push(format!(
                            "  {name}: /{path} would replace a symlink before old owner {} is upgraded",
                            owner.package
                        ));
                    }
                }
            }
            // Existing unowned .pacnew files and final symlinks/hardlinks are
            // legitimate staging destinations, not payload conflicts.
            if backup_destination || below_directory_replacement(Path::new(&path), &replacements) {
                continue;
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
    for (name, path, spelling) in deferred_directories {
        let reject = |reason: String| {
            ExecError::FileConflict(format!(
                "  {name}: /{path}: cannot replace a nonempty directory: {reason}"
            ))
        };
        if retained_directories.contains(&path) {
            return Err(reject(
                "directory is needed by retained or incoming descendants".into(),
            ));
        }
        if let Some(backup) = old_backups
            .iter()
            .find(|backup| Path::new(backup).starts_with(&path))
        {
            return Err(reject(format!(
                "installed backup /{backup} must be preserved"
            )));
        }
        if let Some((link, users)) = old_symlink_users
            .iter()
            .find(|(link, _)| Path::new(link).starts_with(&path))
        {
            return Err(reject(format!(
                "old database paths traverse /{link}: {users:?}; cleanup namespace preservation is not proven"
            )));
        }
        if let Some(users) = old_directory_users.get(Path::new(&path)) {
            return Err(reject(format!(
                "old database paths traverse directory /{path} before resolving outside it: {users:?}; cleanup namespace preservation is not proven"
            )));
        }
        let position = cleanup_positions
            .get(name)
            .copied()
            .ok_or_else(|| reject("missing execution slot".into()))?;
        // Even an absent DB path is a future cleanup operation. After this
        // directory becomes a symlink, late cleanup could unlink its new target.
        for (old_path, owners) in &old_owners {
            let Ok(relative) = Path::new(old_path).strip_prefix(&path) else {
                continue;
            };
            let lexical = Path::new(&spelling).join(relative);
            for owner in owners {
                if Path::new(&owner.spelling) != lexical {
                    return Err(reject(format!(
                        "old database path /{old_path}: owner {} uses unproven cleanup spelling /{}",
                        owner.package, owner.spelling
                    )));
                }
                if !owner
                    .retirement
                    .is_some_and(|retirement| retirement <= position)
                {
                    return Err(reject(format!(
                        "old database path /{old_path}: owner {} does not retire this entry before directory conversion",
                        owner.package
                    )));
                }
            }
        }
        let mut pending = vec![(PathBuf::from(&path), PathBuf::from(&spelling), position)];
        while let Some((current, lexical, deadline)) = pending.pop() {
            let absolute = root.join(&current);
            let metadata = std::fs::symlink_metadata(&absolute).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "{name}: inspect deferred directory entry {}: {error}",
                        absolute.display()
                    ),
                )
            })?;
            let current_name = current.to_str().ok_or_else(|| {
                reject(format!(
                    "non-UTF-8 entry {} has no exact database ownership",
                    absolute.display()
                ))
            })?;
            let owners = old_owners
                .get(current_name)
                .filter(|owners| !owners.is_empty())
                .ok_or_else(|| {
                    reject(format!(
                        "/{current_name} has no exact old database ownership"
                    ))
                })?;
            let mut last_cleanup = 0;
            for owner in owners {
                if Path::new(&owner.spelling) != lexical || owner.directory != metadata.is_dir() {
                    return Err(reject(format!(
                        "/{current_name}: owner {} has a different spelling or entry type (/{})",
                        owner.package, owner.spelling
                    )));
                }
                let retirement = owner.retirement.filter(|retirement| *retirement <= deadline).ok_or_else(|| reject(format!(
                    "/{current_name}: owner {} does not retire this entry before extraction and its parent cleanup", owner.package
                )))?;
                last_cleanup = last_cleanup.max(retirement);
            }
            let filename = current
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if filename.ends_with(".pacsave")
                || filename
                    .rsplit_once(".pacsave.")
                    .is_some_and(|(_, suffix)| {
                        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
                    })
            {
                return Err(reject(format!(
                    "/{current_name} is a preserved .pacsave path"
                )));
            }
            // lstat leaves links as leaves: never walk their targets. Every real
            // subdirectory must have a cleanup after its children; the candidate
            // root alone may be retained for extraction's empty-only remove_dir.
            if metadata.is_dir() {
                let deadline = if current == Path::new(&path) {
                    deadline
                } else {
                    last_cleanup
                };
                let children = std::fs::read_dir(&absolute).map_err(|error| {
                    std::io::Error::new(
                        error.kind(),
                        format!(
                            "{name}: read deferred directory {}: {error}",
                            absolute.display()
                        ),
                    )
                })?;
                for child in children {
                    let child = child.map_err(|error| {
                        std::io::Error::new(
                            error.kind(),
                            format!(
                                "{name}: read entry in deferred directory {}: {error}",
                                absolute.display()
                            ),
                        )
                    })?;
                    pending.push((
                        current.join(child.file_name()),
                        lexical.join(child.file_name()),
                        deadline,
                    ));
                }
            }
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
    use crate::download::DownloadedPackage;
    use crate::prepared::ArchivePolicy;
    use crate::removal::remove_package_paths;
    use pax_core::config::{SigLevel, SigTrust};
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

    fn backup_test_archive(
        dir: &Path,
        name: &str,
        version: &str,
        payload: &str,
    ) -> DownloadedPackage {
        let path = dir.join(format!("{name}-{version}.pkg.tar"));
        let mut builder = tar::Builder::new(std::fs::File::create(&path).unwrap());
        let info = format!(
            "pkgname = {name}\npkgver = {version}\narch = any\nbackup = {payload}\nbackup = missing\n"
        );
        for (path, contents) in [
            (".PKGINFO", info.as_bytes()),
            (payload, b"new config".as_slice()),
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

    fn prepare_archives(db: &Path, raw: &[DownloadedPackage]) -> Vec<PreparedArchive> {
        let gpg_dir = tempfile::tempdir().unwrap();
        raw.iter()
            .map(|package| {
                PreparedArchive::prepare(
                    &package.path,
                    db,
                    gpg_dir.path(),
                    ArchivePolicy {
                        expected_sha256: None,
                        sig_level: SigLevel::Never,
                        sig_trust: SigTrust::TrustedOnly,
                    },
                )
                .unwrap()
            })
            .collect()
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
    fn empty_metapackage_without_size_has_no_files() {
        let temp = tempfile::tempdir().unwrap();
        let entry = temp.path().join("local/metapackage-1-1");
        std::fs::create_dir_all(&entry).unwrap();
        let desc = "%NAME%\nmetapackage\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n";
        std::fs::write(entry.join("desc"), desc).unwrap();
        std::fs::write(entry.join("files"), "").unwrap();
        assert!(
            read_file_list(temp.path(), "metapackage", "1-1")
                .unwrap()
                .is_empty()
        );
        for size in ["12\n", "invalid\n", ""] {
            std::fs::write(entry.join("desc"), format!("{desc}%SIZE%\n{size}")).unwrap();
            assert!(read_file_list(temp.path(), "metapackage", "1-1").is_err());
        }
        for desc in ["", "%NAME%\nmetapackage\n\n", "%VERSION%\n1-1\n\n"] {
            std::fs::write(entry.join("desc"), desc).unwrap();
            assert!(read_file_list(temp.path(), "metapackage", "1-1").is_err());
        }
        std::fs::remove_file(entry.join("desc")).unwrap();
        assert!(read_file_list(temp.path(), "metapackage", "1-1").is_err());
    }

    #[test]
    fn partial_failure_keeps_operation_and_maintenance_errors_without_state_files() {
        let temp = tempfile::tempdir().unwrap();
        let log = temp.path().join("log");
        let mut logger = PaxLogger::open(&log);
        logger.log_transaction_start();
        let error = finish_transaction(
            Err(std::io::Error::other("example 2-1: extract /root/file: disk full").into()),
            vec!["example::pre_upgrade: exit status 42".into()],
            &mut logger,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("partially applied"), "{error}");
        assert!(error.contains("extract /root/file: disk full"), "{error}");
        assert!(error.contains("pre_upgrade: exit status 42"), "{error}");
        let contents = std::fs::read_to_string(&log).unwrap();
        assert!(contents.contains("transaction failed"));
        assert!(!contents.contains("transaction completed"));
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
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
        let downloaded = prepare_archives(&db, &[first, second]);
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
    fn partial_application_preserves_later_replacement_and_skips_planned_post_hooks() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        std::fs::create_dir(&root).unwrap();
        let old = alias_test_entry(&db, "obsolete", "%FILES%\nold\n\n");
        std::fs::write(root.join("old"), "keep until third").unwrap();
        let raw: Vec<_> = ["first", "second", "third"]
            .iter()
            .map(|name| alias_test_archive(temp.path(), name, "1-1", name))
            .collect();
        let prepared = prepare_archives(&db, &raw);
        let mut tx = transaction(&["first", "second", "third"]);
        tx.removals.push(pax_resolver::RemovalAction {
            name: "obsolete".into(),
            version: Version::parse("1-1").unwrap(),
            links: vec![pax_resolver::RemovalLink {
                incoming: "third".into(),
                reason: RemovalReason::Replaced,
            }],
        });
        let incoming = prepare_incoming(&tx, &prepared).unwrap();
        let infos: Vec<_> = incoming
            .values()
            .map(|package| package.info.clone())
            .collect();
        let installed = read_installed_packages(&db).unwrap();
        let steps = execution_plan(&tx, &installed, &infos).unwrap();
        let plans = prepared
            .iter()
            .map(|archive| {
                archive.verify_for_database(&db).unwrap();
                (
                    archive.name(),
                    crate::preflight::inspect_archive(archive.path(), &root, Some("auto")).unwrap(),
                )
            })
            .collect();
        let retained =
            check_file_conflicts_inner(&root, &db, &incoming, &tx, &steps, Some(&plans)).unwrap();
        let incoming_files = incoming
            .values()
            .flat_map(|package| package.files.iter().cloned())
            .collect();
        let packages = transaction_packages(&tx, &HashSet::from(["old".into()]), &incoming_files);
        // Model damage after preflight, before this archive's extraction turn.
        std::fs::set_permissions(prepared[1].path(), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        std::fs::write(prepared[1].path(), b"damaged prepared archive").unwrap();
        std::fs::set_permissions(prepared[1].path(), std::fs::Permissions::from_mode(0o400))
            .unwrap();
        let hooks = [masked_hooks(temp.path())];
        std::fs::write(hooks[0].join("00-post-probe.hook"),
            "[Trigger]\nType = Package\nOperation = Install\nTarget = *\n[Action]\nWhen = PostTransaction\nExec = /must-not-run\n").unwrap();
        let log = temp.path().join("log");
        let mut logger = PaxLogger::open(&log);
        logger.log_transaction_start();
        let mut failures = Vec::new();
        let result = apply_transaction(
            &tx,
            &mut InstallContext {
                root_dir: &root,
                db_path: &db,
                architecture: "auto",
                downloaded: &prepared,
                old_install_scripts: &HashMap::new(),
                old_backup_md5: &HashMap::new(),
                hook_dirs: &hooks,
                check_space: false,
                logger: &mut logger,
            },
            &incoming,
            &incoming_files,
            &retained,
            &steps,
            &packages,
            &mut failures,
        );
        let error = finish_transaction(result, failures, &mut logger)
            .unwrap_err()
            .to_string();
        assert!(error.contains("second"), "{error}");
        assert!(error.contains("partially applied"), "{error}");
        assert_eq!(std::fs::read(root.join("first")).unwrap(), b"new payload");
        assert!(db.join("local/first-1-1/desc").is_file());
        for name in ["second", "third"] {
            assert!(!root.join(name).exists());
            assert!(!db.join(format!("local/{name}-1-1")).exists());
        }
        assert_eq!(
            std::fs::read(root.join("old")).unwrap(),
            b"keep until third"
        );
        assert!(old.join("desc").is_file());
        assert!(!db.join("pax-transactions").exists());
        let log = std::fs::read_to_string(log).unwrap();
        assert!(!log.contains("00-post-probe"));
        assert!(!log.contains("transaction completed"));
    }

    #[test]
    fn applied_packages_with_failed_scriptlets_report_incomplete_maintenance() {
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
        drop(builder);
        let downloaded = prepare_archives(&db, &[downloaded]);

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
        assert!(error.contains("maintenance is incomplete"), "{error}");
        assert_eq!(
            std::fs::read_to_string(root.join("file")).unwrap(),
            "payload"
        );
        assert!(db.join("local/example-1-1/desc").exists());
        drop(downloaded);
        assert!(error.contains("pre_install"));
        assert!(error.contains("post_install"));
        assert!(!db.join("pax-transactions").exists());
        assert!(pax_alpm::DbLock::acquire_with_timeout(&db, std::time::Duration::ZERO).is_ok());
        let log = std::fs::read_to_string(log).unwrap();
        assert!(log.contains("transaction incomplete"));
        assert!(!log.contains("transaction completed"));
        assert!(!log.contains("unmatched"));
    }

    #[test]
    fn prepared_archive_survives_source_changes_and_is_cleaned_after_success() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        for remove_source in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let db = temp.path().join("db");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::create_dir_all(db.join("local")).unwrap();
            std::fs::write(root.join("sentinel"), "keep").unwrap();
            let _lock = pax_alpm::DbLock::acquire(&db).unwrap();
            let raw = archive(temp.path(), "example", "example", "1-1");
            let original = std::fs::read(&raw.path).unwrap();
            let prepared = prepare_archives(&db, std::slice::from_ref(&raw));
            let staged_path = prepared[0].path().to_path_buf();
            let staged_directory = staged_path.parent().unwrap().to_path_buf();
            assert_ne!(staged_path, raw.path);
            if remove_source {
                std::fs::remove_file(&raw.path).unwrap();
                assert!(!raw.path.exists());
            } else {
                std::fs::write(&raw.path, b"not an archive anymore").unwrap();
                assert_eq!(std::fs::read(&raw.path).unwrap(), b"not an archive anymore");
            }
            assert_eq!(std::fs::read(&staged_path).unwrap(), original);
            let hooks = masked_hooks(temp.path());
            let log = temp.path().join("log");
            let mut logger = PaxLogger::open(&log);
            execute_transaction(
                &transaction(&["example"]),
                &mut InstallContext {
                    root_dir: &root,
                    db_path: &db,
                    architecture: "auto",
                    downloaded: &prepared,
                    old_install_scripts: &HashMap::new(),
                    old_backup_md5: &HashMap::new(),
                    hook_dirs: &[hooks],
                    check_space: false,
                    logger: &mut logger,
                },
            )
            .unwrap();
            assert_eq!(
                std::fs::read_to_string(root.join("file")).unwrap(),
                "contents"
            );
            assert_eq!(
                std::fs::read_to_string(root.join("sentinel")).unwrap(),
                "keep"
            );
            let desc = std::fs::read_to_string(db.join("local/example-1-1/desc")).unwrap();
            assert!(desc.contains("%NAME%\nexample\n"));
            assert!(desc.contains("%VERSION%\n1-1\n"));
            assert!(!db.join("pax-transactions").exists());
            assert!(
                std::fs::read_to_string(log)
                    .unwrap()
                    .contains("transaction completed")
            );
            assert_eq!(std::fs::read(&staged_path).unwrap(), original);
            drop(prepared);
            assert!(!staged_directory.exists());
            assert_eq!(
                std::fs::read_to_string(root.join("file")).unwrap(),
                "contents"
            );
            assert!(db.join("local/example-1-1/desc").is_file());
        }
    }

    #[test]
    fn tampered_prepared_archive_stops_execution_before_hooks_or_mutation() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(db.join("local")).unwrap();
        std::fs::write(root.join("sentinel"), "keep").unwrap();
        let _lock = pax_alpm::DbLock::acquire(&db).unwrap();
        let raw = [
            alias_test_archive(temp.path(), "first", "1-1", "first-file"),
            alias_test_archive(temp.path(), "second", "1-1", "second-file"),
        ];
        let prepared = prepare_archives(&db, &raw);
        let staged_directories: Vec<_> = prepared
            .iter()
            .map(|archive| archive.path().parent().unwrap().to_path_buf())
            .collect();
        let original = std::fs::read(prepared[1].path()).unwrap();
        let mut tampered = original.clone();
        let offset = tampered
            .windows(b"new payload".len())
            .position(|bytes| bytes == b"new payload")
            .unwrap();
        tampered[offset..offset + b"bad payload".len()].copy_from_slice(b"bad payload");
        std::fs::set_permissions(prepared[1].path(), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        std::fs::write(prepared[1].path(), &tampered).unwrap();
        std::fs::set_permissions(prepared[1].path(), std::fs::Permissions::from_mode(0o400))
            .unwrap();
        assert_eq!(std::fs::read(&raw[1].path).unwrap(), original);
        let hooks = masked_hooks(temp.path());
        std::fs::write(hooks.join("00-prepared-probe.hook"),
            "[Trigger]\nType = Package\nOperation = Install\nTarget = *\n[Action]\nWhen = PreTransaction\nExec = /must-not-run\nAbortOnFail\n").unwrap();
        let log = temp.path().join("log");
        let mut logger = PaxLogger::open(&log);
        let error = execute_transaction(
            &transaction(&["first", "second"]),
            &mut InstallContext {
                root_dir: &root,
                db_path: &db,
                architecture: "auto",
                downloaded: &prepared,
                old_install_scripts: &HashMap::new(),
                old_backup_md5: &HashMap::new(),
                hook_dirs: &[hooks],
                check_space: false,
                logger: &mut logger,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("verify prepared package second"), "{error}");
        assert!(error.contains("SHA-256 mismatch"), "{error}");
        assert_eq!(
            std::fs::read_to_string(root.join("sentinel")).unwrap(),
            "keep"
        );
        assert!(!root.join("first-file").exists());
        assert!(!root.join("second-file").exists());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(db.join("local")).unwrap().count(), 0);
        assert!(!db.join("pax-transactions").exists());

        assert!(
            !std::fs::read_to_string(log)
                .unwrap()
                .contains("transaction started")
        );
        drop(prepared);
        assert!(
            staged_directories
                .iter()
                .all(|directory| !directory.exists())
        );
    }

    #[test]
    fn validates_every_archive_and_requires_every_download() {
        let temp = tempfile::tempdir().unwrap();
        let tx = transaction(&["first", "second"]);
        let first = archive(temp.path(), "first", "first", "1-1");
        let wrong_name = archive(temp.path(), "second", "unexpected", "1-1");
        let prepared = prepare_archives(temp.path(), &[first, wrong_name]);
        assert!(prepare_incoming(&tx, &prepared).is_err());
        let first = archive(temp.path(), "first", "first", "1-1");
        let wrong_version = archive(temp.path(), "second", "second", "2-1");
        let prepared = prepare_archives(temp.path(), &[first, wrong_version]);
        assert!(prepare_incoming(&tx, &prepared).is_err());
        let first = archive(temp.path(), "first", "first", "1-1");
        let prepared = prepare_archives(temp.path(), &[first]);
        assert!(matches!(
            prepare_incoming(&tx, &prepared),
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
        let downloaded = prepare_archives(
            &db,
            &[archive(temp.path(), "replacement", "replacement", "1-1")],
        );
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
        let mut incoming = HashMap::from([
            (
                "first",
                IncomingPackage {
                    info: package_info("first"),
                    files: vec!["shared/".into()],
                    install_script: None,
                },
            ),
            (
                "second",
                IncomingPackage {
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
    fn backup_destinations_allow_unowned_sidecars_but_reject_retained_ownership() {
        use std::os::unix::fs::MetadataExt;

        for kind in ["absent", "regular", "symlink", "hardlink"] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let db = temp.path().join("db");
            std::fs::create_dir_all(root.join("real")).unwrap();
            std::os::unix::fs::symlink("real", root.join("alias")).unwrap();
            std::fs::write(root.join("real/sentinel"), "keep").unwrap();
            std::fs::write(root.join("missing.pacnew"), "declaration without payload").unwrap();
            let entry =
                alias_test_entry(&db, "other", "%FILES%\nreal/sentinel\nmissing.pacnew\n\n");
            let sidecar = root.join("real/config.pacnew");
            match kind {
                "absent" => {}
                "regular" => std::fs::write(&sidecar, "previous pacnew").unwrap(),
                "symlink" => std::os::unix::fs::symlink("sentinel", &sidecar).unwrap(),
                "hardlink" => std::fs::hard_link(root.join("real/sentinel"), &sidecar).unwrap(),
                _ => unreachable!(),
            }
            let inode = std::fs::symlink_metadata(&sidecar)
                .ok()
                .map(|meta| meta.ino());
            let raw = backup_test_archive(temp.path(), "config", "1-1", "alias/config");
            let plan = crate::preflight::inspect_archive(&raw.path, &root, Some("auto")).unwrap();
            assert_eq!(plan.backups, ["alias/config"]);

            let plans = HashMap::from([("config", plan)]);
            let incoming = HashMap::from([(
                "config",
                IncomingPackage {
                    info: package_info("config"),
                    files: read_archive_file_list(&raw.path).unwrap(),
                    install_script: None,
                },
            )]);
            let tx = transaction(&["config"]);
            let steps = simple_steps(&tx);
            let directories =
                check_file_conflicts_inner(&root, &db, &incoming, &tx, &steps, Some(&plans))
                    .unwrap();
            assert!(directories.contains("real"));

            std::fs::write(
                entry.join("files"),
                "%FILES%\nreal/sentinel\nmissing.pacnew\nreal/config.pacnew\n\n",
            )
            .unwrap();
            // The ordinary payload has no conflict; only the backup candidate is owned.
            assert!(check_file_conflicts(&root, &db, &incoming, &tx, &steps).is_ok());
            let error =
                check_file_conflicts_inner(&root, &db, &incoming, &tx, &steps, Some(&plans))
                    .unwrap_err();
            assert!(
                matches!(&error, ExecError::FileConflict(_)),
                "{kind}: {error}"
            );
            assert!(
                error
                    .to_string()
                    .contains("/real/config.pacnew already owned by other")
            );
            assert_eq!(
                std::fs::symlink_metadata(&sidecar)
                    .ok()
                    .map(|meta| meta.ino()),
                inode
            );
            if kind == "symlink" {
                assert_eq!(std::fs::read_link(&sidecar).unwrap(), Path::new("sentinel"));
            }
            if kind != "absent" {
                let expected = if kind == "regular" {
                    "previous pacnew"
                } else {
                    "keep"
                };
                assert_eq!(std::fs::read_to_string(&sidecar).unwrap(), expected);
            }
            assert_eq!(
                std::fs::read_to_string(root.join("real/sentinel")).unwrap(),
                "keep"
            );
            assert_eq!(
                std::fs::read_to_string(root.join("missing.pacnew")).unwrap(),
                "declaration without payload"
            );
            assert!(!root.join("real/config").exists());
            assert!(!db.join("pax-transactions").exists());
        }
    }

    #[test]
    fn backup_destination_conflicts_stop_execution_before_hooks_or_payload() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        for upgrade in [false, true] {
            for collision in [
                "retained",
                "incoming-first",
                "incoming-last",
                "incoming-child",
            ] {
                let temp = tempfile::tempdir().unwrap();
                let root = temp.path().join("root");
                let db = temp.path().join("db");
                std::fs::create_dir_all(root.join("real")).unwrap();
                std::fs::create_dir_all(db.join("local")).unwrap();
                std::os::unix::fs::symlink("real", root.join("alias")).unwrap();
                std::fs::write(root.join("sentinel"), "keep").unwrap();
                let mut tx = transaction(&["config"]);
                let version = if upgrade { "2-1" } else { "1-1" };
                let mut old_entries = Vec::new();
                if upgrade {
                    tx.installs.clear();
                    tx.upgrades.push(alias_test_upgrade("config"));
                    let baseline = format!("{:x}", md5::compute("original"));
                    let files =
                        format!("%FILES%\nalias/config\n\n%BACKUP%\nalias/config\t{baseline}\n\n");
                    let entry = alias_test_entry(&db, "config", &files);
                    old_entries.push((entry, files));
                    std::fs::write(root.join("real/config"), "local changes").unwrap();
                }
                let mut raw = vec![backup_test_archive(
                    temp.path(),
                    "config",
                    version,
                    "alias/config",
                )];
                if collision == "retained" {
                    let files = "%FILES%\nreal/config.pacnew\n\n";
                    let entry = alias_test_entry(&db, "other", files);
                    old_entries.push((entry, files.to_string()));
                    std::fs::write(root.join("real/config.pacnew"), "owned sidecar").unwrap();
                } else {
                    let payload = if collision == "incoming-child" {
                        "real/config.pacnew/child"
                    } else {
                        "real/config.pacnew"
                    };
                    raw.push(alias_test_archive(temp.path(), "other", "1-1", payload));
                    tx.installs.extend(transaction(&["other"]).installs);
                    tx.package_order.push("other".into());
                    if collision == "incoming-first" {
                        tx.package_order.reverse();
                    }
                }
                let prepared = prepare_archives(&db, &raw);
                let incoming = prepare_incoming(&tx, &prepared).unwrap();
                let installed = read_installed_packages(&db).unwrap();
                let infos: Vec<_> = incoming
                    .values()
                    .map(|package| package.info.clone())
                    .collect();
                let steps = execution_plan(&tx, &installed, &infos).unwrap();
                assert!(check_file_conflicts(&root, &db, &incoming, &tx, &steps).is_ok());
                let hooks = masked_hooks(temp.path());
                std::fs::write(hooks.join("00-backup-ownership-probe.hook"),
                    "[Trigger]\nType = Package\nOperation = Install\nOperation = Upgrade\nTarget = *\n[Action]\nWhen = PreTransaction\nExec = /must-not-run\nAbortOnFail\n").unwrap();
                let log = temp.path().join("log");
                let mut logger = PaxLogger::open(&log);
                let old_descs: Vec<_> = old_entries
                    .iter()
                    .map(|(entry, _)| std::fs::read(entry.join("desc")).unwrap())
                    .collect();
                let error = execute_transaction(
                    &tx,
                    &mut InstallContext {
                        root_dir: &root,
                        db_path: &db,
                        architecture: "auto",
                        downloaded: &prepared,
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
                    "{collision}: {error}"
                );
                assert!(error.to_string().contains("config.pacnew"), "{error}");
                let expected = match collision {
                    "retained" => "already owned by other",
                    "incoming-child" => "must remain a directory",
                    _ => "also supplied by",
                };
                assert!(error.to_string().contains(expected), "{error}");
                assert_eq!(
                    std::fs::read_to_string(root.join("sentinel")).unwrap(),
                    "keep"
                );
                if upgrade {
                    assert_eq!(
                        std::fs::read_to_string(root.join("real/config")).unwrap(),
                        "local changes"
                    );
                } else {
                    assert!(!root.join("real/config").exists());
                }
                if collision == "retained" {
                    assert_eq!(
                        std::fs::read_to_string(root.join("real/config.pacnew")).unwrap(),
                        "owned sidecar"
                    );
                } else {
                    assert!(!root.join("real/config.pacnew").exists());
                }
                assert_eq!(
                    std::fs::read_link(root.join("alias")).unwrap(),
                    Path::new("real")
                );
                for ((entry, files), desc) in old_entries.iter().zip(&old_descs) {
                    assert_eq!(
                        std::fs::read_to_string(entry.join("files")).unwrap(),
                        *files
                    );
                    assert_eq!(std::fs::read(entry.join("desc")).unwrap(), *desc);
                }
                assert_eq!(
                    std::fs::read_dir(db.join("local")).unwrap().count(),
                    old_entries.len()
                );
                assert!(!db.join("pax-transactions").exists());
                assert!(
                    !std::fs::read_to_string(log)
                        .unwrap()
                        .contains("transaction started")
                );
            }
        }
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
        let incoming = HashMap::from([
            (
                "early",
                IncomingPackage {
                    info: package_info("early"),
                    files: vec!["alias/shared".into()],
                    install_script: None,
                },
            ),
            (
                "late",
                IncomingPackage {
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
                let mut incoming = HashMap::from([(
                    "old",
                    IncomingPackage {
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
            let later_name = if upgrade { "old" } else { "late" };
            let incoming = HashMap::from([
                (
                    "early",
                    IncomingPackage {
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
            let incoming = HashMap::from([(
                "new",
                IncomingPackage {
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
            assert_eq!(
                path.traversed_directories,
                [
                    PathBuf::from("real"),
                    PathBuf::from("real/sub"),
                    PathBuf::from("real/implicit")
                ]
            );
            assert_eq!(parents.len(), 1);
        }
        let link = ownership_path(&root, "alias1", &mut parents).unwrap();
        assert_eq!(link.resolved, "alias1");
        assert!(link.symlinks.is_empty());
        assert!(link.traversed_directories.is_empty());
        let directory = ownership_path(&root, "real/", &mut parents).unwrap();
        assert!(directory.traversed_directories.is_empty());
        std::os::unix::fs::symlink(root.join("alias1"), root.join("absolute")).unwrap();
        let path = ownership_path(&root, "absolute/file", &mut parents).unwrap();
        assert_eq!(path.resolved, "real/file");
        assert_eq!(path.symlinks, ["absolute", "alias1", "alias2"]);
        assert_eq!(
            path.traversed_directories,
            [PathBuf::from("real"), PathBuf::from("real/sub")]
        );
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

    fn directory_conversion_archive(
        dir: &Path,
        name: &str,
        version: &str,
        members: &[(&str, tar::EntryType, &str)],
        backup: Option<&str>,
    ) -> DownloadedPackage {
        let path = dir.join(format!("{name}-{version}.pkg.tar"));
        let mut builder = tar::Builder::new(std::fs::File::create(&path).unwrap());
        let mut info = format!("pkgname = {name}\npkgver = {version}\narch = any\n");
        if let Some(backup) = backup {
            info.push_str(&format!("backup = {backup}\n"));
        }
        for (path, kind, contents) in
            std::iter::once((".PKGINFO", tar::EntryType::Regular, info.as_str()))
                .chain(members.iter().copied())
        {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_mode(if kind.is_dir() { 0o755 } else { 0o644 });
            header.set_mtime(1);
            let bytes = if kind.is_symlink() || kind.is_hard_link() {
                header.set_link_name(contents).unwrap();
                b"".as_slice()
            } else {
                contents.as_bytes()
            };
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, path, bytes).unwrap();
        }
        builder.finish().unwrap();
        DownloadedPackage {
            name: name.into(),
            path,
        }
    }

    #[test]
    fn root_owned_empty_directory_to_leaf_preserves_foreign_target() {
        use std::os::unix::fs::MetadataExt;
        use tar::EntryType::{Link, Regular, Symlink};
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        for kind in [Regular, Symlink, Link] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let db = temp.path().join("db");
            std::fs::create_dir_all(root.join("empty")).unwrap();
            std::fs::create_dir(root.join("target")).unwrap();
            std::fs::write(root.join("target/sentinel"), "keep foreign target").unwrap();
            let sentinel = std::fs::metadata(root.join("target/sentinel")).unwrap();
            let old = alias_test_entry(&db, "old", "%FILES%\nempty/\n\n");
            let foreign_files = "%FILES%\ntarget/\ntarget/sentinel\n\n";
            let foreign = alias_test_entry(&db, "foreign", foreign_files);
            let raw = directory_conversion_archive(
                temp.path(),
                "old",
                "2-1",
                &[
                    ("source", Regular, "new source"),
                    (
                        "empty",
                        kind,
                        if kind == Link { "source" } else { "target" },
                    ),
                ],
                None,
            );
            let downloaded = prepare_archives(&db, &[raw]);
            let mut tx = transaction(&[]);
            tx.upgrades.push(alias_test_upgrade("old"));
            tx.package_order.push("old".into());
            let hooks = masked_hooks(temp.path());
            let mut logger = PaxLogger::open(&temp.path().join("log"));
            execute_transaction(
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
            .unwrap_or_else(|error| panic!("{kind:?}: {error}"));
            if kind == Symlink {
                assert_eq!(
                    std::fs::read_link(root.join("empty")).unwrap(),
                    Path::new("target")
                );
            } else {
                assert!(
                    std::fs::symlink_metadata(root.join("empty"))
                        .unwrap()
                        .is_file()
                );
                let contents = if kind == Link {
                    b"new source".as_slice()
                } else {
                    b"target".as_slice()
                };
                assert_eq!(std::fs::read(root.join("empty")).unwrap(), contents);
                if kind == Link {
                    assert_eq!(
                        std::fs::metadata(root.join("empty")).unwrap().ino(),
                        std::fs::metadata(root.join("source")).unwrap().ino()
                    );
                }
            }
            assert_eq!(
                std::fs::read(root.join("target/sentinel")).unwrap(),
                b"keep foreign target"
            );
            assert_eq!(
                std::fs::metadata(root.join("target/sentinel"))
                    .unwrap()
                    .ino(),
                sentinel.ino()
            );
            assert_eq!(
                std::fs::read_to_string(foreign.join("files")).unwrap(),
                foreign_files
            );
            assert!(!old.exists());
            assert_eq!(
                read_file_list(&db, "old", "2-1").unwrap(),
                ["source", "empty"]
            );
        }
    }

    #[test]
    fn root_owned_nonempty_directory_to_leaf_preserves_link_targets() {
        use std::os::unix::fs::{MetadataExt, symlink};
        use tar::EntryType::{Regular, Symlink};
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        for kind in [Regular, Symlink] {
            for alias in [false, true] {
                let temp = tempfile::tempdir().unwrap();
                let root = temp.path().join("root");
                let db = temp.path().join("db");
                std::fs::create_dir_all(root.join("usr/include/vapoursynth/nested")).unwrap();
                std::fs::create_dir_all(root.join("usr/include/target")).unwrap();
                symlink("usr/include", root.join("include")).unwrap();
                let prefix = if alias {
                    "include/vapoursynth"
                } else {
                    "usr/include/vapoursynth"
                };
                let target = temp.path().join("outside");
                std::fs::create_dir(&target).unwrap();
                std::fs::write(target.join("sentinel"), "keep external target").unwrap();
                std::fs::write(root.join("usr/include/target/sentinel"), "keep new target")
                    .unwrap();
                let sentinel = std::fs::metadata(target.join("sentinel")).unwrap();
                std::fs::write(root.join(prefix).join("nested/file"), "obsolete").unwrap();
                symlink(&target, root.join(prefix).join("nested/link")).unwrap();
                std::fs::hard_link(target.join("sentinel"), root.join(prefix).join("hardlink"))
                    .unwrap();
                let old = alias_test_entry(
                    &db,
                    "old",
                    &format!(
                        "%FILES%\n{prefix}/\n{prefix}/nested/\n{prefix}/nested/file\n{prefix}/nested/link\n{prefix}/hardlink\n\n"
                    ),
                );
                let raw = directory_conversion_archive(
                    temp.path(),
                    "old",
                    "2-1",
                    &[(prefix, kind, "target")],
                    None,
                );
                let downloaded = prepare_archives(&db, &[raw]);
                let mut tx = transaction(&[]);
                tx.upgrades.push(alias_test_upgrade("old"));
                tx.package_order.push("old".into());
                let hooks = masked_hooks(temp.path());
                let mut logger = PaxLogger::open(&temp.path().join("log"));
                execute_transaction(
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
                .unwrap_or_else(|error| panic!("{kind:?}, alias={alias}: {error}"));
                let metadata = std::fs::symlink_metadata(root.join(prefix)).unwrap();
                if kind == Symlink {
                    assert!(metadata.file_type().is_symlink());
                    assert_eq!(
                        std::fs::read_link(root.join(prefix)).unwrap(),
                        Path::new("target")
                    );
                } else {
                    assert!(metadata.is_file());
                    assert_eq!(std::fs::read(root.join(prefix)).unwrap(), b"target");
                }
                assert_eq!(
                    std::fs::read(target.join("sentinel")).unwrap(),
                    b"keep external target"
                );
                assert_eq!(
                    std::fs::metadata(target.join("sentinel")).unwrap().ino(),
                    sentinel.ino()
                );
                assert_eq!(
                    std::fs::read(root.join("usr/include/target/sentinel")).unwrap(),
                    b"keep new target"
                );
                assert_eq!(std::fs::read_dir(&target).unwrap().count(), 1);
                assert_eq!(
                    std::fs::read_dir(root.join("usr/include/target"))
                        .unwrap()
                        .count(),
                    1
                );
                assert!(!old.exists());
                assert_eq!(read_file_list(&db, "old", "2-1").unwrap(), [prefix]);
            }
        }
    }

    #[test]
    fn root_nonempty_directory_accepts_earlier_upgrade_and_linked_cleanup() {
        use tar::EntryType::{Regular, Symlink};
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        for scenario in ["earlier-upgrade", "earlier-removal", "same-slot-removal"] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let db = temp.path().join("db");
            std::fs::create_dir_all(root.join("tree/nested")).unwrap();
            std::fs::write(root.join("tree/nested/file"), "obsolete").unwrap();
            std::fs::create_dir(root.join("target")).unwrap();
            std::fs::write(root.join("target/victim"), "keep retained target").unwrap();
            alias_test_entry(&db, "retained", "%FILES%\ntarget/\ntarget/victim\n\n");
            assert!(!root.join("tree/victim").exists());
            alias_test_entry(&db, "old", "%FILES%\ntree/\n\n");
            let other = alias_test_entry(
                &db,
                "other",
                "%FILES%\ntree/nested/\ntree/nested/file\ntree/victim\n\n",
            );
            let mut tx = transaction(&[]);
            tx.upgrades.push(alias_test_upgrade("old"));
            tx.package_order.push("old".into());
            let mut raw = vec![directory_conversion_archive(
                temp.path(),
                "old",
                "2-1",
                &[("tree", Symlink, "target")],
                None,
            )];
            if scenario == "earlier-upgrade" {
                tx.upgrades.push(alias_test_upgrade("other"));
                tx.package_order.insert(0, "other".into());
                raw.push(directory_conversion_archive(
                    temp.path(),
                    "other",
                    "2-1",
                    &[("other-new", Regular, "new")],
                    None,
                ));
            } else {
                let anchor = if scenario == "earlier-removal" {
                    "early"
                } else {
                    "old"
                };
                if anchor == "early" {
                    tx.installs = transaction(&["early"]).installs;
                    tx.package_order.insert(0, "early".into());
                    raw.push(alias_test_archive(temp.path(), "early", "1-1", "early-new"));
                }
                tx.removals.push(pax_resolver::RemovalAction {
                    name: "other".into(),
                    version: Version::parse("1-1").unwrap(),
                    links: vec![pax_resolver::RemovalLink {
                        incoming: anchor.into(),
                        reason: RemovalReason::Replaced,
                    }],
                });
            }
            let downloaded = prepare_archives(&db, &raw);
            let hooks = masked_hooks(temp.path());
            let mut logger = PaxLogger::open(&temp.path().join("log"));
            execute_transaction(
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
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
            assert_eq!(
                std::fs::read_link(root.join("tree")).unwrap(),
                Path::new("target")
            );
            assert_eq!(read_file_list(&db, "old", "2-1").unwrap(), ["tree"]);
            assert!(!other.exists());
            assert_eq!(
                std::fs::read(root.join("tree/victim")).unwrap(),
                b"keep retained target"
            );
            assert_eq!(
                std::fs::read(root.join("target/victim")).unwrap(),
                b"keep retained target"
            );
            assert_eq!(
                read_file_list(&db, "retained", "1-1").unwrap(),
                ["target/", "target/victim"]
            );
        }
    }

    #[test]
    fn root_nonempty_directory_blockers_precede_hooks_and_mutation() {
        use std::os::unix::fs::symlink;
        use tar::EntryType::{Regular, Symlink};
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        for scenario in [
            "unowned-root",
            "unowned-file",
            "unowned-subdir",
            "unowned-pacsave",
            "owned-pacsave",
            "backup-child",
            "backup-root",
            "backup-missing",
            "retained-child",
            "retained-missing",
            "incoming-child",
            "later-upgrade",
            "later-removal",
            "absent-late-upgrade",
            "absent-late-removal",
            "absent-cross-spelling",
            "early-parent-cleanup",
            "cross-spelling-root",
            "cross-spelling-child",
            "old-traversal",
            "wrong-directory-record",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let db = temp.path().join("db");
            std::fs::create_dir_all(root.join("tree/nested")).unwrap();
            std::fs::create_dir_all(root.join("target")).unwrap();
            std::fs::write(root.join("tree/nested/file"), "old contents").unwrap();
            std::fs::write(root.join("target/sentinel"), "keep target").unwrap();
            symlink("tree", root.join("alias")).unwrap();
            let mut files = vec!["tree/", "tree/nested/", "tree/nested/file"];
            let mut backup = "";
            let mut other_files = "";
            match scenario {
                "unowned-root" => {
                    files.remove(0);
                }
                "wrong-directory-record" => files[0] = "tree",
                "cross-spelling-root" => {
                    files = vec!["alias/", "alias/nested/", "alias/nested/file"]
                }
                "cross-spelling-child" => files[2] = "alias/nested/file",
                "unowned-file" => std::fs::write(root.join("tree/local"), "keep local").unwrap(),
                "unowned-subdir" => std::fs::create_dir(root.join("tree/local-dir")).unwrap(),
                "unowned-pacsave" | "owned-pacsave" => {
                    std::fs::write(root.join("tree/file.pacsave"), "keep pacsave").unwrap();
                    if scenario == "owned-pacsave" {
                        files.push("tree/file.pacsave");
                    }
                }
                "backup-child" => backup = "%BACKUP%\ntree/nested/file\tlegacy\n\n",
                "backup-root" => backup = "%BACKUP%\ntree\tlegacy\n\n",
                "backup-missing" => backup = "%BACKUP%\ntree/missing\n\n",
                "retained-child" => {
                    files.pop();
                    alias_test_entry(&db, "retained", "%FILES%\ntree/nested/file\n\n");
                }
                "retained-missing" => {
                    alias_test_entry(&db, "retained", "%FILES%\ntree/missing\n\n");
                }
                "later-upgrade" | "later-removal" => {
                    files.pop();
                    other_files = "%FILES%\ntree/nested/file\n\n";
                }
                "absent-late-upgrade" | "absent-late-removal" | "absent-cross-spelling" => {
                    other_files = if scenario == "absent-cross-spelling" {
                        "%FILES%\nalias/victim\n\n"
                    } else {
                        "%FILES%\ntree/victim\n\n"
                    };
                    std::fs::write(root.join("target/victim"), "keep retained target").unwrap();
                    alias_test_entry(&db, "retained", "%FILES%\ntarget/\ntarget/victim\n\n");
                    assert!(!root.join("tree/victim").exists());
                }
                "early-parent-cleanup" => {
                    files.remove(1);
                    other_files = "%FILES%\ntree/nested/\n\n";
                }
                "old-traversal" => {
                    symlink("../target", root.join("tree/link")).unwrap();
                    files.extend(["tree/link", "tree/link/sentinel"]);
                }
                _ => {}
            }
            let old_contents = format!("%FILES%\n{}\n\n{backup}", files.join("\n"));
            let old = alias_test_entry(&db, "old", &old_contents);
            let old_desc = std::fs::read(old.join("desc")).unwrap();
            let mut tx = transaction(&[]);
            tx.upgrades.push(alias_test_upgrade("old"));
            tx.package_order.push("old".into());
            let mut raw = vec![directory_conversion_archive(
                temp.path(),
                "old",
                "2-1",
                &[
                    ("first-payload", Regular, "must not install"),
                    ("tree", Symlink, "target"),
                ],
                None,
            )];
            if !other_files.is_empty() {
                alias_test_entry(&db, "other", other_files);
                if matches!(scenario, "later-removal" | "absent-late-removal") {
                    tx.installs = transaction(&["late"]).installs;
                    tx.package_order.push("late".into());
                    tx.removals.push(pax_resolver::RemovalAction {
                        name: "other".into(),
                        version: Version::parse("1-1").unwrap(),
                        links: vec![pax_resolver::RemovalLink {
                            incoming: "late".into(),
                            reason: RemovalReason::Replaced,
                        }],
                    });
                    raw.push(alias_test_archive(
                        temp.path(),
                        "late",
                        "1-1",
                        "later-payload",
                    ));
                } else {
                    tx.upgrades.push(alias_test_upgrade("other"));
                    if matches!(scenario, "early-parent-cleanup" | "absent-cross-spelling") {
                        tx.package_order.insert(0, "other".into());
                    } else {
                        tx.package_order.push("other".into());
                    }
                    raw.push(alias_test_archive(
                        temp.path(),
                        "other",
                        "2-1",
                        "later-payload",
                    ));
                }
            }
            if scenario == "incoming-child" {
                tx.installs = transaction(&["new"]).installs;
                tx.package_order.push("new".into());
                raw.push(alias_test_archive(
                    temp.path(),
                    "new",
                    "1-1",
                    "tree/nested/next",
                ));
            }
            let downloaded = prepare_archives(&db, &raw);
            let hooks = masked_hooks(temp.path());
            std::fs::write(hooks.join("00-nonempty-probe.hook"),
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
                matches!(error, ExecError::FileConflict(_)),
                "{scenario}: {error}"
            );
            assert!(
                error
                    .to_string()
                    .contains("cannot replace a nonempty directory"),
                "{scenario}: {error}"
            );
            assert_eq!(
                std::fs::read(root.join("tree/nested/file")).unwrap(),
                b"old contents",
                "{scenario}"
            );
            assert_eq!(
                std::fs::read(root.join("target/sentinel")).unwrap(),
                b"keep target"
            );
            assert_eq!(
                std::fs::read_to_string(old.join("files")).unwrap(),
                old_contents
            );
            assert_eq!(std::fs::read(old.join("desc")).unwrap(), old_desc);
            assert!(!root.join("first-payload").exists());
            assert!(!root.join("later-payload").exists());
            assert!(!db.join("local/old-2-1").exists());
            assert!(
                !std::fs::read_to_string(log)
                    .unwrap()
                    .contains("transaction started")
            );
            if scenario.starts_with("absent-") {
                let message = error.to_string();
                assert!(
                    message.contains("old database path /tree/victim: owner other"),
                    "{scenario}: {error}"
                );
                let reason = if scenario == "absent-cross-spelling" {
                    "unproven cleanup spelling /alias/victim"
                } else {
                    "does not retire this entry before directory conversion"
                };
                assert!(message.contains(reason), "{scenario}: {error}");
                assert!(
                    std::fs::symlink_metadata(root.join("tree"))
                        .unwrap()
                        .is_dir()
                );
                assert!(!root.join("tree/victim").exists());
                assert_eq!(
                    std::fs::read(root.join("target/victim")).unwrap(),
                    b"keep retained target"
                );
                assert_eq!(
                    read_file_list(&db, "retained", "1-1").unwrap(),
                    ["target/", "target/victim"]
                );
                assert_eq!(
                    std::fs::read_to_string(db.join("local/other-1-1/files")).unwrap(),
                    other_files
                );
                assert!(!db.join("local/other-2-1").exists());
                assert!(!db.join("local/late-1-1").exists());
            }
            if scenario.ends_with("pacsave") {
                assert_eq!(
                    std::fs::read(root.join("tree/file.pacsave")).unwrap(),
                    b"keep pacsave"
                );
            }
            if scenario == "unowned-file" {
                assert_eq!(
                    std::fs::read(root.join("tree/local")).unwrap(),
                    b"keep local"
                );
            }
            if scenario == "unowned-subdir" {
                assert!(root.join("tree/local-dir").is_dir());
            }
        }
    }

    #[test]
    fn root_nonempty_directory_rejects_alias_dotdot_namespace_changes_before_hooks() {
        use std::os::unix::fs::{MetadataExt, symlink};
        use tar::EntryType::{Link, Regular, Symlink};
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        for scenario in [
            "old-missing-late-upgrade",
            "old-missing-late-removal",
            "incoming-path",
            "incoming-hardlink-source",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let db = temp.path().join("db");
            for directory in ["tree", "landing", "other/dir", "other/landing"] {
                std::fs::create_dir_all(root.join(directory)).unwrap();
            }
            std::fs::write(root.join("tree/obsolete"), "old contents").unwrap();
            std::fs::write(root.join("other/landing/victim"), "keep C target").unwrap();
            let sentinel = std::fs::metadata(root.join("other/landing/victim")).unwrap();
            symlink("tree/../landing", root.join("alias")).unwrap();
            alias_test_entry(&db, "a", "%FILES%\ntree/\ntree/obsolete\n\n");
            alias_test_entry(
                &db,
                "c",
                "%FILES%\nother/\nother/dir/\nother/landing/\nother/landing/victim\n\n",
            );
            let mut parents = HashMap::new();
            let alias = ownership_path(&root, "alias/victim", &mut parents).unwrap();
            assert_eq!(alias.resolved, "landing/victim");
            assert_eq!(
                alias.traversed_directories,
                [PathBuf::from("tree"), PathBuf::from("landing")]
            );
            assert!(!root.join("alias/victim").exists());

            let mut tx = transaction(&[]);
            tx.upgrades.push(alias_test_upgrade("a"));
            tx.package_order.push("a".into());
            let a = directory_conversion_archive(
                temp.path(),
                "a",
                "2-1",
                &[
                    ("a-new", Regular, "must not install"),
                    ("tree", Symlink, "other/dir"),
                ],
                None,
            );
            let a_plan =
                crate::preflight::inspect_transaction_archive(&a.path, &root, None).unwrap();
            assert!(a_plan.traversed_directories.is_empty());
            assert_eq!(
                a_plan.deferred_directory_replacements,
                HashSet::from([PathBuf::from("tree")])
            );
            let mut raw = vec![a];
            if scenario.starts_with("old-") {
                // There is deliberately no tree/ record in B and no current victim.
                alias_test_entry(&db, "b", "%FILES%\nalias/victim\n\n");
                if scenario == "old-missing-late-upgrade" {
                    tx.upgrades.push(alias_test_upgrade("b"));
                    tx.package_order.push("b".into());
                    raw.push(alias_test_archive(temp.path(), "b", "2-1", "b-new"));
                } else {
                    tx.installs = transaction(&["replacement"]).installs;
                    tx.package_order.push("replacement".into());
                    tx.removals.push(pax_resolver::RemovalAction {
                        name: "b".into(),
                        version: Version::parse("1-1").unwrap(),
                        links: vec![pax_resolver::RemovalLink {
                            incoming: "replacement".into(),
                            reason: RemovalReason::Replaced,
                        }],
                    });
                    raw.push(alias_test_archive(
                        temp.path(),
                        "replacement",
                        "1-1",
                        "b-new",
                    ));
                }
            } else {
                tx.installs = transaction(&["b"]).installs;
                tx.package_order.push("b".into());
                let members = if scenario == "incoming-path" {
                    vec![("alias/victim", Regular, "must not overwrite C")]
                } else {
                    vec![
                        ("landing/victim", Regular, "new source"),
                        ("copy", Link, "alias/victim"),
                    ]
                };
                // No alias/ header: only the parent traversal depends on tree.
                let b = directory_conversion_archive(temp.path(), "b", "1-1", &members, None);
                let b_plan = crate::preflight::inspect_archive(&b.path, &root, None).unwrap();
                assert!(b_plan.traversed_directories.contains(Path::new("tree")));
                assert_eq!(
                    b_plan.traversed_symlinks,
                    HashSet::from([PathBuf::from("alias")])
                );
                raw.push(b);
            }
            let old_entries: Vec<_> = std::fs::read_dir(db.join("local"))
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    let desc = std::fs::read(path.join("desc")).unwrap();
                    let files = std::fs::read(path.join("files")).unwrap();
                    (path, desc, files)
                })
                .collect();
            let downloaded = prepare_archives(&db, &raw);
            let hooks = masked_hooks(temp.path());
            std::fs::write(hooks.join("00-dotdot-probe.hook"),
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
                matches!(error, ExecError::FileConflict(_)),
                "{scenario}: {error}"
            );
            let expected = if scenario.starts_with("old-") {
                "old database paths traverse directory /tree before resolving outside it"
            } else {
                "b: archive payload or hardlink source traverses directory /tree"
            };
            assert!(error.to_string().contains(expected), "{scenario}: {error}");
            assert!(
                std::fs::symlink_metadata(root.join("tree"))
                    .unwrap()
                    .is_dir()
            );
            assert_eq!(
                std::fs::read(root.join("tree/obsolete")).unwrap(),
                b"old contents"
            );
            assert_eq!(
                std::fs::read(root.join("other/landing/victim")).unwrap(),
                b"keep C target"
            );
            assert_eq!(
                std::fs::metadata(root.join("other/landing/victim"))
                    .unwrap()
                    .ino(),
                sentinel.ino()
            );
            assert!(root.join("other/dir").is_dir());
            assert_eq!(
                std::fs::read_link(root.join("alias")).unwrap(),
                Path::new("tree/../landing")
            );
            for absent in ["landing/victim", "alias/victim", "a-new", "b-new", "copy"] {
                assert!(!root.join(absent).exists(), "{scenario}: {absent}");
            }
            assert_eq!(
                std::fs::read_dir(db.join("local")).unwrap().count(),
                old_entries.len()
            );
            for (path, desc, files) in old_entries {
                assert_eq!(std::fs::read(path.join("desc")).unwrap(), desc);
                assert_eq!(std::fs::read(path.join("files")).unwrap(), files);
            }
            assert!(
                !std::fs::read_to_string(log)
                    .unwrap()
                    .contains("transaction started")
            );
        }
    }

    #[test]
    fn root_empty_directory_conversion_cannot_redirect_later_cleanup() {
        use std::os::unix::fs::{MetadataExt, symlink};
        use tar::EntryType::{Regular, Symlink};
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        for convert_tree in [true, false] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let db = temp.path().join("db");
            for directory in ["pivot", "landing/tree", "other/dir", "other/landing/tree"] {
                std::fs::create_dir_all(root.join(directory)).unwrap();
            }
            std::fs::write(root.join("landing/tree/obsolete"), "old A contents").unwrap();
            let victim = root.join("other/landing/tree/obsolete");
            std::fs::write(&victim, "keep C contents").unwrap();
            let sentinel = std::fs::metadata(&victim).unwrap();
            symlink("pivot/../landing", root.join("alias")).unwrap();
            alias_test_entry(&db, "b", "%FILES%\npivot/\n\n");
            alias_test_entry(&db, "a", "%FILES%\nalias/tree/\nalias/tree/obsolete\n\n");
            alias_test_entry(
                &db,
                "c",
                "%FILES%\nother/\nother/dir/\nother/landing/\nother/landing/tree/\nother/landing/tree/obsolete\n\n",
            );
            let b = directory_conversion_archive(
                temp.path(),
                "b",
                "2-1",
                &[("pivot", Symlink, "other/dir")],
                None,
            );
            let mut a_members = vec![("a-new", Regular, "must not install")];
            if convert_tree {
                a_members.push(("alias/tree", Symlink, "target"));
            }
            let a = directory_conversion_archive(temp.path(), "a", "2-1", &a_members, None);
            let b_plan =
                crate::preflight::inspect_transaction_archive(&b.path, &root, None).unwrap();
            assert_eq!(
                b_plan.directory_to_leaf_replacements,
                HashSet::from([PathBuf::from("pivot")])
            );
            assert!(b_plan.deferred_directory_replacements.is_empty());
            let a_plan =
                crate::preflight::inspect_transaction_archive(&a.path, &root, None).unwrap();
            if convert_tree {
                assert_eq!(
                    a_plan.deferred_directory_replacements,
                    HashSet::from([PathBuf::from("landing/tree")])
                );
                assert!(a_plan.traversed_directories.contains(Path::new("pivot")));
            } else {
                // No incoming traversal: the old DB cleanup must independently block B.
                assert!(a_plan.traversed_directories.is_empty());
            }
            let old_entries: Vec<_> = std::fs::read_dir(db.join("local"))
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    let desc = std::fs::read(path.join("desc")).unwrap();
                    let files = std::fs::read(path.join("files")).unwrap();
                    (path, desc, files)
                })
                .collect();
            let downloaded = prepare_archives(&db, &[b, a]);
            let mut tx = transaction(&[]);
            for name in ["b", "a"] {
                tx.upgrades.push(alias_test_upgrade(name));
                tx.package_order.push(name.into());
            }
            let hooks = masked_hooks(temp.path());
            std::fs::write(hooks.join("00-empty-pivot-probe.hook"),
                "[Trigger]\nType = Package\nOperation = Upgrade\nTarget = *\n[Action]\nWhen = PreTransaction\nExec = /must-not-run\nAbortOnFail\n").unwrap();
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
                matches!(error, ExecError::FileConflict(_)),
                "convert_tree={convert_tree}: {error}"
            );
            let message = error.to_string();
            assert!(message.contains("b: /pivot cannot become a non-directory: old database paths traverse this directory"), "{message}");
            if convert_tree {
                assert!(
                    message.contains(
                        "a: archive payload or hardlink source traverses directory /pivot"
                    ),
                    "{message}"
                );
            }
            assert_eq!(std::fs::read(&victim).unwrap(), b"keep C contents");
            assert_eq!(std::fs::metadata(&victim).unwrap().ino(), sentinel.ino());
            assert!(
                std::fs::symlink_metadata(root.join("other/landing/tree"))
                    .unwrap()
                    .is_dir()
            );
            assert_eq!(
                std::fs::read(root.join("landing/tree/obsolete")).unwrap(),
                b"old A contents"
            );
            assert!(
                std::fs::symlink_metadata(root.join("landing/tree"))
                    .unwrap()
                    .is_dir()
            );
            assert!(
                std::fs::symlink_metadata(root.join("pivot"))
                    .unwrap()
                    .is_dir()
            );
            assert_eq!(std::fs::read_dir(root.join("pivot")).unwrap().count(), 0);
            assert_eq!(
                std::fs::read_link(root.join("alias")).unwrap(),
                Path::new("pivot/../landing")
            );
            assert!(!root.join("a-new").exists());
            assert_eq!(
                std::fs::read_dir(db.join("local")).unwrap().count(),
                old_entries.len()
            );
            for (path, desc, files) in old_entries {
                assert_eq!(std::fs::read(path.join("desc")).unwrap(), desc);
                assert_eq!(std::fs::read(path.join("files")).unwrap(), files);
            }
            assert!(
                !std::fs::read_to_string(log)
                    .unwrap()
                    .contains("transaction started")
            );
        }
    }

    #[test]
    fn root_nonempty_directory_recheck_preserves_unexpected_children() {
        use tar::EntryType::{Regular, Symlink};
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        std::fs::create_dir_all(root.join("tree/nested")).unwrap();
        std::fs::write(root.join("tree/nested/old"), "obsolete").unwrap();
        let old = alias_test_entry(
            &db,
            "old",
            "%FILES%\ntree/\ntree/nested/\ntree/nested/old\n\n",
        );
        let raw = directory_conversion_archive(
            temp.path(),
            "old",
            "2-1",
            &[
                ("first-payload", Regular, "must not install"),
                ("tree", Symlink, "target"),
            ],
            None,
        );
        let plan = crate::preflight::inspect_transaction_archive(&raw.path, &root, None).unwrap();
        let downloaded = prepare_archives(&db, &[raw]);
        let mut tx = transaction(&[]);
        tx.upgrades.push(alias_test_upgrade("old"));
        tx.package_order.push("old".into());
        let incoming = prepare_incoming(&tx, &downloaded).unwrap();
        check_file_conflicts_inner(
            &root,
            &db,
            &incoming,
            &tx,
            &simple_steps(&tx),
            Some(&HashMap::from([("old", plan)])),
        )
        .unwrap();
        // Model a hook/scriptlet adding data after the read-only ownership proof.
        std::fs::write(root.join("tree/nested/local"), "keep unexpected").unwrap();
        remove_package_paths(
            &old,
            &root,
            &HashSet::from(["tree".into(), "first-payload".into()]),
        )
        .unwrap();
        let error = extract_prepared(&downloaded[0], &db, &root, &HashMap::new())
            .err()
            .expect("unexpected child must prevent extraction");
        assert!(
            error
                .to_string()
                .contains("cannot replace a nonempty directory"),
            "{error}"
        );
        assert_eq!(
            std::fs::read(root.join("tree/nested/local")).unwrap(),
            b"keep unexpected"
        );
        assert!(!root.join("tree/nested/old").exists());
        assert!(!root.join("first-payload").exists());
        assert!(old.exists());
        assert!(!db.join("local/old-2-1").exists());
    }

    #[test]
    fn root_owned_symlink_to_directory_upgrade_preserves_targets_and_hardlinks() {
        use std::os::unix::fs::{MetadataExt, symlink};
        use tar::EntryType::{Directory, Link, Regular};
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        for target_kind in [
            "relative",
            "absolute",
            "external",
            "escaping-relative",
            "dangling",
            "loop",
        ] {
            for alias in [false, true] {
                let temp = tempfile::tempdir().unwrap();
                let root = temp.path().join("root");
                let db = temp.path().join("db");
                std::fs::create_dir_all(root.join("real-parent")).unwrap();
                symlink("real-parent", root.join("alias")).unwrap();
                let prefix = if alias {
                    "alias/link"
                } else {
                    "real-parent/link"
                };
                let target = if matches!(target_kind, "external" | "escaping-relative") {
                    temp.path().join("outside")
                } else {
                    root.join("target")
                };
                std::fs::create_dir_all(target.join("source")).unwrap();
                std::fs::write(target.join("source/sentinel"), "keep sentinel").unwrap();
                std::fs::write(target.join("child"), "not a future parent").unwrap();
                let sentinel = std::fs::metadata(target.join("source/sentinel")).unwrap();
                let link_target = match target_kind {
                    "relative" => PathBuf::from("../target"),
                    "escaping-relative" => PathBuf::from("../../outside"),
                    "dangling" => temp.path().join("absent-external-target"),
                    "loop" => PathBuf::from("link"),
                    _ => target.clone(),
                };
                symlink(&link_target, root.join(prefix)).unwrap();
                let old = alias_test_entry(&db, "old", &format!("%FILES%\n{prefix}\n\n"));
                if target.starts_with(&root) {
                    alias_test_entry(
                        &db,
                        "retained",
                        "%FILES%\ntarget/\ntarget/child\ntarget/source/\ntarget/source/sentinel\n\n",
                    );
                }
                let directory = format!("{prefix}/");
                let source = format!("{prefix}/source");
                let child = format!("{prefix}/child/file");
                let hardlink = format!("{prefix}/child/hardlink");
                let raw = directory_conversion_archive(
                    temp.path(),
                    "old",
                    "2-1",
                    &[
                        (&directory, Directory, ""),
                        (&source, Regular, "new source"),
                        (&child, Regular, "new child"),
                        (&hardlink, Link, &source),
                    ],
                    None,
                );
                let plan = crate::preflight::inspect_archive(&raw.path, &root, None).unwrap();
                assert_eq!(
                    plan.directory_replacements,
                    HashSet::from([PathBuf::from("real-parent/link")])
                );
                let downloaded = prepare_archives(&db, &[raw]);
                let mut tx = transaction(&[]);
                tx.upgrades.push(alias_test_upgrade("old"));
                tx.package_order.push("old".into());
                let hooks = masked_hooks(temp.path());
                let log = temp.path().join("log");
                let mut logger = PaxLogger::open(&log);
                execute_transaction(
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
                .unwrap_or_else(|error| panic!("{target_kind}, alias={alias}: {error}"));
                assert!(
                    std::fs::symlink_metadata(root.join(prefix))
                        .unwrap()
                        .is_dir()
                );
                assert_eq!(std::fs::read(root.join(&source)).unwrap(), b"new source");
                assert_eq!(std::fs::read(root.join(&child)).unwrap(), b"new child");
                assert_eq!(
                    std::fs::metadata(root.join(&source)).unwrap().ino(),
                    std::fs::metadata(root.join(&hardlink)).unwrap().ino()
                );
                assert_eq!(
                    std::fs::read(target.join("source/sentinel")).unwrap(),
                    b"keep sentinel"
                );
                assert_eq!(
                    std::fs::metadata(target.join("source/sentinel"))
                        .unwrap()
                        .ino(),
                    sentinel.ino()
                );
                assert_eq!(
                    std::fs::read(target.join("child")).unwrap(),
                    b"not a future parent"
                );
                assert!(!temp.path().join("absent-external-target").exists());
                assert!(!old.exists());
                let files = read_file_list(&db, "old", "2-1").unwrap();
                for file in [&directory, &source, &child, &hardlink] {
                    assert!(files.contains(file), "{files:?}");
                }
                assert_eq!(
                    std::fs::read_link(root.join("alias")).unwrap(),
                    Path::new("real-parent")
                );
                assert!(
                    std::fs::read_to_string(log)
                        .unwrap()
                        .contains("transaction completed")
                );
            }
        }
    }

    #[test]
    fn root_directory_conversion_accepts_linked_removal_at_its_slot() {
        use tar::EntryType::{Directory, Regular};
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        std::fs::create_dir_all(root.join("target")).unwrap();
        std::fs::write(root.join("target/sentinel"), "keep").unwrap();
        std::os::unix::fs::symlink("target", root.join("link")).unwrap();
        let old = alias_test_entry(&db, "old", "%FILES%\nlink\n\n");
        let raw = directory_conversion_archive(
            temp.path(),
            "new",
            "1-1",
            &[("link/", Directory, ""), ("link/file", Regular, "new file")],
            None,
        );
        let downloaded = prepare_archives(&db, &[raw]);
        let mut tx = transaction(&["new"]);
        tx.removals.push(pax_resolver::RemovalAction {
            name: "old".into(),
            version: Version::parse("1-1").unwrap(),
            links: vec![pax_resolver::RemovalLink {
                incoming: "new".into(),
                reason: RemovalReason::Replaced,
            }],
        });
        let hooks = masked_hooks(temp.path());
        let mut logger = PaxLogger::open(&temp.path().join("log"));
        execute_transaction(
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
        .unwrap();
        assert!(
            std::fs::symlink_metadata(root.join("link"))
                .unwrap()
                .is_dir()
        );
        assert_eq!(std::fs::read(root.join("link/file")).unwrap(), b"new file");
        assert_eq!(
            std::fs::read(root.join("target/sentinel")).unwrap(),
            b"keep"
        );
        assert!(!root.join("target/file").exists());
        assert!(!old.exists());
        assert_eq!(
            read_file_list(&db, "new", "1-1").unwrap(),
            ["link/", "link/file"]
        );
    }

    #[test]
    fn root_hardlink_source_cannot_traverse_another_packages_changing_symlink() {
        use tar::EntryType::{Directory, Link, Regular};
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        std::fs::create_dir_all(root.join("target")).unwrap();
        std::fs::write(root.join("target/sentinel"), "keep").unwrap();
        std::os::unix::fs::symlink("target", root.join("link")).unwrap();
        let old = alias_test_entry(&db, "a", "%FILES%\nlink\n\n");
        let old_desc = std::fs::read(old.join("desc")).unwrap();
        let old_files = std::fs::read(old.join("files")).unwrap();
        let a = directory_conversion_archive(
            temp.path(),
            "a",
            "2-1",
            &[("link/", Directory, ""), ("link/item", Regular, "A-data")],
            None,
        );
        let b = directory_conversion_archive(
            temp.path(),
            "b",
            "1-1",
            &[
                ("target/item", Regular, "B-data"),
                ("copy", Link, "link/item"),
            ],
            None,
        );
        let a_plan = crate::preflight::inspect_archive(&a.path, &root, None).unwrap();
        assert!(a_plan.traversed_symlinks.is_empty());
        let b_plan = crate::preflight::inspect_archive(&b.path, &root, None).unwrap();
        assert_eq!(
            b_plan.traversed_symlinks,
            HashSet::from([PathBuf::from("link")])
        );
        assert!(b_plan.directory_replacements.is_empty());
        crate::extract::validate_package_archive(&b.path, &root).unwrap();
        let downloaded = prepare_archives(&db, &[a, b]);
        let mut tx = transaction(&["b"]);
        tx.upgrades.push(alias_test_upgrade("a"));
        tx.package_order.insert(0, "a".into());
        let hooks = masked_hooks(temp.path());
        std::fs::write(hooks.join("00-hardlink-probe.hook"),
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
        assert!(matches!(&error, ExecError::FileConflict(_)), "{error}");
        assert!(error.to_string().contains(
            "b: archive payload or hardlink source traverses filesystem symlink /link owned by changing package a"
        ), "{error}");
        assert_eq!(
            std::fs::read_link(root.join("link")).unwrap(),
            Path::new("target")
        );
        assert_eq!(
            std::fs::read(root.join("target/sentinel")).unwrap(),
            b"keep"
        );
        assert!(!root.join("link/item").exists());
        assert!(!root.join("target/item").exists());
        assert!(!root.join("copy").exists());
        assert_eq!(std::fs::read(old.join("desc")).unwrap(), old_desc);
        assert_eq!(std::fs::read(old.join("files")).unwrap(), old_files);
        assert!(!db.join("local/a-2-1").exists());
        assert!(!db.join("local/b-1-1").exists());
        assert!(
            !std::fs::read_to_string(log)
                .unwrap()
                .contains("transaction started")
        );
    }

    #[test]
    fn root_directory_conversion_blockers_precede_hooks_and_all_mutations() {
        use std::os::unix::fs::symlink;
        use tar::EntryType::{Directory, Regular, Symlink};
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        for scenario in [
            "unowned",
            "foreign",
            "foreign-directory-record",
            "upgraded-directory-record",
            "regular-file",
            "nonempty-directory",
            "incoming-backup",
            "old-backup-child",
            "old-backup-declaration",
            "old-link-backup",
            "retained-child",
            "earlier-member",
            "later-archive",
            "late-removal",
            "late-upgrade",
            "escaping-new-parent",
            "dangling-new-parent",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let db = temp.path().join("db");
            std::fs::create_dir_all(root.join("target")).unwrap();
            for (path, contents) in [
                ("target/config", "local changes"),
                ("target/config.pacnew", "old pacnew"),
                ("target/config.pacsave", "old pacsave"),
                ("old-file", "old payload"),
            ] {
                std::fs::write(root.join(path), contents).unwrap();
            }
            match scenario {
                "regular-file" => std::fs::write(root.join("link"), "keep ordinary file").unwrap(),
                "nonempty-directory" => {
                    std::fs::create_dir(root.join("link")).unwrap();
                    std::fs::write(root.join("link/sentinel"), "keep directory contents").unwrap();
                }
                _ => symlink("target", root.join("link")).unwrap(),
            }
            let files = match scenario {
                "unowned" | "foreign" | "foreign-directory-record" => "%FILES%\nold-file\n\n",
                "old-backup-child" => {
                    "%FILES%\nold-file\nlink\nlink/config\n\n%BACKUP%\nlink/config\tlegacy\n\n"
                }
                "old-backup-declaration" => {
                    "%FILES%\nold-file\nlink\n\n%BACKUP%\nlink/config\tlegacy\n\n"
                }
                "old-link-backup" => "%FILES%\nold-file\nlink\n\n%BACKUP%\nlink\tlegacy\n\n",
                "nonempty-directory" | "upgraded-directory-record" => {
                    "%FILES%\nold-file\nlink/\n\n"
                }
                _ => "%FILES%\nold-file\nlink\n\n",
            };
            let old = alias_test_entry(&db, "old", files);
            match scenario {
                "foreign" => {
                    alias_test_entry(&db, "retained", "%FILES%\nlink\n\n");
                }
                "foreign-directory-record" => {
                    alias_test_entry(&db, "retained", "%FILES%\nlink/\n\n");
                }
                "retained-child" => {
                    alias_test_entry(&db, "retained", "%FILES%\nlink/config\n\n");
                }
                _ => {}
            }
            let old_desc = std::fs::read(old.join("desc")).unwrap();
            let mut tx = transaction(&[]);
            tx.upgrades.push(alias_test_upgrade("old"));
            tx.package_order.push("old".into());
            let mut members = vec![("first-payload", Regular, "must not install")];
            if scenario == "earlier-member" {
                members.push(("link/earlier", Regular, "must not reach target"));
            }
            if scenario == "nonempty-directory" {
                members.push(("link", Regular, "must not replace directory"));
            } else {
                members.extend([
                    ("link/", Directory, ""),
                    ("link/config", Regular, "new config"),
                ]);
            }
            if matches!(scenario, "escaping-new-parent" | "dangling-new-parent") {
                members.extend([
                    (
                        "link/parent",
                        Symlink,
                        if scenario == "escaping-new-parent" {
                            "../../outside"
                        } else {
                            "missing"
                        },
                    ),
                    ("link/parent/file", Regular, "must not follow"),
                ]);
            }
            let conversion_name = if matches!(scenario, "late-removal" | "late-upgrade") {
                "early"
            } else {
                "old"
            };
            let version = if conversion_name == "early" {
                "1-1"
            } else {
                "2-1"
            };
            let mut raw = vec![directory_conversion_archive(
                temp.path(),
                conversion_name,
                version,
                &members,
                (scenario == "incoming-backup").then_some("link/config"),
            )];
            if scenario == "later-archive" {
                tx.installs = transaction(&["early"]).installs;
                tx.package_order.insert(0, "early".into());
                raw.insert(
                    0,
                    alias_test_archive(temp.path(), "early", "1-1", "link/earlier"),
                );
            } else if scenario == "late-upgrade" {
                tx.installs = transaction(&["early"]).installs;
                tx.package_order.insert(0, "early".into());
                raw.push(alias_test_archive(temp.path(), "old", "2-1", "late-file"));
            } else if scenario == "late-removal" {
                tx = transaction(&["early", "late"]);
                tx.removals.push(pax_resolver::RemovalAction {
                    name: "old".into(),
                    version: Version::parse("1-1").unwrap(),
                    links: vec![pax_resolver::RemovalLink {
                        incoming: "late".into(),
                        reason: RemovalReason::Replaced,
                    }],
                });
                raw.push(alias_test_archive(temp.path(), "late", "1-1", "late-file"));
            }
            let downloaded = prepare_archives(&db, &raw);
            let hooks = masked_hooks(temp.path());
            std::fs::write(hooks.join("00-directory-probe.hook"),
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
            let expected = match scenario {
                "regular-file" => "cannot replace an existing non-directory",
                "nonempty-directory" => "cannot replace a nonempty directory",
                "incoming-backup" => "backup link/config is below",
                "old-backup-child" | "old-backup-declaration" | "retained-child" => {
                    "old database path /link/config"
                }
                "old-link-backup" => "declared as an installed backup",
                "earlier-member" => "traversed by an earlier archive member",
                "later-archive" => "traverses parent symlink /link",
                "late-removal" => "before old owner old is removed",
                "late-upgrade" => "before old owner old is upgraded",
                "escaping-new-parent" => "parent symlink escapes installation root",
                "dangling-new-parent" => "dangling parent symlink target",
                _ => "requires changing old owners with non-directory records",
            };
            assert!(error.to_string().contains(expected), "{scenario}: {error}");
            assert_eq!(std::fs::read_to_string(old.join("files")).unwrap(), files);
            assert_eq!(std::fs::read(old.join("desc")).unwrap(), old_desc);
            assert_eq!(
                std::fs::read(root.join("old-file")).unwrap(),
                b"old payload"
            );
            assert_eq!(
                std::fs::read(root.join("target/config")).unwrap(),
                b"local changes"
            );
            assert_eq!(
                std::fs::read(root.join("target/config.pacnew")).unwrap(),
                b"old pacnew"
            );
            assert_eq!(
                std::fs::read(root.join("target/config.pacsave")).unwrap(),
                b"old pacsave"
            );
            assert!(!root.join("target/config.pacsave.1").exists());
            assert!(!root.join("target/earlier").exists());
            assert!(!root.join("first-payload").exists());
            assert!(!root.join("late-file").exists());
            assert!(!db.join("local/old-2-1").exists());
            assert!(
                !std::fs::read_to_string(log)
                    .unwrap()
                    .contains("transaction started")
            );
            match scenario {
                "regular-file" => assert_eq!(
                    std::fs::read(root.join("link")).unwrap(),
                    b"keep ordinary file"
                ),
                "nonempty-directory" => assert_eq!(
                    std::fs::read(root.join("link/sentinel")).unwrap(),
                    b"keep directory contents"
                ),
                _ => assert_eq!(
                    std::fs::read_link(root.join("link")).unwrap(),
                    Path::new("target")
                ),
            }
        }
    }

    #[test]
    fn alias_blockers_stop_execution_before_hooks_or_backup_changes() {
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
            let downloaded = prepare_archives(&db, &downloaded);
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
        let incoming = HashMap::from([(
            "new",
            IncomingPackage {
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
        let mut incoming = HashMap::from([
            (
                "new",
                IncomingPackage {
                    info: package_info("new"),
                    files: vec!["shared".into()],
                    install_script: None,
                },
            ),
            (
                "old",
                IncomingPackage {
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
