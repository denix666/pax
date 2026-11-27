use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::error::{ExecError, Result};
use crate::execute::{
    finish_transaction, read_file_list, retained_removal_directories, run_transaction_hooks,
    run_transaction_scriptlet,
};
use crate::extract::{ensure_safe_parent, safe_relative_path, validate_identity};
use crate::hooks::{HookWhen, TransactionPackages};
use crate::log::PaxLogger;
use crate::register::remove_db_entry;
use crate::scriptlet::ScriptletOp;

pub struct RemovalTarget {
    pub name: String,
    pub version: String,
}

pub fn remove_package(
    target: &RemovalTarget,
    root_dir: &Path,
    db_path: &Path,
    logger: &mut PaxLogger,
) -> Result<Vec<String>> {
    pax_alpm::lock::ensure_no_active_transaction(db_path)?;
    let files = read_file_list(db_path, &target.name, &target.version)?;
    validate_removal_paths(root_dir, &files)?;
    let retained_directories =
        retained_removal_directories(root_dir, db_path, std::slice::from_ref(target), &files)?;
    logger.log_transaction_start();
    let mut failures = Vec::new();
    let mut removed_files = Vec::new();
    let result = remove_transaction_package(
        target,
        root_dir,
        db_path,
        logger,
        &mut failures,
        &retained_directories,
    )
    .map(|removed| {
        removed_files = removed;
        logger.log_removed(&target.name, &target.version);
    });
    finish_transaction(result, failures, logger)?;
    Ok(removed_files)
}

pub(crate) fn remove_transaction_package(
    target: &RemovalTarget,
    root_dir: &Path,
    db_path: &Path,
    logger: &mut PaxLogger,
    failures: &mut Vec<String>,
    retained_directories: &HashSet<String>,
) -> Result<Vec<String>> {
    validate_identity(&target.name, &target.version)?;
    let original_files = read_file_list(db_path, &target.name, &target.version)?;
    validate_removal_paths(root_dir, &original_files)?;
    let pkg_dir = db_path
        .join("local")
        .join(format!("{}-{}", target.name, target.version));

    let install_path = pkg_dir.join("install");
    let script = match std::fs::read_to_string(&install_path) {
        Ok(script) => Some(script),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(std::io::Error::new(
                error.kind(),
                format!(
                    "{} {}: read removal script {}: {error}",
                    target.name,
                    target.version,
                    install_path.display()
                ),
            )
            .into());
        }
    };
    if let Some(script) = &script {
        run_transaction_scriptlet(
            failures,
            script,
            ScriptletOp::PreRemove,
            &target.version,
            None,
            root_dir,
            &target.name,
            logger,
        );
    }

    let removed_files =
        remove_package_paths(&pkg_dir, root_dir, retained_directories).map_err(|error| {
            std::io::Error::other(format!(
                "{} {}: remove paths from {}: {error}",
                target.name,
                target.version,
                pkg_dir.display()
            ))
        })?;

    if let Some(script) = &script {
        run_transaction_scriptlet(
            failures,
            script,
            ScriptletOp::PostRemove,
            &target.version,
            None,
            root_dir,
            &target.name,
            logger,
        );
    }

    remove_db_entry(db_path, &target.name, &target.version).map_err(|error| {
        std::io::Error::other(format!(
            "{} {}: remove database entry {}: {error}",
            target.name,
            target.version,
            pkg_dir.display()
        ))
    })?;

    Ok(removed_files)
}

/// Execute removals under a caller-held DB lock, with the same hook and
/// maintenance outcome semantics as installation and upgrade transactions.
pub fn execute_removal_transaction(
    targets: &[RemovalTarget],
    root_dir: &Path,
    db_path: &Path,
    hook_dirs: &[PathBuf],
    logger: &mut PaxLogger,
) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(ExecError::NotRoot);
    }
    pax_alpm::lock::ensure_no_active_transaction(db_path)?;
    let mut files = Vec::new();
    for target in targets {
        let outgoing = read_file_list(db_path, &target.name, &target.version)?;
        validate_removal_paths(root_dir, &outgoing)?;
        files.extend(outgoing);
    }
    files.sort();
    files.dedup();
    let retained_directories = retained_removal_directories(root_dir, db_path, targets, &files)?;
    files.retain(|file| !retained_directories.contains(file.trim_end_matches('/')));
    let mut packages = TransactionPackages {
        removed: targets.iter().map(|target| target.name.clone()).collect(),
        removed_files: files,
        ..Default::default()
    };
    logger.log_transaction_start();
    let mut failures = Vec::new();
    let result = (|| {
        run_transaction_hooks(
            root_dir,
            db_path,
            hook_dirs,
            &HookWhen::PreTransaction,
            &packages,
            logger,
            &mut failures,
        )?;
        packages.removed_files.clear();
        eprintln!(":: Applying package removals...");
        for (index, target) in targets.iter().enumerate() {
            eprintln!(
                "({}/{}) Removing {} ({})...",
                index + 1,
                targets.len(),
                target.name,
                target.version
            );
            let removed = remove_transaction_package(
                target,
                root_dir,
                db_path,
                logger,
                &mut failures,
                &retained_directories,
            )?;
            packages.removed_files.extend(removed);
            logger.log_removed(&target.name, &target.version);
        }
        // Only run the planned post-hooks once every removal has succeeded.
        eprintln!(":: Running post-transaction maintenance...");
        run_transaction_hooks(
            root_dir,
            db_path,
            hook_dirs,
            &HookWhen::PostTransaction,
            &packages,
            logger,
            &mut failures,
        )
    })();
    finish_transaction(result, failures, logger)
}

/// Validate outgoing file lists without modifying the filesystem. The final path
/// may itself be a symlink: removal unlinks it without following its target.
pub fn validate_removal_paths(root_dir: &Path, files: &[String]) -> Result<()> {
    for file in files {
        let relative = safe_relative_path(Path::new(file))?;
        if relative.as_os_str().is_empty() {
            return Err(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "empty removal path").into(),
            );
        }
        ensure_safe_parent(root_dir, &relative)?;
    }
    Ok(())
}

/// Remove paths from an old local DB entry, saving modified backups as .pacsave.
/// For upgrades, pass all incoming paths to retain files taken over in this transaction.
/// This does not run scriptlets or delete the database entry.
pub fn remove_package_paths(
    pkg_dir: &Path,
    root_dir: &Path,
    incoming_files: &HashSet<String>,
) -> Result<Vec<String>> {
    let content = crate::execute::read_file_metadata(&pkg_dir.join("files"))?;
    let incoming: HashSet<_> = incoming_files
        .iter()
        .map(|path| safe_relative_path(Path::new(path)))
        .collect::<Result<_>>()?;

    let mut files: Vec<String> = Vec::new();
    let mut backup: HashMap<String, String> = HashMap::new();
    let mut in_files = false;
    let mut in_backup = false;

    for line in content.lines() {
        match line {
            "%FILES%" => {
                in_files = true;
                in_backup = false;
                continue;
            }
            "%BACKUP%" => {
                in_files = false;
                in_backup = true;
                continue;
            }
            l if l.starts_with('%') || l.is_empty() => {
                in_files = false;
                in_backup = false;
                continue;
            }
            _ => {}
        }

        if in_files {
            files.push(line.to_string());
        } else if in_backup {
            if let Some((path, md5)) = line.split_once('\t') {
                backup.insert(path.to_string(), md5.to_string());
            } else {
                // A missing baseline must never make a backup disposable.
                backup.insert(line.to_string(), String::new());
            }
        }
    }

    validate_removal_paths(root_dir, &files)?;
    files.sort_by_key(|file| std::cmp::Reverse(Path::new(file).components().count()));

    let mut removed = Vec::new();

    for file in &files {
        let relative = safe_relative_path(Path::new(file))?;
        if incoming.contains(&relative) {
            continue;
        }
        let expected_md5 = backup.iter().find_map(|(backup_path, md5)| {
            (Path::new(backup_path) == relative.as_path()).then_some(md5.as_str())
        });
        let applied = (|| {
            ensure_safe_parent(root_dir, &relative)?;
            remove_path(root_dir, &relative, expected_md5)
        })()
        .map_err(|error: ExecError| {
            std::io::Error::other(format!(
                "package entry {}: remove path {}: {error}",
                pkg_dir.display(),
                root_dir.join(&relative).display()
            ))
        })?;
        if applied {
            removed.push(file.clone());
        }
    }

    Ok(removed)
}

fn should_save_backup(
    expected_md5: Option<&str>,
    is_directory: bool,
    matches_md5: impl FnOnce(&str) -> Result<bool>,
) -> Result<bool> {
    if is_directory {
        return Ok(false);
    }
    match expected_md5 {
        // No baseline and nonregular replacements are local changes, not disposable backups.
        Some("") => Ok(true),
        Some(expected) => Ok(!matches_md5(expected)?),
        None => Ok(false),
    }
}

fn select_pacsave<T>(
    relative: &Path,
    mut absent: impl FnMut(&Path) -> Result<Option<T>>,
) -> Result<(PathBuf, T)> {
    for suffix in 0..10_000 {
        let mut candidate = relative.as_os_str().to_os_string();
        candidate.push(".pacsave");
        if suffix != 0 {
            candidate.push(format!(".{suffix}"));
        }
        let candidate = PathBuf::from(candidate);
        let available = absent(&candidate).map_err(|error| {
            std::io::Error::other(format!(
                "inspect pacsave destination {}: {error}",
                candidate.display()
            ))
        })?;
        if let Some(destination) = available {
            return Ok((candidate, destination));
        }
    }
    Err(std::io::Error::other(format!(
        "select pacsave destination for {}: all 10000 candidates occupied",
        relative.display()
    ))
    .into())
}

fn remove_path(root_dir: &Path, relative: &Path, expected_md5: Option<&str>) -> Result<bool> {
    let path = root_dir.join(relative);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if should_save_backup(expected_md5, metadata.is_dir(), |expected| {
        Ok(metadata.is_file() && compute_md5(&path)? == expected)
    })? {
        let (pacsave, ()) =
            select_pacsave(relative, |candidate| {
                match std::fs::symlink_metadata(root_dir.join(candidate)) {
                    Ok(_) => Ok(None),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Some(())),
                    Err(error) => Err(error.into()),
                }
            })?;
        let pacsave = root_dir.join(pacsave);
        rename_noreplace(&path, &pacsave).map_err(|error| {
            std::io::Error::other(format!(
                "pacsave rename {} to {} without replacement: {error}",
                path.display(),
                pacsave.display()
            ))
        })?;
        eprintln!(
            "warning: {} saved as {}",
            relative.display(),
            pacsave.display()
        );
        return Ok(true);
    }
    if metadata.is_dir() {
        match std::fs::remove_dir(&path) {
            Ok(()) => {}
            Err(error)
                if error.raw_os_error() == Some(libc::ENOTEMPTY)
                    || error.raw_os_error() == Some(libc::EEXIST) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        }
    } else {
        std::fs::remove_file(&path)?;
    }
    Ok(true)
}

fn rename_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    let source = CString::new(source.as_os_str().as_bytes())?;
    let destination = CString::new(destination.as_os_str().as_bytes())?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct RemovalFixture {
        _temporary: tempfile::TempDir,
        root: PathBuf,
        entry: PathBuf,
    }

    impl RemovalFixture {
        fn new(metadata: &str, setup: impl FnOnce(&Path)) -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("root");
            let entry = temporary.path().join("db/local/example-1-1");
            std::fs::create_dir_all(&entry).unwrap();
            std::fs::create_dir(&root).unwrap();
            std::fs::write(entry.join("desc"), "%NAME%\nexample\n\n%VERSION%\n1-1\n\n").unwrap();
            std::fs::write(entry.join("files"), metadata).unwrap();
            setup(&root);
            Self {
                _temporary: temporary,
                root,
                entry,
            }
        }

        fn remove(&self, incoming: &HashSet<String>) -> Result<Vec<String>> {
            remove_package_paths(&self.entry, &self.root, incoming)
        }
    }

    fn assert_shared_directory_removal(
        outgoing_dir: &str,
        retained_dir: &str,
        transaction: bool,
        remove_both: bool,
    ) {
        let fixture =
            RemovalFixture::new(&format!("%FILES%\n{outgoing_dir}\nonly-a\n\n"), |root| {
                if outgoing_dir == "shared/" {
                    std::fs::create_dir(root.join("shared")).unwrap();
                } else {
                    std::fs::create_dir_all(root.join("usr/lib/shared")).unwrap();
                    symlink("usr/lib", root.join("lib")).unwrap();
                }
                std::fs::write(root.join("only-a"), "remove me").unwrap();
            });
        let db = fixture._temporary.path().join("db");
        let remaining = db.join("local/retained-1-1");
        std::fs::create_dir(&remaining).unwrap();
        let desc = "%NAME%\nretained\n\n%VERSION%\n1-1\n\n";
        let files = format!("%FILES%\n{retained_dir}\n\n");
        std::fs::write(remaining.join("desc"), desc).unwrap();
        std::fs::write(remaining.join("files"), &files).unwrap();
        let mut targets = vec![RemovalTarget {
            name: "example".into(),
            version: "1-1".into(),
        }];
        if remove_both {
            targets.push(RemovalTarget {
                name: "retained".into(),
                version: "1-1".into(),
            });
        }
        let _lock = pax_alpm::DbLock::acquire(&db).unwrap();
        if transaction {
            let hooks = fixture._temporary.path().join("hooks");
            std::fs::create_dir(&hooks).unwrap();
            if !remove_both {
                for when in ["PreTransaction", "PostTransaction"] {
                    std::fs::write(hooks.join(format!("{when}.hook")), format!(
                        "[Trigger]\nType = Path\nOperation = Remove\nTarget = {}*\n[Action]\nWhen = {when}\nExec = /must-not-run\nAbortOnFail\n",
                        outgoing_dir.trim_end_matches('/')
                    )).unwrap();
                }
            }
            execute_removal_transaction(
                &targets,
                &fixture.root,
                &db,
                &[hooks],
                &mut PaxLogger::none(),
            )
            .unwrap();
        } else {
            let removed =
                remove_package(&targets[0], &fixture.root, &db, &mut PaxLogger::none()).unwrap();
            assert_eq!(removed, ["only-a"]);
        }
        assert!(!fixture.root.join("only-a").exists());
        assert!(!fixture.entry.exists());
        if remove_both {
            assert!(!fixture.root.join(outgoing_dir).exists());
            assert!(!fixture.root.join(retained_dir).exists());
            assert!(!remaining.exists());
        } else {
            assert!(fixture.root.join(outgoing_dir).is_dir());
            assert!(fixture.root.join(retained_dir).is_dir());
            assert_eq!(
                std::fs::read_dir(fixture.root.join(retained_dir))
                    .unwrap()
                    .count(),
                0
            );
            assert_eq!(
                std::fs::read(remaining.join("desc")).unwrap(),
                desc.as_bytes()
            );
            assert_eq!(
                std::fs::read(remaining.join("files")).unwrap(),
                files.as_bytes()
            );
        }
        if outgoing_dir != "shared/" {
            assert_eq!(
                std::fs::read_link(fixture.root.join("lib")).unwrap(),
                Path::new("usr/lib")
            );
        }
    }

    #[test]
    fn single_removal_preserves_shared_empty_directories_and_aliases() {
        for (outgoing, retained) in [
            ("shared/", "shared/"),
            ("lib/shared/", "usr/lib/shared/"),
            ("usr/lib/shared/", "lib/shared/"),
        ] {
            assert_shared_directory_removal(outgoing, retained, false, false);
        }
    }

    #[test]
    fn removal_transaction_preserves_shared_empty_directories_and_aliases() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        for (outgoing, retained) in [
            ("shared/", "shared/"),
            ("lib/shared/", "usr/lib/shared/"),
            ("usr/lib/shared/", "lib/shared/"),
        ] {
            assert_shared_directory_removal(outgoing, retained, true, false);
            assert_shared_directory_removal(outgoing, retained, true, true);
        }
    }

    #[test]
    fn invalid_remaining_file_metadata_stops_removal_before_changes() {
        for contents in [None, Some("damaged"), Some("%FILES%\n../outside/\n\n")] {
            let fixture = RemovalFixture::new("%FILES%\nshared/\nonly-a\n\n", |root| {
                std::fs::create_dir(root.join("shared")).unwrap();
                std::fs::write(root.join("only-a"), "keep").unwrap();
            });
            let db = fixture._temporary.path().join("db");
            let remaining = db.join("local/retained-1-1");
            std::fs::create_dir(&remaining).unwrap();
            std::fs::write(
                remaining.join("desc"),
                "%NAME%\nretained\n\n%VERSION%\n1-1\n\n",
            )
            .unwrap();
            if let Some(contents) = contents {
                std::fs::write(remaining.join("files"), contents).unwrap();
            }
            let error = remove_package(
                &RemovalTarget {
                    name: "example".into(),
                    version: "1-1".into(),
                },
                &fixture.root,
                &db,
                &mut PaxLogger::none(),
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("retained"), "{error}");
            assert!(fixture.root.join("shared").is_dir());
            assert_eq!(std::fs::read(fixture.root.join("only-a")).unwrap(), b"keep");
            assert!(fixture.entry.join("desc").is_file());
            assert!(remaining.join("desc").is_file());
        }
    }

    #[test]
    fn removal_skips_absent_and_incoming_and_retains_nonempty_directories() {
        let fixture = RemovalFixture::new(
            "%FILES%\nempty/\nnonempty/\nnonempty/owned\nplain\nlink\nmissing\nretained\n\n",
            |root| {
                std::fs::create_dir(root.join("empty")).unwrap();
                std::fs::create_dir(root.join("nonempty")).unwrap();
                for path in ["plain", "retained", "nonempty/owned", "nonempty/unlisted"] {
                    std::fs::write(root.join(path), path).unwrap();
                }
                symlink("plain", root.join("link")).unwrap();
            },
        );
        let removed = fixture.remove(&HashSet::from(["retained".into()])).unwrap();
        assert_eq!(removed, ["nonempty/owned", "empty/", "plain", "link"]);
        assert!(!fixture.root.join("empty").exists());
        assert!(!fixture.root.join("link").is_symlink());
        assert_eq!(
            std::fs::read(fixture.root.join("nonempty/unlisted")).unwrap(),
            b"nonempty/unlisted"
        );
        assert_eq!(
            std::fs::read(fixture.root.join("retained")).unwrap(),
            b"retained"
        );
    }

    #[test]
    fn pacsave_observes_post_hook_changes_and_never_clobbers_existing_saves() {
        let md5 = format!("{:x}", md5::compute("original"));
        let metadata = format!(
            "%FILES%\nchanged\nunchanged\nlinked\nlegacy\ncreated\n\n%BACKUP%\nchanged\t{md5}\nunchanged\t{md5}\nlinked\t{md5}\nlegacy\ncreated\t{md5}\n\n"
        );
        let fixture = RemovalFixture::new(&metadata, |root| {
            for path in ["changed", "unchanged", "legacy"] {
                std::fs::write(root.join(path), "original").unwrap();
            }
            symlink("missing", root.join("linked")).unwrap();
        });
        std::fs::write(fixture.root.join("changed"), "post-hook contents").unwrap();
        std::fs::write(fixture.root.join("changed.pacsave"), "older save").unwrap();
        symlink("missing", fixture.root.join("changed.pacsave.1")).unwrap();
        std::fs::write(fixture.root.join("created"), "created after preflight").unwrap();
        assert_eq!(fixture.remove(&HashSet::new()).unwrap().len(), 5);
        assert_eq!(
            std::fs::read(fixture.root.join("changed.pacsave")).unwrap(),
            b"older save"
        );
        assert_eq!(
            std::fs::read_link(fixture.root.join("changed.pacsave.1")).unwrap(),
            Path::new("missing")
        );
        assert_eq!(
            std::fs::read(fixture.root.join("changed.pacsave.2")).unwrap(),
            b"post-hook contents"
        );
        assert_eq!(
            std::fs::read_link(fixture.root.join("linked.pacsave")).unwrap(),
            Path::new("missing")
        );
        assert_eq!(
            std::fs::read(fixture.root.join("legacy.pacsave")).unwrap(),
            b"original"
        );
        assert_eq!(
            std::fs::read(fixture.root.join("created.pacsave")).unwrap(),
            b"created after preflight"
        );
        assert!(!fixture.root.join("unchanged").exists());
        assert!(!fixture.root.join("unchanged.pacsave").exists());
    }

    #[test]
    fn late_pacsave_collision_fails_without_overwrite_or_retry() {
        let fixture = RemovalFixture::new("%FILES%\nfile\n\n", |root| {
            std::fs::write(root.join("file"), "local changes").unwrap();
        });
        let (candidate, ()) = select_pacsave(Path::new("file"), |path| {
            Ok((!fixture.root.join(path).exists()).then_some(()))
        })
        .unwrap();
        std::fs::write(fixture.root.join(&candidate), "late arrival").unwrap();
        assert!(
            rename_noreplace(&fixture.root.join("file"), &fixture.root.join(candidate)).is_err()
        );
        assert_eq!(
            std::fs::read(fixture.root.join("file")).unwrap(),
            b"local changes"
        );
        assert_eq!(
            std::fs::read(fixture.root.join("file.pacsave")).unwrap(),
            b"late arrival"
        );
        assert!(!fixture.root.join("file.pacsave.1").exists());
    }

    #[test]
    fn pacsave_no_replace_rejects_late_dangling_symlink() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("config");
        std::fs::write(&source, "local changes").unwrap();
        let (candidate, ()) = select_pacsave(Path::new("config"), |_| Ok(Some(()))).unwrap();
        let destination = temporary.path().join(candidate);
        symlink("missing", &destination).unwrap();
        assert_eq!(
            rename_noreplace(&source, &destination)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EEXIST)
        );
        assert_eq!(std::fs::read(source).unwrap(), b"local changes");
        assert_eq!(
            std::fs::read_link(destination).unwrap(),
            Path::new("missing")
        );
    }

    #[test]
    fn pacsave_selection_is_bounded_and_preserves_raw_relative_names() {
        let relative = Path::new(std::ffi::OsStr::from_bytes(b"etc/raw-\xff.conf"));
        let mut inspected = 0;
        let error = select_pacsave::<()>(relative, |candidate| {
            assert!(!candidate.is_absolute());
            assert!(
                candidate
                    .as_os_str()
                    .as_bytes()
                    .starts_with(b"etc/raw-\xff.conf.pacsave")
            );
            inspected += 1;
            Ok(None)
        })
        .unwrap_err();
        assert_eq!(inspected, 10_000);
        assert!(error.to_string().contains("all 10000 candidates occupied"));
        let (candidate, ()) = select_pacsave(relative, |_| Ok(Some(()))).unwrap();
        assert_eq!(
            candidate.as_os_str().as_bytes(),
            b"etc/raw-\xff.conf.pacsave"
        );
    }

    #[test]
    fn missing_or_damaged_file_metadata_does_not_silently_remove_database_entry() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        let entry = db.join("local/example-1-1");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("desc"), "%NAME%\nexample\n\n%SIZE%\n4\n\n").unwrap();
        std::fs::write(root.join("file"), "keep").unwrap();
        assert!(remove_package_paths(&entry, &root, &HashSet::new()).is_err());
        std::fs::write(entry.join("files"), "damaged").unwrap();
        assert!(remove_package_paths(&entry, &root, &HashSet::new()).is_err());
        let target = RemovalTarget {
            name: "example".into(),
            version: "1-1".into(),
        };
        assert!(remove_package(&target, &root, &db, &mut PaxLogger::none()).is_err());
        assert!(entry.join("desc").exists());
        assert_eq!(std::fs::read_to_string(root.join("file")).unwrap(), "keep");
        assert!(!db.join("pax-transactions").exists());
    }

    #[test]
    fn outgoing_path_preflight_is_read_only_and_does_not_follow_final_links() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("file"), "keep").unwrap();
        symlink(&outside, root.join("link")).unwrap();
        validate_removal_paths(&root, &["link".into()]).unwrap();
        assert!(validate_removal_paths(&root, &["link/file".into()]).is_err());
        assert!(validate_removal_paths(&root, &["../outside/file".into()]).is_err());
        assert!(validate_removal_paths(&root, &["/outside/file".into()]).is_err());
        assert!(root.join("link").is_symlink());
        assert_eq!(
            std::fs::read_to_string(outside.join("file")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn stale_backups_are_saved_and_incoming_paths_retained() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        let old_md5 = format!("{:x}", md5::compute("original"));
        std::fs::write(db.join("files"), format!("%FILES%\netc/\netc/stale\netc/retained\netc/plain\n\n%BACKUP%\netc/stale\t{old_md5}\netc/retained\t{old_md5}\n\n")).unwrap();
        std::fs::write(root.join("etc/stale"), "edited").unwrap();
        std::fs::write(root.join("etc/stale.pacsave"), "older save").unwrap();
        std::fs::write(root.join("etc/retained"), "keep").unwrap();
        std::fs::write(root.join("etc/plain"), "remove").unwrap();
        let incoming = HashSet::from(["etc/retained".to_string()]);
        let removed = remove_package_paths(&db, &root, &incoming).unwrap();
        assert!(removed.contains(&"etc/stale".to_string()));
        assert!(!root.join("etc/plain").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("etc/stale.pacsave")).unwrap(),
            "older save"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("etc/stale.pacsave.1")).unwrap(),
            "edited"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("etc/retained")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn removal_rejects_escaping_parent_before_deletion() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        let outside = temp.path().join("outside");
        for dir in [&root, &db, &outside] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(outside.join("file"), "keep").unwrap();
        symlink(&outside, root.join("link")).unwrap();
        std::fs::write(db.join("files"), "%FILES%\nlink/file\n\n").unwrap();
        assert!(remove_package_paths(&db, &root, &HashSet::new()).is_err());
        assert_eq!(
            std::fs::read_to_string(outside.join("file")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn unchanged_backup_is_removed_and_symlink_backup_saved() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        let hash = format!("{:x}", md5::compute("original"));
        std::fs::write(
            db.join("files"),
            format!("%FILES%\nconfig\nlinked\n\n%BACKUP%\nconfig\t{hash}\nlinked\t{hash}\n\n"),
        )
        .unwrap();
        std::fs::write(root.join("config"), "original").unwrap();
        symlink("missing", root.join("linked")).unwrap();
        remove_package_paths(&db, &root, &HashSet::new()).unwrap();
        assert!(!root.join("config").exists());
        assert_eq!(
            std::fs::read_link(root.join("linked.pacsave")).unwrap(),
            Path::new("missing")
        );
    }
}

fn compute_md5(path: &Path) -> Result<String> {
    let data = std::fs::read(path)?;
    Ok(format!("{:x}", md5::compute(&data)))
}
