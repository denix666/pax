use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::error::Result;
use crate::extract::{ensure_safe_parent, safe_relative_path, validate_identity};
use crate::log::PaxLogger;
use crate::register::remove_db_entry;
use crate::scriptlet::{ScriptletOp, run_scriptlet};

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
    validate_identity(&target.name, &target.version)?;
    let pkg_dir = db_path
        .join("local")
        .join(format!("{}-{}", target.name, target.version));

    let install_path = pkg_dir.join("install");
    let script = match std::fs::read_to_string(&install_path) {
        Ok(script) => Some(script),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if let Some(script) = &script {
        run_scriptlet(
            &script,
            ScriptletOp::PreRemove,
            &target.version,
            None,
            root_dir,
            &target.name,
            logger,
        )?;
    }

    let removed_files = remove_package_paths(&pkg_dir, root_dir, &HashSet::new())?;

    if let Some(script) = &script {
        run_scriptlet(
            &script,
            ScriptletOp::PostRemove,
            &target.version,
            None,
            root_dir,
            &target.name,
            logger,
        )?;
    }

    remove_db_entry(db_path, &target.name, &target.version)?;

    Ok(removed_files)
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
/// For upgrades, pass the incoming package's paths to retain files it still owns.
/// This does not run scriptlets or delete the database entry.
pub fn remove_package_paths(
    pkg_dir: &Path,
    root_dir: &Path,
    incoming_files: &HashSet<String>,
) -> Result<Vec<String>> {
    let content = match std::fs::read_to_string(pkg_dir.join("files")) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
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
        ensure_safe_parent(root_dir, &relative)?;
        let path = root_dir.join(&relative);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let expected_md5 = backup.iter().find_map(|(backup_path, md5)| {
            (Path::new(backup_path) == relative.as_path()).then_some(md5)
        });
        if let Some(expected_md5) = expected_md5 {
            // Symlinks replacing backup files are also local changes; preserve the link itself.
            let modified = !metadata.is_file() || compute_md5(&path)? != *expected_md5;
            if modified && !metadata.is_dir() {
                let mut pacsave = path.as_os_str().to_os_string();
                pacsave.push(".pacsave");
                let mut pacsave = std::path::PathBuf::from(pacsave);
                let mut suffix = 1;
                loop {
                    match std::fs::symlink_metadata(&pacsave) {
                        Ok(_) => {
                            let mut name = path.as_os_str().to_os_string();
                            name.push(format!(".pacsave.{suffix}"));
                            pacsave = name.into();
                            suffix += 1;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                        Err(error) => return Err(error.into()),
                    }
                }
                std::fs::rename(&path, &pacsave)?;
                eprintln!("warning: {file} saved as {}", pacsave.display());
                removed.push(file.clone());
                continue;
            }
        }
        if metadata.is_dir() {
            match std::fs::remove_dir(&path) {
                Ok(()) => {}
                Err(error)
                    if error.raw_os_error() == Some(libc::ENOTEMPTY)
                        || error.raw_os_error() == Some(libc::EEXIST) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            std::fs::remove_file(&path)?;
        }
        removed.push(file.clone());
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

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
