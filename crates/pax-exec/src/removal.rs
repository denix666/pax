use std::collections::HashMap;
use std::path::Path;

use crate::error::Result;
use crate::register::remove_db_entry;
use crate::scriptlet::{run_scriptlet, ScriptletOp};

pub struct RemovalTarget {
    pub name: String,
    pub version: String,
}

pub fn remove_package(
    target: &RemovalTarget,
    root_dir: &Path,
    db_path: &Path,
) -> Result<Vec<String>> {
    let pkg_dir = db_path
        .join("local")
        .join(format!("{}-{}", target.name, target.version));

    let install_path = pkg_dir.join("install");
    if let Ok(script) = std::fs::read_to_string(&install_path) {
        run_scriptlet(
            &script,
            ScriptletOp::PreRemove,
            &target.version,
            None,
            root_dir,
            &target.name,
        )?;
    }

    let removed_files = remove_files(&pkg_dir, root_dir)?;

    if let Ok(script) = std::fs::read_to_string(&install_path) {
        run_scriptlet(
            &script,
            ScriptletOp::PostRemove,
            &target.version,
            None,
            root_dir,
            &target.name,
        )?;
    }

    remove_db_entry(db_path, &target.name, &target.version)?;

    Ok(removed_files)
}

fn remove_files(pkg_dir: &Path, root_dir: &Path) -> Result<Vec<String>> {
    let files_path = pkg_dir.join("files");
    if !files_path.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(&files_path)?;

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
            }
        }
    }

    files.sort();
    files.reverse();

    let mut removed = Vec::new();

    for file in &files {
        let path = root_dir.join(file);

        if let Some(expected_md5) = backup.get(file.as_str()) {
            if path.is_file() {
                let current_md5 = compute_md5(&path).unwrap_or_default();
                if current_md5 != *expected_md5 {
                    let pacsave = format!("{}.pacsave", path.display());
                    let _ = std::fs::rename(&path, &pacsave);
                    eprintln!(
                        "warning: {} saved as {}",
                        file,
                        pacsave
                    );
                    removed.push(file.clone());
                    continue;
                }
            }
        }

        if path.is_symlink() || path.is_file() {
            let _ = std::fs::remove_file(&path);
        } else if path.is_dir() {
            let _ = std::fs::remove_dir(&path);
        }
        removed.push(file.clone());
    }

    Ok(removed)
}

fn compute_md5(path: &Path) -> Result<String> {
    let data = std::fs::read(path)?;
    Ok(format!("{:x}", md5::compute(&data)))
}
