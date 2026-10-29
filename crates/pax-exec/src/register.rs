use std::path::Path;

use pax_alpm::desc::{generate_files_content, generate_local_desc_from_pkginfo};
use pax_core::package::{InstallReason, Validation};

use crate::error::{ExecError, Result};
use crate::extract::{PackageMetadata, validate_identity};

pub fn register_package(
    db_path: &Path,
    metadata: &PackageMetadata,
    reason: InstallReason,
    validation: &[Validation],
    _root_dir: &Path,
) -> Result<()> {
    let (name, version) = parse_name_version(&metadata.pkginfo)?;

    let installed_size = parse_pkginfo_field(&metadata.pkginfo, "size")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    let install_date = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let pkg_dir = db_path.join("local").join(format!("{name}-{version}"));
    let tmp_dir = db_path.join("local").join(format!(".{name}-{version}.tmp"));

    if tmp_dir.exists() {
        std::fs::remove_dir_all(&tmp_dir)?;
    }
    std::fs::create_dir_all(&tmp_dir)?;

    let desc = generate_local_desc_from_pkginfo(
        &metadata.pkginfo,
        installed_size,
        install_date,
        reason,
        validation,
    );
    std::fs::write(tmp_dir.join("desc"), &desc)?;

    let backup_with_md5: Vec<(String, String)> = metadata
        .backup
        .iter()
        .map(|path| {
            let md5 = metadata
                .backup_md5
                .get(path)
                .ok_or_else(|| ExecError::Extraction {
                    pkg: name.clone(),
                    message: format!("missing archive MD5 for backup {path}"),
                })?;
            Ok((path.clone(), md5.clone()))
        })
        .collect::<Result<_>>()?;

    let files_content = generate_files_content(&metadata.files, &backup_with_md5);
    std::fs::write(tmp_dir.join("files"), &files_content)?;

    if !metadata.mtree.is_empty() {
        std::fs::write(tmp_dir.join("mtree"), &metadata.mtree)?;
    }

    if let Some(ref install) = metadata.install {
        std::fs::write(tmp_dir.join("install"), install)?;
    }

    if pkg_dir.exists() {
        std::fs::remove_dir_all(&pkg_dir)?;
    }
    std::fs::rename(&tmp_dir, &pkg_dir)?;

    Ok(())
}

pub fn remove_db_entry(db_path: &Path, name: &str, version: &str) -> Result<()> {
    validate_identity(name, version)?;
    let pkg_dir = db_path.join("local").join(format!("{name}-{version}"));
    if pkg_dir.exists() {
        std::fs::remove_dir_all(&pkg_dir)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn registration_uses_archive_hash_even_with_local_modifications() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/config"), "local changes").unwrap();
        let hash = format!("{:x}", md5::compute("incoming defaults"));
        let metadata = PackageMetadata {
            pkginfo: "pkgname = test\npkgver = 1-1\n".into(),
            mtree: Vec::new(),
            install: None,
            files: vec!["etc/config".into()],
            backup: vec!["etc/config".into()],
            backup_md5: HashMap::from([("etc/config".into(), hash.clone())]),
            warnings: Vec::new(),
        };
        register_package(&db, &metadata, InstallReason::Explicit, &[], &root).unwrap();
        let files = std::fs::read_to_string(db.join("local/test-1-1/files")).unwrap();
        assert!(files.contains(&format!("etc/config\t{hash}")));
    }

    #[test]
    fn registration_requires_backup_archive_hash() {
        let temp = tempfile::tempdir().unwrap();
        let metadata = PackageMetadata {
            pkginfo: "pkgname = test\npkgver = 1-1\n".into(),
            mtree: Vec::new(),
            install: None,
            files: vec!["config".into()],
            backup: vec!["config".into()],
            backup_md5: HashMap::new(),
            warnings: Vec::new(),
        };
        assert!(
            register_package(
                temp.path(),
                &metadata,
                InstallReason::Explicit,
                &[],
                temp.path()
            )
            .is_err()
        );
        assert!(!temp.path().join("local/test-1-1").exists());
    }
}

fn parse_name_version(pkginfo: &str) -> Result<(String, String)> {
    let mut name = None;
    let mut version = None;

    for line in pkginfo.lines() {
        if let Some(val) = line.strip_prefix("pkgname = ") {
            name = Some(val.to_string());
        } else if let Some(val) = line.strip_prefix("pkgver = ") {
            version = Some(val.to_string());
        }
        if name.is_some() && version.is_some() {
            break;
        }
    }

    match (name, version) {
        (Some(n), Some(v)) => {
            validate_identity(&n, &v)?;
            Ok((n, v))
        }
        _ => Err(ExecError::Extraction {
            pkg: String::new(),
            message: "missing pkgname or pkgver in .PKGINFO".to_string(),
        }),
    }
}

fn parse_pkginfo_field<'a>(pkginfo: &'a str, field: &str) -> Option<&'a str> {
    let prefix = format!("{field} = ");
    pkginfo
        .lines()
        .find(|line| line.starts_with(&prefix))
        .map(|line| &line[prefix.len()..])
}
