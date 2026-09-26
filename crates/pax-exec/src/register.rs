use std::path::Path;

use pax_alpm::desc::{generate_files_content, generate_local_desc_from_pkginfo};
use pax_core::package::{InstallReason, Validation};

use crate::error::{ExecError, Result};
use crate::extract::PackageMetadata;

pub fn register_package(
    db_path: &Path,
    metadata: &PackageMetadata,
    reason: InstallReason,
    validation: &[Validation],
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
            let md5 = compute_file_md5(Path::new("/").join(path))
                .unwrap_or_default();
            (path.clone(), md5)
        })
        .collect();

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
    let pkg_dir = db_path.join("local").join(format!("{name}-{version}"));
    if pkg_dir.exists() {
        std::fs::remove_dir_all(&pkg_dir)?;
    }
    Ok(())
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
        (Some(n), Some(v)) => Ok((n, v)),
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

fn compute_file_md5(path: impl AsRef<Path>) -> Result<String> {
    let data = std::fs::read(path)?;
    Ok(format!("{:x}", md5::compute(&data)))
}
