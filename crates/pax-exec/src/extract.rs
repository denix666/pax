use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use tar::Archive;

use crate::error::{ExecError, Result};

pub struct PackageMetadata {
    pub pkginfo: String,
    pub mtree: Vec<u8>,
    pub install: Option<String>,
    pub files: Vec<String>,
    pub backup: Vec<String>,
}

pub fn extract_package(
    pkg_path: &Path,
    root_dir: &Path,
    existing_backup_md5: &HashMap<String, String>,
) -> Result<PackageMetadata> {
    let pkg_name = pkg_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let file = std::fs::File::open(pkg_path)?;
    let decompressor = decompress(file, &pkg_name)?;
    let mut archive = Archive::new(decompressor);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    archive.set_unpack_xattrs(true);

    let mut pkginfo = String::new();
    let mut mtree = Vec::new();
    let mut install = None;
    let mut files: Vec<String> = Vec::new();
    let mut backup_entries: Vec<String> = Vec::new();

    for entry_result in archive.entries().map_err(|e| ExecError::Extraction {
        pkg: pkg_name.clone(),
        message: e.to_string(),
    })? {
        let mut entry = entry_result.map_err(|e| ExecError::Extraction {
            pkg: pkg_name.clone(),
            message: e.to_string(),
        })?;

        let path = entry
            .path()
            .map_err(|e| ExecError::Extraction {
                pkg: pkg_name.clone(),
                message: e.to_string(),
            })?
            .to_path_buf();

        let path_str = path.to_string_lossy().to_string();
        let path_str = path_str.strip_prefix("./").unwrap_or(&path_str);

        if path_str.starts_with('.') {
            match path_str {
                ".PKGINFO" => {
                    entry.read_to_string(&mut pkginfo).map_err(|e| {
                        ExecError::Extraction {
                            pkg: pkg_name.clone(),
                            message: format!(".PKGINFO: {e}"),
                        }
                    })?;
                    backup_entries = parse_backup_from_pkginfo(&pkginfo);
                }
                ".MTREE" => {
                    entry.read_to_end(&mut mtree).map_err(|e| {
                        ExecError::Extraction {
                            pkg: pkg_name.clone(),
                            message: format!(".MTREE: {e}"),
                        }
                    })?;
                }
                ".INSTALL" => {
                    let mut s = String::new();
                    entry.read_to_string(&mut s).map_err(|e| {
                        ExecError::Extraction {
                            pkg: pkg_name.clone(),
                            message: format!(".INSTALL: {e}"),
                        }
                    })?;
                    install = Some(s);
                }
                _ => {}
            }
            continue;
        }

        files.push(path_str.to_string());

        let dest = root_dir.join(path_str);

        if backup_entries.contains(&path_str.to_string()) {
            if let Some(existing_md5) = existing_backup_md5.get(path_str) {
                if dest.exists() {
                    let current_md5 = compute_md5(&dest)?;
                    if current_md5 != *existing_md5 {
                        let pacnew = PathBuf::from(format!("{}.pacnew", dest.display()));
                        entry.unpack(&pacnew).map_err(|e| ExecError::Extraction {
                            pkg: pkg_name.clone(),
                            message: format!("{}: {e}", pacnew.display()),
                        })?;
                        continue;
                    }
                }
            }
        }

        if let Some(parent) = dest.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        entry.unpack(&dest).map_err(|e| ExecError::Extraction {
            pkg: pkg_name.clone(),
            message: format!("{}: {e}", dest.display()),
        })?;
    }

    Ok(PackageMetadata {
        pkginfo,
        mtree,
        install,
        files,
        backup: backup_entries,
    })
}

fn decompress(file: std::fs::File, filename: &str) -> Result<Box<dyn Read>> {
    if filename.ends_with(".zst") {
        let dec = zstd::Decoder::new(file).map_err(|e| ExecError::Extraction {
            pkg: filename.to_string(),
            message: format!("zstd: {e}"),
        })?;
        Ok(Box::new(dec))
    } else if filename.ends_with(".xz") {
        let dec = xz2::read::XzDecoder::new(file);
        Ok(Box::new(dec))
    } else if filename.ends_with(".gz") {
        let dec = flate2::read::GzDecoder::new(file);
        Ok(Box::new(dec))
    } else {
        Ok(Box::new(file))
    }
}

fn parse_backup_from_pkginfo(pkginfo: &str) -> Vec<String> {
    pkginfo
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix("backup = ").map(|v| v.to_string())
        })
        .collect()
}

fn compute_md5(path: &Path) -> Result<String> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(format!("{:x}", md5::compute(&buf)))
}

pub struct PkgFileInfo {
    pub name: String,
    pub version: String,
    pub installed_size: u64,
}

pub fn read_pkginfo(pkg_path: &Path) -> Result<PkgFileInfo> {
    let filename = pkg_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let file = std::fs::File::open(pkg_path)?;
    let decompressor = decompress(file, &filename)?;
    let mut archive = Archive::new(decompressor);

    let mut pkginfo = String::new();

    for entry_result in archive.entries().map_err(|e| ExecError::Extraction {
        pkg: filename.clone(),
        message: e.to_string(),
    })? {
        let mut entry = entry_result.map_err(|e| ExecError::Extraction {
            pkg: filename.clone(),
            message: e.to_string(),
        })?;

        let path = entry.path().map_err(|e| ExecError::Extraction {
            pkg: filename.clone(),
            message: e.to_string(),
        })?;
        let path_str = path.to_string_lossy();
        let path_str = path_str.strip_prefix("./").unwrap_or(&path_str);

        if path_str == ".PKGINFO" {
            entry.read_to_string(&mut pkginfo).map_err(|e| ExecError::Extraction {
                pkg: filename.clone(),
                message: format!(".PKGINFO: {e}"),
            })?;
            break;
        }
    }

    if pkginfo.is_empty() {
        return Err(ExecError::Extraction {
            pkg: filename,
            message: "missing .PKGINFO".to_string(),
        });
    }

    let name = pkginfo
        .lines()
        .find_map(|l| l.strip_prefix("pkgname = "))
        .ok_or_else(|| ExecError::Extraction {
            pkg: filename.clone(),
            message: "missing pkgname in .PKGINFO".to_string(),
        })?
        .to_string();

    let version = pkginfo
        .lines()
        .find_map(|l| l.strip_prefix("pkgver = "))
        .ok_or_else(|| ExecError::Extraction {
            pkg: filename.clone(),
            message: "missing pkgver in .PKGINFO".to_string(),
        })?
        .to_string();

    let installed_size = pkginfo
        .lines()
        .find_map(|l| l.strip_prefix("size = "))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    Ok(PkgFileInfo {
        name,
        version,
        installed_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_backup_from_pkginfo() {
        let pkginfo = r#"pkgname = nginx
pkgver = 1.30.4-1
backup = etc/nginx/nginx.conf
backup = etc/nginx/fastcgi.conf
depend = glibc
"#;
        let backups = parse_backup_from_pkginfo(pkginfo);
        assert_eq!(backups, vec!["etc/nginx/nginx.conf", "etc/nginx/fastcgi.conf"]);
    }
}
