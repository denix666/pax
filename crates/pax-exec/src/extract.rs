use std::collections::HashMap;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use pax_alpm::desc::{desc_to_package_info, generate_local_desc_from_pkginfo, parse_desc};
use pax_core::package::{InstallReason, PackageInfo};

use tar::Archive;

use crate::error::{ExecError, Result};

pub struct PackageMetadata {
    pub pkginfo: String,
    pub mtree: Vec<u8>,
    pub install: Option<String>,
    pub files: Vec<String>,
    pub backup: Vec<String>,
    /// MD5 of each backup's incoming archive contents, even when kept as .pacnew.
    pub backup_md5: HashMap<String, String>,
    pub warnings: Vec<String>,
}

pub fn extract_package(
    pkg_path: &Path,
    root_dir: &Path,
    existing_backup_md5: &HashMap<String, String>,
) -> Result<PackageMetadata> {
    validate_package_archive(pkg_path, root_dir)?;
    let pkg_name = pkg_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // First pass: read .PKGINFO to get backup entries before processing regular files
    let backup_entries: Vec<String> = {
        let file = std::fs::File::open(pkg_path)?;
        let decompressor = decompress(file, &pkg_name)?;
        let mut archive = Archive::new(decompressor);
        let mut pkginfo = String::new();
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
            let path_str = path_str.strip_prefix("./").unwrap_or(&path_str).to_string();
            if path_str == ".PKGINFO" {
                if !entry.header().entry_type().is_file() {
                    return Err(unsafe_path(&path));
                }
                entry
                    .read_to_string(&mut pkginfo)
                    .map_err(|e| ExecError::Extraction {
                        pkg: pkg_name.clone(),
                        message: format!(".PKGINFO: {e}"),
                    })?;
                break;
            }
        }
        let name = pkginfo
            .lines()
            .find_map(|line| line.strip_prefix("pkgname = "))
            .unwrap_or("");
        let version = pkginfo
            .lines()
            .find_map(|line| line.strip_prefix("pkgver = "))
            .unwrap_or("");
        validate_identity(name, version)?;
        parse_backup_from_pkginfo(&pkginfo)
    };

    // Second pass: extract everything
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
    let mut warnings: Vec<String> = Vec::new();
    let mut backup_md5 = HashMap::new();
    std::fs::create_dir_all(root_dir)?;
    let root_dir = root_dir.canonicalize()?;
    for backup in &backup_entries {
        safe_relative_path(Path::new(backup))?;
    }

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

        let path = safe_relative_path(&path)?;
        if path.as_os_str().is_empty() {
            continue;
        }
        let path_str = path.to_str().ok_or_else(|| unsafe_path(&path))?;

        if path_str.starts_with('.') {
            match path_str {
                ".PKGINFO" => {
                    if !pkginfo.is_empty() || !entry.header().entry_type().is_file() {
                        return Err(ExecError::Extraction {
                            pkg: pkg_name.clone(),
                            message: "duplicate or non-regular .PKGINFO".into(),
                        });
                    }
                    entry
                        .read_to_string(&mut pkginfo)
                        .map_err(|e| ExecError::Extraction {
                            pkg: pkg_name.clone(),
                            message: format!(".PKGINFO: {e}"),
                        })?;
                }
                ".MTREE" => {
                    entry
                        .read_to_end(&mut mtree)
                        .map_err(|e| ExecError::Extraction {
                            pkg: pkg_name.clone(),
                            message: format!(".MTREE: {e}"),
                        })?;
                }
                ".INSTALL" => {
                    let mut s = String::new();
                    entry
                        .read_to_string(&mut s)
                        .map_err(|e| ExecError::Extraction {
                            pkg: pkg_name.clone(),
                            message: format!(".INSTALL: {e}"),
                        })?;
                    install = Some(s);
                }
                _ => {}
            }
            continue;
        }

        files.push(if entry.header().entry_type().is_dir() {
            format!("{path_str}/")
        } else {
            path_str.to_string()
        });

        let dest = root_dir.join(&path);
        ensure_safe_parent(&root_dir, &path)?;
        let entry_type = entry.header().entry_type();
        if backup_entries.iter().any(|backup| backup == path_str) {
            if !entry_type.is_file() {
                return Err(unsafe_path(&path));
            }
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            let new_md5 = format!("{:x}", md5::compute(&buf));
            backup_md5.insert(path_str.to_string(), new_md5.clone());
            let current_md5 = match std::fs::symlink_metadata(&dest) {
                Ok(metadata) if metadata.is_file() => Some(compute_md5(&dest)?),
                Ok(_) => return Err(unsafe_path(&path)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            };
            if let Some(current) = current_md5.as_ref() {
                if current == &new_md5 {
                    continue;
                }
                if let Some(old) = existing_backup_md5.get(path_str) {
                    if old == &new_md5 {
                        continue;
                    }
                }
            }
            let should_pacnew = current_md5
                .as_ref()
                .is_some_and(|current| existing_backup_md5.get(path_str) != Some(current));
            let output = if should_pacnew {
                dest.with_file_name(format!(
                    "{}.pacnew",
                    dest.file_name().unwrap().to_string_lossy()
                ))
            } else {
                dest.clone()
            };
            write_backup(&output, &buf, entry.header().mode()?)?;
            if should_pacnew {
                warnings.push(format!("{path_str} installed as {path_str}.pacnew"));
            }
            continue;
        }

        if entry_type.is_hard_link() {
            let target = entry.link_name()?.ok_or_else(|| unsafe_path(&path))?;
            let target = safe_relative_path(&target)?;
            if target.as_os_str().is_empty() {
                return Err(unsafe_path(&path));
            }

            ensure_safe_parent(&root_dir, &target)?;
            let source = root_dir.join(&target);
            match std::fs::symlink_metadata(&source) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink()
                        && !source.canonicalize()?.starts_with(&root_dir)
                    {
                        return Err(unsafe_path(&target));
                    }
                    if entry_type.is_hard_link() && !metadata.is_file() {
                        return Err(unsafe_path(&target));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        } else if !entry_type.is_file() && !entry_type.is_dir() && !entry_type.is_symlink() {
            return Err(unsafe_path(&path));
        }

        if entry_type.is_file() || entry_type.is_hard_link() {
            // Unlink first: an existing hard link may refer to data outside the root.
            match std::fs::symlink_metadata(&dest) {
                Ok(metadata) if !metadata.is_dir() => std::fs::remove_file(&dest)?,
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        // Replace only empty directories; never recursively delete user data.
        match std::fs::symlink_metadata(&dest) {
            Ok(metadata) if metadata.is_dir() && !entry_type.is_dir() => {
                std::fs::remove_dir(&dest)?;
            }
            Ok(metadata) if metadata.file_type().is_symlink() && !entry_type.is_dir() => {
                std::fs::remove_file(&dest)?;
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if entry_type.is_symlink() {
            // Link text is package data. Absolute links refer to the installed root;
            // only operations traversing a link need containment checks.
            let target = entry.link_name()?.ok_or_else(|| unsafe_path(&path))?;
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::os::unix::fs::symlink(target, &dest)?;
        } else if !entry.unpack_in(&root_dir)? {
            return Err(unsafe_path(&path));
        }
    }

    for backup in &backup_entries {
        if !backup_md5.contains_key(backup) {
            return Err(ExecError::Extraction {
                pkg: pkg_name.clone(),
                message: format!("backup missing from archive: {backup}"),
            });
        }
    }
    Ok(PackageMetadata {
        pkginfo,
        mtree,
        install,
        files,
        backup: backup_entries,
        backup_md5,
        warnings,
    })
}

/// Inspect every member without creating files or directories. Incoming symlinks
/// are tracked in archive order so later members cannot write through escaping links.
pub fn validate_package_archive(pkg_path: &Path, root_dir: &Path) -> Result<()> {
    let filename = pkg_path.file_name().unwrap_or_default().to_string_lossy();
    let mut archive = Archive::new(decompress(std::fs::File::open(pkg_path)?, &filename)?);
    let root = validation_root(root_dir)?;
    let mut overlays: HashMap<PathBuf, Option<PathBuf>> = HashMap::new();
    let mut pkginfo = None;
    let mut regular_files = std::collections::HashSet::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = safe_relative_path(&entry.path()?)?;
        let kind = entry.header().entry_type();
        if !kind.is_file() && !kind.is_dir() && !kind.is_symlink() && !kind.is_hard_link() {
            return Err(unsafe_path(&path));
        }
        if path.as_os_str().is_empty() {
            if kind.is_dir() {
                continue;
            }
            return Err(unsafe_path(&path));
        }
        let name = path.to_str().ok_or_else(|| unsafe_path(&path))?;
        entry.header().mode()?;
        if kind.is_dir() {
            resolve_archive_parent(&root, &path.join(".pax-validation"), &overlays)?;
        }
        let parent = resolve_archive_parent(&root, &path, &overlays)?;
        let destination = parent.join(path.file_name().ok_or_else(|| unsafe_path(&path))?);
        let target = if kind.is_symlink() || kind.is_hard_link() {
            let target = entry
                .link_name()?
                .ok_or_else(|| unsafe_path(&path))?
                .into_owned();
            if target.as_os_str().is_empty() {
                return Err(unsafe_path(&path));
            }
            if kind.is_hard_link() {
                let target = safe_relative_path(&target)?;
                if target.as_os_str().is_empty() {
                    return Err(unsafe_path(&path));
                }
                let parent = resolve_archive_parent(&root, &target, &overlays)?;
                let source = parent.join(target.file_name().ok_or_else(|| unsafe_path(&target))?);
                if matches!(overlays.get(&source), Some(Some(_))) {
                    return Err(unsafe_path(&target));
                }
                if !overlays.contains_key(&source) {
                    match std::fs::symlink_metadata(root.join(&source)) {
                        Ok(metadata) if !metadata.is_file() => return Err(unsafe_path(&target)),
                        Ok(_) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            Some(target)
        } else {
            None
        };
        if name.starts_with('.') {
            if !kind.is_file() {
                return Err(unsafe_path(&path));
            }
            if name == ".PKGINFO" {
                if pkginfo.is_some() {
                    return Err(unsafe_path(&path));
                }
                let mut text = String::new();
                entry.read_to_string(&mut text)?;
                pkginfo = Some(text);
            }
        } else {
            if kind.is_file() {
                regular_files.insert(path.clone());
            }
            // Directory entries preserve existing directory symlinks, so keep
            // their resolution visible to subsequent members.
            if !kind.is_dir() {
                overlays.insert(destination, if kind.is_symlink() { target } else { None });
            }
        }
        // Read every payload, including the final one, to detect truncated archives.
        std::io::copy(&mut entry, &mut std::io::sink())?;
    }
    let pkginfo = pkginfo.ok_or_else(|| ExecError::Extraction {
        pkg: filename.to_string(),
        message: "missing .PKGINFO".into(),
    })?;
    let name = pkginfo
        .lines()
        .find_map(|line| line.strip_prefix("pkgname = "))
        .unwrap_or("");
    let version = pkginfo
        .lines()
        .find_map(|line| line.strip_prefix("pkgver = "))
        .unwrap_or("");
    validate_identity(name, version)?;
    for backup in parse_backup_from_pkginfo(&pkginfo) {
        let path = safe_relative_path(Path::new(&backup))?;
        if !regular_files.contains(&path) {
            return Err(unsafe_path(&path));
        }
        ensure_safe_parent_for_validation(&root, &path)?;
        match std::fs::symlink_metadata(root.join(&path)) {
            Ok(metadata) if !metadata.is_file() => return Err(unsafe_path(&path)),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

// Canonicalize the existing prefix without creating a missing installation root.
fn validation_root(root: &Path) -> Result<PathBuf> {
    match root.canonicalize() {
        Ok(root) => Ok(root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let absolute = if root.is_absolute() {
                root.to_path_buf()
            } else {
                std::env::current_dir()?.join(root)
            };
            let parent = absolute.parent().ok_or_else(|| unsafe_path(root))?;
            Ok(validation_root(parent)?
                .join(absolute.file_name().ok_or_else(|| unsafe_path(root))?))
        }
        Err(error) => Err(error.into()),
    }
}

fn ensure_safe_parent_for_validation(root: &Path, path: &Path) -> Result<()> {
    resolve_archive_parent(root, path, &HashMap::new()).map(|_| ())
}

fn resolve_archive_parent(
    root: &Path,
    path: &Path,
    overlays: &HashMap<PathBuf, Option<PathBuf>>,
) -> Result<PathBuf> {
    use std::collections::VecDeque;
    let mut pending: VecDeque<_> = path
        .parent()
        .unwrap_or(Path::new(""))
        .components()
        .map(|part| part.as_os_str().to_os_string())
        .collect();
    let mut resolved = PathBuf::new();
    let mut followed = 0;
    while let Some(part) = pending.pop_front() {
        if part == "." {
            continue;
        }
        if part == ".." {
            if !resolved.pop() {
                return Err(unsafe_path(path));
            }
            continue;
        }
        let candidate = resolved.join(&part);
        let link = match overlays.get(&candidate) {
            Some(link) => link.clone(),
            None => match std::fs::read_link(root.join(&candidate)) {
                Ok(target) if target.is_absolute() => Some(
                    target
                        .strip_prefix(root)
                        .map_err(|_| unsafe_path(path))?
                        .to_path_buf(),
                )
                .map(|target| {
                    resolved.clear();
                    target
                }),
                Ok(target) => Some(target),
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        || error.kind() == std::io::ErrorKind::InvalidInput =>
                {
                    None
                }
                Err(error) => return Err(error.into()),
            },
        };
        if let Some(target) = link {
            // Absolute incoming links are valid to install, but the host must never
            // dereference them while writing into an alternate root.
            if target.is_absolute() {
                return Err(unsafe_path(path));
            }
            followed += 1;
            if followed > 40 {
                return Err(unsafe_path(path));
            }
            for component in target.components().rev() {
                pending.push_front(component.as_os_str().to_os_string());
            }
        } else {
            resolved.push(part);
        }
    }
    Ok(resolved)
}

fn unsafe_path(path: &Path) -> ExecError {
    ExecError::Extraction {
        pkg: String::new(),
        message: format!("unsafe package path: {}", path.display()),
    }
}

pub(crate) fn safe_relative_path(path: &Path) -> Result<PathBuf> {
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::CurDir => {}
            _ => return Err(unsafe_path(path)),
        }
    }
    Ok(relative)
}

/// Check existing parents before any filesystem operation, including backup writes.
/// Internal symlinks such as lib -> usr/lib are permitted.
pub(crate) fn ensure_safe_parent(root: &Path, relative: &Path) -> Result<()> {
    let root = root.canonicalize()?;
    let mut parent = root.clone();
    if let Some(components) = relative.parent() {
        for component in components.components() {
            parent.push(component);
            match std::fs::symlink_metadata(&parent) {
                Ok(_) => {
                    if !parent.canonicalize()?.starts_with(&root) {
                        return Err(unsafe_path(relative));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_identity(name: &str, version: &str) -> Result<()> {
    for value in [name, version] {
        if value.is_empty()
            || value == "."
            || value == ".."
            || value.contains('/')
            || value.contains('\\')
            || value.chars().any(char::is_control)
        {
            return Err(unsafe_path(Path::new(value)));
        }
    }
    Ok(())
}

fn write_backup(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let parent = path.parent().ok_or_else(|| unsafe_path(path))?;
    std::fs::create_dir_all(parent)?;
    // Rename a fresh inode so existing symlinks and hard links cannot redirect writes.
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(data)?;
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    temporary
        .persist(path)
        .map_err(|error| ExecError::Io(error.error))?;
    Ok(())
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
            line.strip_prefix("backup = ")
                .map(|v| v.strip_prefix("./").unwrap_or(v).to_string())
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

pub fn read_archive_file_list(pkg_path: &Path) -> Result<Vec<String>> {
    let filename = pkg_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let file = std::fs::File::open(pkg_path)?;
    let decompressor = decompress(file, &filename)?;
    let mut archive = Archive::new(decompressor);

    let mut files = Vec::new();

    for entry_result in archive.entries().map_err(|e| ExecError::Extraction {
        pkg: filename.clone(),
        message: e.to_string(),
    })? {
        let entry = entry_result.map_err(|e| ExecError::Extraction {
            pkg: filename.clone(),
            message: e.to_string(),
        })?;

        let path = entry.path().map_err(|e| ExecError::Extraction {
            pkg: filename.clone(),
            message: e.to_string(),
        })?;
        let path = safe_relative_path(&path)?;
        let path_str = path.to_str().ok_or_else(|| unsafe_path(&path))?;

        if path_str.is_empty() || path_str.starts_with('.') {
            continue;
        }

        files.push(if entry.header().entry_type().is_dir() {
            format!("{}/", path_str.trim_end_matches('/'))
        } else {
            path_str.to_string()
        });
    }

    Ok(files)
}

pub struct PkgFileInfo {
    pub info: PackageInfo,
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
            entry
                .read_to_string(&mut pkginfo)
                .map_err(|e| ExecError::Extraction {
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

    validate_identity(&name, &version)?;
    let desc =
        generate_local_desc_from_pkginfo(&pkginfo, installed_size, 0, InstallReason::Explicit, &[]);
    let info = desc_to_package_info(&parse_desc(&desc))?;
    Ok(PkgFileInfo {
        info,
        name,
        version,
        installed_size,
    })
}

pub fn read_install_script(pkg_path: &Path) -> Result<Option<String>> {
    let filename = pkg_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let file = std::fs::File::open(pkg_path)?;
    let decompressor = decompress(file, &filename)?;
    let mut archive = Archive::new(decompressor);

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

        if path_str == ".INSTALL" {
            let mut s = String::new();
            entry
                .read_to_string(&mut s)
                .map_err(|e| ExecError::Extraction {
                    pkg: filename.clone(),
                    message: format!(".INSTALL: {e}"),
                })?;
            return Ok(Some(s));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(dir: &Path, contents: &[u8], link: Option<(&str, &str, tar::EntryType)>) -> PathBuf {
        let archive = dir.join("test.pkg.tar");
        let mut builder = tar::Builder::new(std::fs::File::create(&archive).unwrap());
        let pkginfo = b"pkgname = test\npkgver = 1-1\narch = any\nbackup = etc/config\ndepend = libc>=1\noptdepend = tool: optional tool\nprovides = virtual=1\nconflict = other\nreplaces = obsolete\n";
        for (path, data) in [(".PKGINFO", pkginfo.as_slice()), ("etc/config", contents)] {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, data).unwrap();
        }
        if let Some((path, target, kind)) = link {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_size(0);
            header.set_mode(0o777);
            builder.append_link(&mut header, path, target).unwrap();
        }
        builder.finish().unwrap();
        archive
    }

    #[test]
    fn backup_three_way_and_archive_baseline() {
        for (old, current, incoming, pacnew, expected) in [
            ("old", "old", "new", false, "new"),
            ("old", "edited", "new", true, "edited"),
            ("old", "new", "new", false, "new"),
            ("old", "edited", "old", false, "edited"),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            std::fs::create_dir_all(root.join("etc")).unwrap();
            std::fs::write(root.join("etc/config"), current).unwrap();
            let archive = package(temp.path(), incoming.as_bytes(), None);
            let old = HashMap::from([("etc/config".into(), format!("{:x}", md5::compute(old)))]);
            let metadata = extract_package(&archive, &root, &old).unwrap();
            assert_eq!(
                std::fs::read_to_string(root.join("etc/config")).unwrap(),
                expected
            );
            assert_eq!(root.join("etc/config.pacnew").exists(), pacnew);
            assert_eq!(
                metadata.backup_md5["etc/config"],
                format!("{:x}", md5::compute(incoming))
            );
        }
    }

    #[test]
    fn package_info_includes_dependency_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let archive = package(temp.path(), b"new", None);
        let pkg = read_pkginfo(&archive).unwrap();
        assert_eq!(pkg.info.name, pkg.name);
        assert_eq!(pkg.info.version.to_string(), pkg.version);
        assert_eq!(pkg.info.depends.len(), 1);
        assert_eq!(pkg.info.optdepends.len(), 1);
        assert_eq!(pkg.info.provides.len(), 1);
        assert_eq!(pkg.info.conflicts.len(), 1);
        assert_eq!(pkg.info.replaces.len(), 1);
    }

    #[test]
    fn rejects_escaping_paths_and_links() {
        assert!(safe_relative_path(Path::new("/etc/config")).is_err());
        assert!(safe_relative_path(Path::new("etc/../config")).is_err());
        for kind in [tar::EntryType::Link] {
            for target in ["../outside", "/outside"] {
                let temp = tempfile::tempdir().unwrap();
                let archive = package(temp.path(), b"new", Some(("link", target, kind)));
                assert!(
                    extract_package(&archive, &temp.path().join("root"), &HashMap::new()).is_err()
                );
            }
        }
    }

    #[test]
    fn normal_parent_relative_and_absolute_symlinks_are_preserved() {
        for target in ["../lib/libexample.so.1", "/usr/lib/libexample.so.1"] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let archive = package(
                temp.path(),
                b"new",
                Some(("usr/lib64/libexample.so", target, tar::EntryType::Symlink)),
            );
            validate_package_archive(&archive, &root).unwrap();
            assert!(!root.exists(), "preflight must not create the root");
            extract_package(&archive, &root, &HashMap::new()).unwrap();
            assert_eq!(
                std::fs::read_link(root.join("usr/lib64/libexample.so")).unwrap(),
                Path::new(target)
            );
        }
    }

    fn overlay_package(dir: &Path, target: &str) -> PathBuf {
        let archive = dir.join("overlay.pkg.tar");
        let mut builder = tar::Builder::new(std::fs::File::create(&archive).unwrap());
        let mut header = tar::Header::new_gnu();
        let pkginfo = b"pkgname = overlay\npkgver = 1-1\n";
        header.set_mode(0o644);
        header.set_size(pkginfo.len() as u64);
        builder
            .append_data(&mut header, ".PKGINFO", pkginfo.as_slice())
            .unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_mode(0o777);
        header.set_size(0);
        builder
            .append_link(&mut header, "usr/link", target)
            .unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(7);
        builder
            .append_data(&mut header, "usr/link/file", b"payload".as_slice())
            .unwrap();
        builder.finish().unwrap();
        archive
    }

    #[test]
    fn incoming_symlink_cannot_redirect_later_archive_writes() {
        for target in ["../../outside", "/tmp", "../alias"] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            std::fs::create_dir(&root).unwrap();
            // Also exercise a link chain through an existing escaping symlink.
            std::os::unix::fs::symlink(temp.path().join("outside"), root.join("alias")).unwrap();
            let archive = overlay_package(temp.path(), target);
            assert!(validate_package_archive(&archive, &root).is_err());
            assert!(!root.join("usr").exists());
            assert!(extract_package(&archive, &root, &HashMap::new()).is_err());
            assert!(!root.join("usr").exists());
        }
    }

    #[test]
    fn incoming_parent_relative_link_can_resolve_within_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("lib")).unwrap();
        let archive = overlay_package(temp.path(), "../lib");
        validate_package_archive(&archive, &root).unwrap();
        assert!(!root.join("usr").exists());
        extract_package(&archive, &root, &HashMap::new()).unwrap();
        assert_eq!(std::fs::read(root.join("lib/file")).unwrap(), b"payload");
    }

    #[test]
    fn escaping_parent_and_backup_symlinks_cannot_write_outside_root() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("config"), "protected").unwrap();
        symlink(&outside, root.join("etc")).unwrap();
        let archive = package(temp.path(), b"new", None);
        assert!(extract_package(&archive, &root, &HashMap::new()).is_err());
        assert_eq!(
            std::fs::read_to_string(outside.join("config")).unwrap(),
            "protected"
        );
        std::fs::remove_file(root.join("etc")).unwrap();
        std::fs::create_dir(root.join("etc")).unwrap();
        symlink(outside.join("config"), root.join("etc/config")).unwrap();
        assert!(extract_package(&archive, &root, &HashMap::new()).is_err());
        assert_eq!(
            std::fs::read_to_string(outside.join("config")).unwrap(),
            "protected"
        );
    }

    #[test]
    fn directory_replaced_by_symlink_preserves_contents() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("data")).unwrap();
        std::fs::write(root.join("data/user-file"), "keep").unwrap();
        let archive = package(
            temp.path(),
            b"new",
            Some(("data", "other", tar::EntryType::Symlink)),
        );
        assert!(extract_package(&archive, &root, &HashMap::new()).is_err());
        assert_eq!(
            std::fs::read_to_string(root.join("data/user-file")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn test_parse_backup_from_pkginfo() {
        let pkginfo = r#"pkgname = nginx
pkgver = 1.30.4-1
backup = etc/nginx/nginx.conf
backup = etc/nginx/fastcgi.conf
depend = glibc
"#;
        let backups = parse_backup_from_pkginfo(pkginfo);
        assert_eq!(
            backups,
            vec!["etc/nginx/nginx.conf", "etc/nginx/fastcgi.conf"]
        );
    }
}
