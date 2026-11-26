use std::collections::HashMap;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use pax_alpm::desc::{desc_to_package_info, generate_local_desc_from_pkginfo, parse_desc};
use pax_core::package::{InstallReason, PackageInfo};

use tar::Archive;

use crate::error::{ExecError, Result};

pub(crate) const PKGINFO_LIMIT: u64 = 4 * 1024 * 1024;

fn read_pkginfo_text<R: Read>(entry: &mut tar::Entry<'_, R>, archive: &Path) -> Result<String> {
    let size = entry.size();
    let invalid = |message: String| ExecError::Extraction {
        pkg: archive.display().to_string(),
        message: format!(".PKGINFO: {message}"),
    };
    if !entry.header().entry_type().is_file() || size > PKGINFO_LIMIT {
        return Err(invalid(
            "expected a regular metadata entry of at most 4 MiB".into(),
        ));
    }
    let mut contents = String::new();
    entry
        .take(PKGINFO_LIMIT + 1)
        .read_to_string(&mut contents)
        .map_err(|error| invalid(format!("read bounded metadata: {error}")))?;
    if contents.len() as u64 != size || contents.len() as u64 > PKGINFO_LIMIT {
        return Err(invalid(format!(
            "metadata length mismatch: declared {size}, read {}",
            contents.len()
        )));
    }
    Ok(contents)
}

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
    let directory_replacements = validate_package_archive_inner(pkg_path, root_dir)?;

    let pkg_name = pkg_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // First pass: read .PKGINFO to get backup entries before processing regular files
    let first_pkginfo = {
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
                pkginfo = read_pkginfo_text(&mut entry, pkg_path)?;
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
        pkginfo
    };
    let backup_entries = parse_backup_from_pkginfo(&first_pkginfo);

    // Second pass: extract everything
    let file = std::fs::File::open(pkg_path)?;
    let decompressor = decompress(file, &pkg_name)?;
    let mut archive = Archive::new(decompressor);
    // Apply metadata below: tar rejects blank IDs and must not set capabilities
    // or set-ID bits before our numeric ownership change.
    archive.set_preserve_permissions(false);
    archive.set_preserve_ownerships(false);
    archive.set_preserve_mtime(false);
    archive.set_unpack_xattrs(false);

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
                    pkginfo = read_pkginfo_text(&mut entry, pkg_path)?;
                    if pkginfo != first_pkginfo {
                        return Err(ExecError::Extraction {
                            pkg: pkg_name.clone(),
                            message: ".PKGINFO changed between extraction passes".into(),
                        });
                    }
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

        let mut operation = "check destination parent";
        (|| -> Result<()> {
            let dest = root_dir.join(&path);
            ensure_safe_parent(&root_dir, &path)?;
            let entry_type = entry.header().entry_type();
            if backup_entries.iter().any(|backup| backup == path_str) {
                if !entry_type.is_file() {
                    return Err(unsafe_path(&path));
                }
                operation = "stage backup payload";
                let parent = dest.parent().ok_or_else(|| unsafe_path(&path))?;
                std::fs::create_dir_all(parent)?;
                // Keep the incoming inode private even after assigning package ownership.
                // Stage on the destination filesystem so publication is an atomic rename.
                let private = tempfile::Builder::new()
                    .prefix(".pax-backup-")
                    .permissions(std::fs::Permissions::from_mode(0o700))
                    .tempdir_in(parent)?;
                let mut temporary = tempfile::NamedTempFile::new_in(private.path())?;
                let size = entry.size();
                if std::io::copy(&mut entry, &mut temporary)? != size {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated backup payload",
                    )
                    .into());
                }
                let new_md5 = compute_md5(temporary.path())?;
                backup_md5.insert(path_str.to_string(), new_md5.clone());
                operation = "inspect existing backup";
                let current_md5 = match std::fs::symlink_metadata(&dest) {
                    Ok(metadata) if metadata.is_file() => Some(compute_md5(&dest)?),
                    Ok(_) => return Err(unsafe_path(&path)),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error.into()),
                };
                if current_md5.as_ref().is_some_and(|current| {
                    current != &new_md5 && existing_backup_md5.get(path_str) == Some(&new_md5)
                }) {
                    return Ok(());
                }
                // C == N converges to the archive inode and metadata, even if O differs.
                let should_pacnew = current_md5.as_ref().is_some_and(|current| {
                    current != &new_md5 && existing_backup_md5.get(path_str) != Some(current)
                });
                let output = if should_pacnew {
                    dest.with_file_name(format!(
                        "{}.pacnew",
                        dest.file_name().unwrap().to_string_lossy()
                    ))
                } else {
                    dest.clone()
                };
                operation = "write backup payload (or .pacnew)";
                ensure_safe_parent(&root_dir, &path)?;
                write_backup(&output, temporary, &mut entry)?;
                if should_pacnew {
                    warnings.push(format!("{path_str} installed as {path_str}.pacnew"));
                }
                return Ok(());
            }

            operation = "validate payload type and hard link target";
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

            operation = "inspect destination";
            if entry_type.is_file() || entry_type.is_hard_link() || entry_type.is_symlink() {
                // Unlink first: existing files and links must be replaced, not followed.
                match std::fs::symlink_metadata(&dest) {
                    Ok(metadata) if !metadata.is_dir() => {
                        operation = "unlink existing destination";
                        std::fs::remove_file(&dest)?;
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            // Replace only empty directories; never recursively delete user data.
            operation = "inspect destination";
            match std::fs::symlink_metadata(&dest) {
                Ok(metadata) if metadata.is_dir() && entry_type.is_dir() => {
                    // Existing directory metadata belongs to the live system. Skip
                    // tar as well: it chmods existing directories during unpack.
                    return Ok(());
                }
                Ok(metadata) if metadata.is_dir() => {
                    operation = "remove empty destination directory";
                    std::fs::remove_dir(&dest)?;
                }
                Ok(metadata) if entry_type.is_dir() && metadata.file_type().is_symlink() => {
                    let parent = dest
                        .parent()
                        .ok_or_else(|| unsafe_path(&path))?
                        .canonicalize()?;
                    let resolved = parent.join(dest.file_name().ok_or_else(|| unsafe_path(&path))?);
                    let relative = resolved
                        .strip_prefix(&root_dir)
                        .map_err(|_| unsafe_path(&path))?;
                    if !directory_replacements.contains(relative) {
                        return Err(unsafe_path(&path));
                    }
                    // Unlink only the rechecked leaf. Its target is neither
                    // traversed nor deleted, including dangling/external targets.
                    operation = "unlink symlink for explicit directory entry";
                    std::fs::remove_file(&dest)?;
                    operation = "create replacement directory";
                    std::fs::create_dir(&dest)?;
                }
                Ok(_) if entry_type.is_dir() => {
                    return Err(std::io::Error::other(
                        "cannot replace an existing non-directory with a directory",
                    )
                    .into());
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            if entry_type.is_symlink() {
                // Link text is package data. Absolute links refer to the installed root;
                // only operations traversing a link need containment checks.
                operation = "read symlink target";
                let target = entry.link_name()?.ok_or_else(|| unsafe_path(&path))?;
                operation = "create symlink parent directories";
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                operation = "create symlink";
                std::os::unix::fs::symlink(target, &dest)?;
            } else {
                operation = "unpack payload";
                if !entry.unpack_in(&root_dir)? {
                    return Err(unsafe_path(&path));
                }
            }
            // Hardlinks share the live source inode, including a kept local config.
            if !entry_type.is_hard_link() {
                ensure_safe_parent(&root_dir, &path)?;
                operation = "set archive ownership";
                set_ownership(&dest, entry.header())?;
                if !entry_type.is_symlink() {
                    operation = "restore archive permissions";
                    std::fs::set_permissions(
                        &dest,
                        std::fs::Permissions::from_mode(entry.header().mode()?),
                    )?;
                }
                operation = "set archive extended attributes";
                unpack_xattrs(&dest, &mut entry)?;
                // Empty directories keep this timestamp; subsequent child creation
                // updates populated directories, matching pacman's entry-order behavior.
                operation = "set archive modification time";
                set_mtime(&dest, entry.header().mtime()?)?;
            }
            Ok(())
        })()
        .map_err(|error| ExecError::Extraction {
            pkg: pkg_name.clone(),
            message: format!("{}: {operation}: {error}", path.display()),
        })?;
    }

    if pkginfo != first_pkginfo {
        return Err(ExecError::Extraction {
            pkg: pkg_name,
            message: "missing or changed .PKGINFO after extraction".into(),
        });
    }

    // Some packages retain obsolete backup declarations in .PKGINFO. Only
    // archived backup files have a baseline and belong in the installed backup list.
    let backup_entries = backup_entries
        .into_iter()
        .filter(|path| backup_md5.contains_key(path))
        .collect();
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
    validate_package_archive_inner(pkg_path, root_dir).map(|_| ())
}

fn validate_package_archive_inner(
    pkg_path: &Path,
    root_dir: &Path,
) -> Result<std::collections::HashSet<PathBuf>> {
    let filename = pkg_path.file_name().unwrap_or_default().to_string_lossy();
    let mut archive = Archive::new(decompress(std::fs::File::open(pkg_path)?, &filename)?);
    let root = validation_root(root_dir)?;
    let mut overlays: HashMap<PathBuf, Option<PathBuf>> = HashMap::new();
    let mut pkginfo = None;
    let mut regular_files = std::collections::HashSet::new();
    let mut resolved_regular_files = std::collections::HashSet::new();
    let mut payload_paths = std::collections::HashSet::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = safe_relative_path(&entry.path()?)?;
        let kind = entry.header().entry_type();
        archive_ids(entry.header()).map_err(|error| ExecError::Extraction {
            pkg: pkg_path.display().to_string(),
            message: format!("{}: validate archive ownership: {error}", path.display()),
        })?;
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
        let parent = resolve_archive_parent(&root, &path, &overlays)?;
        let destination = parent.join(path.file_name().ok_or_else(|| unsafe_path(&path))?);
        if kind.is_dir() {
            match std::fs::symlink_metadata(root.join(&destination)) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    // Structural conversions need the full, archive-ordered view:
                    // validating descendants against the old link target is wrong.
                    return crate::preflight::inspect_archive(pkg_path, root_dir, None)
                        .map(|plan| plan.directory_replacements);
                }
                Ok(metadata) if !metadata.is_dir() => return Err(unsafe_path(&path)),
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            resolve_archive_parent(&root, &path.join(".pax-validation"), &overlays)?;
        }
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
                if source == destination || !resolved_regular_files.contains(&source) {
                    return Err(ExecError::Extraction {
                        pkg: pkg_path.display().to_string(),
                        message: format!(
                            "{}: hardlink source {} is not an earlier regular payload in this archive",
                            path.display(),
                            target.display()
                        ),
                    });
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
                pkginfo = Some(read_pkginfo_text(&mut entry, pkg_path)?);
            }
        } else {
            payload_paths.insert(path.clone());
            if kind.is_file() {
                regular_files.insert(path.clone());
                // The live inode may be a kept backup, but its archive entry
                // must still precede the hardlink in this same resolved namespace.
                resolved_regular_files.insert(destination.clone());
            } else {
                resolved_regular_files.remove(&destination);
            }
            // Existing symlink-to-directory conversions use Inspection above;
            // ordinary directory entries need no additional link overlay.
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
        if path.as_os_str().is_empty() {
            return Err(unsafe_path(&path));
        }
        if !payload_paths.contains(&path) {
            continue;
        }
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
    Ok(std::collections::HashSet::new())
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

fn write_backup<R: Read>(
    path: &Path,
    temporary: tempfile::NamedTempFile,
    entry: &mut tar::Entry<'_, R>,
) -> Result<()> {
    (|| -> Result<()> {
        // chown can clear set-ID bits and capabilities, so apply it before mode/xattrs.
        set_ownership(temporary.path(), entry.header())?;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(entry.header().mode()?))?;
        unpack_xattrs(temporary.path(), entry)?;
        set_mtime(temporary.path(), entry.header().mtime()?)?;
        // Replace the directory entry, never truncate a possibly hardlinked .pacnew.
        temporary
            .persist(path)
            .map_err(|error| ExecError::Io(error.error))?;
        Ok(())
    })()
    .map_err(|error| ExecError::Extraction {
        pkg: String::new(),
        message: format!(
            "{}: apply backup metadata and publish: {error}",
            path.display()
        ),
    })
}

pub(crate) fn archive_ids(header: &tar::Header) -> std::io::Result<(libc::uid_t, libc::gid_t)> {
    fn parse(raw: &[u8], parsed: std::io::Result<u64>, name: &str) -> std::io::Result<u32> {
        let padding = |byte: &u8| matches!(byte, 0 | b' ');
        // libarchive treats blank numeric owner fields as zero; tar's parser does not.
        let Some(first) = raw.iter().position(|byte| !padding(byte)) else {
            return Ok(0);
        };
        if raw[0] & 0x80 == 0 {
            let last = raw.iter().rposition(|byte| !padding(byte)).unwrap();
            if !raw[first..=last]
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'7'))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("malformed archive {name}"),
                ));
            }
        }
        let value = parsed?;
        // -1 means 'leave unchanged' to chown, not an archive owner to install.
        if value >= u32::MAX as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("archive {name} out of range: {value}"),
            ));
        }
        Ok(value as u32)
    }
    Ok((
        parse(&header.as_old().uid, header.uid(), "UID")?,
        parse(&header.as_old().gid, header.gid(), "GID")?,
    ))
}

fn set_ownership(path: &Path, header: &tar::Header) -> Result<()> {
    let (uid, gid) = archive_ids(header)?;
    if unsafe { libc::geteuid() } != 0 {
        // Low-level extraction also supports unprivileged callers; transactions require root.
        return Ok(());
    }
    let path =
        std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| unsafe_path(path))?;
    if unsafe { libc::lchown(path.as_ptr(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn set_mtime(path: &Path, seconds: u64) -> Result<()> {
    let seconds = libc::time_t::try_from(seconds).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("archive mtime out of range: {error}"),
        )
    })?;
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        },
    ];
    let path =
        std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| unsafe_path(path))?;
    if unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn unpack_xattrs<R: Read>(path: &Path, entry: &mut tar::Entry<'_, R>) -> Result<()> {
    let Some(extensions) = entry.pax_extensions()? else {
        return Ok(());
    };
    let c_path =
        std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| unsafe_path(path))?;
    for extension in extensions {
        let extension = extension?;
        // Match tar's existing regular-file xattr dialect; do not follow symlink targets.
        let Some(name) = extension.key_bytes().strip_prefix(b"SCHILY.xattr.") else {
            continue;
        };
        let name = std::ffi::CString::new(name).map_err(|_| unsafe_path(path))?;
        let value = extension.value_bytes();
        if unsafe {
            libc::lsetxattr(
                c_path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            return Err(std::io::Error::new(
                error.kind(),
                format!("{}: set xattr {:?}: {error}", path.display(), name),
            )
            .into());
        }
    }
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
    let mut file = std::fs::File::open(path)?;
    let mut digest = md5::Context::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let length = match file.read(&mut buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if length == 0 {
            return Ok(format!("{:x}", digest.finalize()));
        }
        digest.consume(&buffer[..length]);
    }
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
            pkginfo = read_pkginfo_text(&mut entry, pkg_path)?;
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
            header.set_uid(0);
            header.set_gid(0);
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, data).unwrap();
        }
        if let Some((path, target, kind)) = link {
            let mut header = tar::Header::new_gnu();
            header.set_uid(0);
            header.set_gid(0);
            header.set_entry_type(kind);
            header.set_size(0);
            header.set_mode(0o777);
            builder.append_link(&mut header, path, target).unwrap();
        }
        builder.finish().unwrap();
        archive
    }

    #[test]
    fn missing_backup_declaration_does_not_block_extraction_or_registration() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("mc.pkg.tar");
        let pkginfo = b"pkgname = mc\npkgver = 1-1\narch = any\nbackup = etc/mc/mc.ext\nbackup = etc/mc/mc.ext.ini\n";
        let mut builder = tar::Builder::new(std::fs::File::create(&archive).unwrap());
        for (path, data) in [
            (".PKGINFO", pkginfo.as_slice()),
            ("etc/mc/mc.ext.ini", b"new config".as_slice()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_uid(0);
            header.set_gid(0);
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, data).unwrap();
        }
        builder.finish().unwrap();
        drop(builder);
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("etc/mc")).unwrap();
        std::fs::write(root.join("etc/mc/mc.ext"), b"unowned config").unwrap();
        let metadata = extract_package(&archive, &root, &HashMap::new()).unwrap();
        assert_eq!(metadata.backup, ["etc/mc/mc.ext.ini"]);
        assert!(!metadata.backup_md5.contains_key("etc/mc/mc.ext"));
        assert_eq!(
            std::fs::read(root.join("etc/mc/mc.ext")).unwrap(),
            b"unowned config"
        );
        let db = temp.path().join("db");
        crate::register::register_package(&db, &metadata, InstallReason::Explicit, &[], &root)
            .unwrap();
        let files = std::fs::read_to_string(db.join("local/mc-1-1/files")).unwrap();
        assert!(files.contains(&format!(
            "etc/mc/mc.ext.ini\t{:x}",
            md5::compute(b"new config")
        )));
        assert!(
            !files
                .lines()
                .any(|line| line == "etc/mc/mc.ext" || line.starts_with("etc/mc/mc.ext\t"))
        );
    }

    #[test]
    fn real_mc_archive_extracts_when_provided() {
        let Some(path) = std::env::var_os("PAX_TEST_MC_ARCHIVE") else {
            return;
        };
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let metadata = extract_package(Path::new(&path), &root, &HashMap::new()).unwrap();
        assert!(root.join("etc/mc/mc.ext.ini").is_file());
        assert!(!root.join("etc/mc/mc.ext").exists());
        assert!(!metadata.backup.iter().any(|path| path == "etc/mc/mc.ext"));
        crate::register::register_package(
            &temp.path().join("db"),
            &metadata,
            InstallReason::Explicit,
            &[],
            &root,
        )
        .unwrap();
    }

    #[test]
    fn backup_three_way_and_archive_baseline() {
        for (old, current, incoming, pacnew, expected) in [
            (Some("old"), Some("old"), "new", false, "new"),
            (Some("old"), Some("edited"), "new", true, "edited"),
            (Some("old"), Some("new"), "new", false, "new"),
            (Some("old"), Some("edited"), "old", false, "edited"),
            (None, Some("edited"), "new", true, "edited"),
            (None, Some("new"), "new", false, "new"),
            (Some("new"), None, "new", false, "new"),
            (None, None, "new", false, "new"),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            std::fs::create_dir_all(root.join("etc")).unwrap();
            if let Some(current) = current {
                std::fs::write(root.join("etc/config"), current).unwrap();
            }
            let archive = package(temp.path(), incoming.as_bytes(), None);
            let old = old
                .map(|old| {
                    HashMap::from([("etc/config".into(), format!("{:x}", md5::compute(old)))])
                })
                .unwrap_or_default();
            let metadata = extract_package(&archive, &root, &old).unwrap();
            assert_eq!(
                std::fs::read_to_string(root.join("etc/config")).unwrap(),
                expected
            );
            assert_eq!(root.join("etc/config.pacnew").exists(), pacnew);
            if pacnew {
                assert_eq!(
                    std::fs::read_to_string(root.join("etc/config.pacnew")).unwrap(),
                    incoming
                );
                assert_eq!(
                    metadata.warnings,
                    ["etc/config installed as etc/config.pacnew"]
                );
            } else {
                assert!(metadata.warnings.is_empty());
            }
            assert_eq!(
                metadata.backup_md5["etc/config"],
                format!("{:x}", md5::compute(incoming))
            );
        }
    }

    #[test]
    fn hardlink_recheck_rejects_a_source_after_symlink_directory_conversion() {
        use std::os::unix::fs::{MetadataExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/config"), "untouched B destination").unwrap();
        symlink("etc", root.join("link")).unwrap();
        let archive = package(
            temp.path(),
            b"B-data",
            Some(("copy", "link/config", tar::EntryType::Link)),
        );
        crate::preflight::inspect_archive(&archive, &root, None).unwrap();
        validate_package_archive(&archive, &root).unwrap();

        // Model an earlier package changing the namespace between transaction
        // preflight and B's extraction-time validation.
        std::fs::remove_file(root.join("link")).unwrap();
        std::fs::create_dir(root.join("link")).unwrap();
        std::fs::write(root.join("link/config"), "A-data").unwrap();
        let before = std::fs::metadata(root.join("link/config")).unwrap();
        let error = extract_package(&archive, &root, &HashMap::new())
            .err()
            .unwrap();
        assert!(error.to_string().contains(
            "copy: hardlink source link/config is not an earlier regular payload in this archive"
        ), "{error}");
        assert_eq!(
            std::fs::read(root.join("etc/config")).unwrap(),
            b"untouched B destination"
        );
        assert_eq!(std::fs::read(root.join("link/config")).unwrap(), b"A-data");
        let after = std::fs::metadata(root.join("link/config")).unwrap();
        assert_eq!((before.ino(), before.nlink()), (after.ino(), after.nlink()));
        assert!(!root.join("copy").exists());
        assert!(!root.join("etc/config.pacnew").exists());
        assert_eq!(std::fs::read_dir(root.join("etc")).unwrap().count(), 1);
    }

    #[test]
    fn hardlinks_to_earlier_backups_keep_alias_resolution_and_local_inode() {
        use std::os::unix::fs::{MetadataExt, symlink};
        for source in ["etc/config", "alias/config"] {
            for old in ["original", "incoming"] {
                let temp = tempfile::tempdir().unwrap();
                let root = temp.path().join("root");
                std::fs::create_dir_all(root.join("etc")).unwrap();
                std::fs::write(root.join("etc/config"), "local changes").unwrap();
                symlink("etc", root.join("alias")).unwrap();
                let before = std::fs::metadata(root.join("etc/config")).unwrap();
                let archive = package(
                    temp.path(),
                    b"incoming",
                    Some(("copy", source, tar::EntryType::Link)),
                );
                crate::preflight::inspect_archive(&archive, &root, None).unwrap();
                let metadata = extract_package(
                    &archive,
                    &root,
                    &HashMap::from([("etc/config".into(), format!("{:x}", md5::compute(old)))]),
                )
                .unwrap();
                assert_eq!(std::fs::read(root.join("copy")).unwrap(), b"local changes");
                assert_eq!(
                    std::fs::read(root.join("etc/config")).unwrap(),
                    b"local changes"
                );
                assert_eq!(
                    std::fs::metadata(root.join("copy")).unwrap().ino(),
                    before.ino()
                );
                assert_eq!(
                    std::fs::metadata(root.join("etc/config")).unwrap().ino(),
                    before.ino()
                );
                assert_eq!(
                    metadata.backup_md5["etc/config"],
                    format!("{:x}", md5::compute("incoming"))
                );
                assert_eq!(root.join("etc/config.pacnew").exists(), old == "original");
                if old == "original" {
                    assert_eq!(
                        std::fs::read(root.join("etc/config.pacnew")).unwrap(),
                        b"incoming"
                    );
                }
                assert_eq!(
                    std::fs::read_link(root.join("alias")).unwrap(),
                    Path::new("etc")
                );
            }
        }
    }

    #[test]
    fn pacnew_replaces_links_without_changing_their_targets() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

        for hardlink in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            std::fs::create_dir_all(root.join("etc")).unwrap();
            let config = root.join("etc/config");
            let pacnew = root.join("etc/config.pacnew");
            let outside = temp.path().join("outside");
            std::fs::write(&config, b"local").unwrap();
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::write(&outside, b"untouched").unwrap();
            if hardlink {
                std::fs::hard_link(&config, &pacnew).unwrap();
            } else {
                symlink(&outside, &pacnew).unwrap();
            }
            let before = std::fs::metadata(&config).unwrap();
            let archive = package(temp.path(), b"incoming", None);
            let old = HashMap::from([("etc/config".into(), format!("{:x}", md5::compute(b"old")))]);
            let metadata = extract_package(&archive, &root, &old).unwrap();
            assert_eq!(std::fs::read(&config).unwrap(), b"local");
            assert_eq!(std::fs::read(&outside).unwrap(), b"untouched");
            assert!(std::fs::symlink_metadata(&pacnew).unwrap().is_file());
            assert_eq!(std::fs::read(&pacnew).unwrap(), b"incoming");
            let after = std::fs::metadata(&config).unwrap();
            assert_eq!(
                (after.ino(), after.mode(), after.mtime(), after.mtime_nsec()),
                (
                    before.ino(),
                    before.mode(),
                    before.mtime(),
                    before.mtime_nsec()
                )
            );
            assert_ne!(after.ino(), std::fs::metadata(&pacnew).unwrap().ino());
            assert_eq!(
                metadata.backup_md5["etc/config"],
                format!("{:x}", md5::compute(b"incoming"))
            );
            assert_eq!(
                metadata.warnings,
                ["etc/config installed as etc/config.pacnew"]
            );
            assert_eq!(std::fs::read_dir(root.join("etc")).unwrap().count(), 2);
        }
    }

    fn ownership_package(dir: &Path, uid: [u8; 8], gid: [u8; 8]) -> PathBuf {
        let archive = dir.join("ownership.pkg.tar");
        let mut builder = tar::Builder::new(std::fs::File::create(&archive).unwrap());
        let info = b"pkgname = ownership\npkgver = 1-1\narch = any\nbackup = opt/config\n";
        for (path, kind, contents) in [
            (".PKGINFO", tar::EntryType::Regular, info.as_slice()),
            ("earlier", tar::EntryType::Regular, b"replace".as_slice()),
            ("opt", tar::EntryType::Directory, b"".as_slice()),
            ("opt/file", tar::EntryType::Regular, b"payload".as_slice()),
            ("opt/config", tar::EntryType::Regular, b"config".as_slice()),
            ("opt/link", tar::EntryType::Symlink, b"".as_slice()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_mode(if kind.is_dir() { 0o755 } else { 0o644 });
            header.set_size(contents.len() as u64);
            if matches!(path, ".PKGINFO" | "earlier") {
                header.set_uid(0);
                header.set_gid(0);
            } else {
                header.as_old_mut().uid = uid;
                header.as_old_mut().gid = gid;
            }
            if kind.is_symlink() {
                builder.append_link(&mut header, path, "file").unwrap();
            } else {
                builder.append_data(&mut header, path, contents).unwrap();
            }
        }
        builder.finish().unwrap();
        archive
    }

    #[test]
    fn archive_ids_accept_blank_fields_and_validate_nonblank_numbers() {
        for blank in [[0; 8], [b' '; 8], [0, b' ', 0, b' ', 0, b' ', 0, b' ']] {
            let mut header = tar::Header::new_gnu();
            header.as_old_mut().uid = blank;
            header.as_old_mut().gid = blank;
            assert_eq!(archive_ids(&header).unwrap(), (0, 0));
        }
        let mut header = tar::Header::new_gnu();
        header.set_uid(65534);
        header.set_gid(3_000_000); // GNU base-256, not octal text.
        assert_eq!(archive_ids(&header).unwrap(), (65534, 3_000_000));
        for malformed in [*b"invalid!", *b"0000008\0", *b"0\0junk\0\0"] {
            header.as_old_mut().uid = malformed;
            assert!(
                archive_ids(&header)
                    .unwrap_err()
                    .to_string()
                    .contains("UID")
            );
            header.set_uid(0);
            header.as_old_mut().gid = malformed;
            assert!(
                archive_ids(&header)
                    .unwrap_err()
                    .to_string()
                    .contains("GID")
            );
            header.set_gid(0);
        }
        for value in [u32::MAX as u64, u32::MAX as u64 + 1] {
            header.set_uid(value);
            assert!(archive_ids(&header).is_err());
            header.set_uid(0);
            header.set_gid(value);
            assert!(archive_ids(&header).is_err());
            header.set_gid(0);
        }
    }

    #[test]
    fn malformed_archive_ids_are_rejected_before_payload_changes() {
        for (uid, gid, field) in [(*b"invalid!", [0; 8], "UID"), ([0; 8], *b"invalid!", "GID")] {
            let temp = tempfile::tempdir().unwrap();
            let archive = ownership_package(temp.path(), uid, gid);
            for existing in [false, true] {
                let root = temp
                    .path()
                    .join(if existing { "existing" } else { "missing" });
                if existing {
                    std::fs::create_dir(&root).unwrap();
                    std::fs::write(root.join("earlier"), b"keep").unwrap();
                }
                let error = crate::preflight::inspect_archive(&archive, &root, None)
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("opt") && error.contains(field), "{error}");
                let error = extract_package(&archive, &root, &HashMap::new())
                    .err()
                    .expect("malformed ownership must fail")
                    .to_string();
                assert!(error.contains("opt") && error.contains(field), "{error}");
                assert!(!root.join("opt").exists());
                if existing {
                    assert_eq!(std::fs::read(root.join("earlier")).unwrap(), b"keep");
                } else {
                    assert!(!root.exists());
                }
            }
        }
    }

    #[test]
    #[ignore = "requires root to verify blank archive ownership resolves to numeric zero"]
    fn root_blank_archive_ids_install_as_zero() {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(unsafe { libc::geteuid() }, 0, "run this regression as root");
        for blank in [[0; 8], [b' '; 8], [0, b' ', 0, b' ', 0, b' ', 0, b' ']] {
            let temp = tempfile::tempdir().unwrap();
            let archive = ownership_package(temp.path(), blank, blank);
            let root = temp.path().join("root");
            crate::preflight::inspect_archive(&archive, &root, None).unwrap();
            extract_package(&archive, &root, &HashMap::new()).unwrap();
            for path in ["opt", "opt/file", "opt/config", "opt/link"] {
                let metadata = std::fs::symlink_metadata(root.join(path)).unwrap();
                assert_eq!((metadata.uid(), metadata.gid()), (0, 0), "{path}");
            }
            assert_eq!(std::fs::read(root.join("opt/file")).unwrap(), b"payload");
            assert_eq!(std::fs::read(root.join("opt/config")).unwrap(), b"config");
            assert_eq!(
                std::fs::read_link(root.join("opt/link")).unwrap(),
                Path::new("file")
            );
        }
    }

    fn metadata_package(dir: &Path, target: &Path, mtime: u64) -> PathBuf {
        let archive = dir.join("metadata.pkg.tar");
        let mut builder = tar::Builder::new(std::fs::File::create(&archive).unwrap());
        let info = b"pkgname = metadata\npkgver = 1-1\narch = any\nbackup = etc/config\n";
        for (path, kind, contents) in [
            (".PKGINFO", tar::EntryType::Regular, info.as_slice()),
            ("empty", tar::EntryType::Directory, b"".as_slice()),
            ("etc", tar::EntryType::Directory, b"".as_slice()),
            (
                "etc/config",
                tar::EntryType::Regular,
                b"incoming".as_slice(),
            ),
            ("etc/config-copy", tar::EntryType::Link, b"".as_slice()),
            ("usr", tar::EntryType::Directory, b"".as_slice()),
            ("usr/file", tar::EntryType::Regular, b"payload".as_slice()),
            ("usr/link", tar::EntryType::Symlink, b"".as_slice()),
        ] {
            if kind.is_file() || kind.is_dir() {
                builder
                    .append_pax_extensions([(
                        "SCHILY.xattr.user.pax-metadata",
                        b"archive\0value".as_slice(),
                    )])
                    .unwrap();
            }
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_size(contents.len() as u64);
            header.set_uid(65534);
            header.set_gid(65533);
            header.set_mode(if kind.is_dir() { 0o2750 } else { 0o4640 });
            header.set_mtime(mtime);
            if kind.is_symlink() {
                builder.append_link(&mut header, path, target).unwrap();
            } else if kind.is_hard_link() {
                // A link must not apply its own metadata to the shared live config inode.
                header.set_uid(0);
                header.set_gid(0);
                header.set_mode(0o777);
                header.set_mtime(mtime + 1);
                builder
                    .append_link(&mut header, path, "etc/config")
                    .unwrap();
            } else {
                builder.append_data(&mut header, path, contents).unwrap();
            }
        }
        builder.finish().unwrap();
        archive
    }

    fn metadata_xattr(path: &Path) -> Vec<u8> {
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let mut value = vec![0; 64];
        let count = unsafe {
            libc::lgetxattr(
                path.as_ptr(),
                c"user.pax-metadata".as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        assert!(count >= 0, "{}", std::io::Error::last_os_error());
        value.truncate(count as usize);
        value
    }

    #[test]
    fn existing_directory_metadata_and_reinstallation_hardening_are_preserved() {
        use std::os::unix::fs::MetadataExt;

        for reinstall in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let archive = temp.path().join("directories.pkg.tar");
            let mut builder = tar::Builder::new(std::fs::File::create(&archive).unwrap());
            let info = b"pkgname = directories\npkgver = 1-1\narch = any\n";
            for (path, directory, data) in [
                (".PKGINFO", false, info.as_slice()),
                ("usr", true, b"".as_slice()),
                ("usr/file", false, b"payload".as_slice()),
                ("empty", true, b"".as_slice()),
                ("new", true, b"".as_slice()),
            ] {
                if directory {
                    builder
                        .append_pax_extensions([(
                            "SCHILY.xattr.user.pax-metadata",
                            b"archive".as_slice(),
                        )])
                        .unwrap();
                }
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(if directory {
                    tar::EntryType::Directory
                } else {
                    tar::EntryType::Regular
                });
                header.set_mode(if directory { 0o755 } else { 0o644 });
                header.set_uid(65534);
                header.set_gid(65533);
                header.set_mtime(0);
                header.set_size(data.len() as u64);
                builder.append_data(&mut header, path, data).unwrap();
            }
            builder.finish().unwrap();
            drop(builder);
            if reinstall {
                extract_package(&archive, &root, &HashMap::new()).unwrap();
            }
            let mut before = Vec::new();
            for path in ["usr", "empty"] {
                let full = root.join(path);
                std::fs::create_dir_all(&full).unwrap();
                std::fs::set_permissions(&full, std::fs::Permissions::from_mode(0o700)).unwrap();
                let c_path = std::ffi::CString::new(full.as_os_str().as_bytes()).unwrap();
                assert_eq!(
                    unsafe {
                        libc::lsetxattr(
                            c_path.as_ptr(),
                            c"user.pax-metadata".as_ptr(),
                            b"local".as_ptr().cast(),
                            5,
                            0,
                        )
                    },
                    0
                );
                set_mtime(&full, 123).unwrap();
                before.push((path, std::fs::symlink_metadata(&full).unwrap()));
            }
            std::fs::write(root.join("usr/file"), b"replace me").unwrap();
            let metadata = extract_package(&archive, &root, &HashMap::new()).unwrap();
            for (path, old) in before {
                let full = root.join(path);
                let current = std::fs::symlink_metadata(&full).unwrap();
                assert_eq!(
                    (current.ino(), current.uid(), current.gid(), current.mode()),
                    (old.ino(), old.uid(), old.gid(), old.mode()),
                    "{path}, reinstall={reinstall}"
                );
                assert_eq!(metadata_xattr(&full), b"local");
                if path == "empty" {
                    assert_eq!(
                        (current.mtime(), current.mtime_nsec()),
                        (old.mtime(), old.mtime_nsec())
                    );
                }
                assert!(metadata.files.contains(&format!("{path}/")));
            }
            let new = std::fs::symlink_metadata(root.join("new")).unwrap();
            assert_eq!((new.mode() & 0o7777, new.mtime()), (0o755, 0));
            assert_eq!(metadata_xattr(&root.join("new")), b"archive");
            assert_eq!(std::fs::read(root.join("usr/file")).unwrap(), b"payload");
        }
    }

    #[test]
    #[ignore = "requires root for archive numeric ownership and metadata"]
    fn root_archive_metadata_and_epoch_mtime() {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(unsafe { libc::geteuid() }, 0, "run this regression as root");
        for mtime in [0, 123456789] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            let outside = temp.path().join("outside");
            std::fs::write(&outside, b"untouched").unwrap();
            let before = std::fs::metadata(&outside).unwrap();
            // Include an existing directory as well as an archive-created directory.
            std::fs::create_dir_all(root.join("usr")).unwrap();
            let existing_usr = std::fs::symlink_metadata(root.join("usr")).unwrap();
            let archive = metadata_package(temp.path(), &outside, mtime);
            extract_package(&archive, &root, &HashMap::new()).unwrap();
            for path in ["etc", "usr", "empty", "usr/file", "etc/config", "usr/link"] {
                let full = root.join(path);
                let metadata = std::fs::symlink_metadata(&full).unwrap();
                if path == "usr" {
                    assert_eq!(
                        (metadata.uid(), metadata.gid(), metadata.mode()),
                        (existing_usr.uid(), existing_usr.gid(), existing_usr.mode())
                    );
                    assert_ne!((metadata.mtime(), metadata.mtime_nsec()), (mtime as i64, 0));
                    continue;
                }
                assert_eq!((metadata.uid(), metadata.gid()), (65534, 65533), "{path}");
                if path == "etc" {
                    assert_ne!(
                        (metadata.mtime(), metadata.mtime_nsec()),
                        (mtime as i64, 0),
                        "child creation must update {path} after its archive entry"
                    );
                } else {
                    assert_eq!(
                        (metadata.mtime(), metadata.mtime_nsec()),
                        (mtime as i64, 0),
                        "{path}"
                    );
                }
                if !metadata.is_symlink() {
                    assert_eq!(
                        metadata.mode() & 0o7777,
                        if metadata.is_dir() { 0o2750 } else { 0o4640 },
                        "{path}"
                    );
                    assert_eq!(metadata_xattr(&full), b"archive\0value", "{path}");
                }
            }
            assert_eq!(std::fs::read_link(root.join("usr/link")).unwrap(), outside);
            let after = std::fs::metadata(&outside).unwrap();
            assert_eq!(
                (
                    after.uid(),
                    after.gid(),
                    after.mode(),
                    after.mtime(),
                    after.mtime_nsec()
                ),
                (
                    before.uid(),
                    before.gid(),
                    before.mode(),
                    before.mtime(),
                    before.mtime_nsec()
                )
            );
            assert_eq!(std::fs::read(&outside).unwrap(), b"untouched");
            assert_eq!(
                std::fs::metadata(root.join("etc/config")).unwrap().ino(),
                std::fs::metadata(root.join("etc/config-copy"))
                    .unwrap()
                    .ino()
            );
            assert_eq!(std::fs::read_dir(root.join("etc")).unwrap().count(), 2);
        }
    }

    #[test]
    #[ignore = "requires root for config ownership, modes and extended attributes"]
    fn root_backup_metadata_and_original_hardlinks() {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(unsafe { libc::geteuid() }, 0, "run this regression as root");
        let hash = |data: &str| format!("{:x}", md5::compute(data));
        for (current, old, pacnew, replaced) in [
            ("old", Some(hash("old")), false, true),
            ("local", Some(hash("old")), true, false),
            ("local", Some(hash("incoming")), false, false),
            ("incoming", Some(hash("old")), false, true),
            ("local", None, true, false),
            ("local", Some(String::new()), true, false),
            ("local", Some("not-an-md5".into()), true, false),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            std::fs::create_dir_all(root.join("etc")).unwrap();
            let config = root.join("etc/config");
            let original = root.join("original-config");
            let sidecar = root.join("etc/config.pacnew");
            std::fs::write(&config, current).unwrap();
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
            set_mtime(&config, 123).unwrap();
            let c_config = std::ffi::CString::new(config.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe {
                    libc::lsetxattr(
                        c_config.as_ptr(),
                        c"user.pax-metadata".as_ptr(),
                        b"local".as_ptr().cast(),
                        5,
                        0,
                    )
                },
                0
            );
            std::fs::hard_link(&config, &original).unwrap();
            std::fs::hard_link(&config, &sidecar).unwrap();
            let before = std::fs::metadata(&config).unwrap();
            let archive = metadata_package(temp.path(), &original, 0);
            let old = old
                .map(|value| HashMap::from([("etc/config".into(), value)]))
                .unwrap_or_default();
            let metadata = extract_package(&archive, &root, &old).unwrap();
            assert_eq!(metadata.backup_md5["etc/config"], hash("incoming"));
            assert_eq!(std::fs::read_to_string(&original).unwrap(), current);
            let after = std::fs::metadata(&original).unwrap();
            assert_eq!(
                (
                    after.ino(),
                    after.uid(),
                    after.gid(),
                    after.mode(),
                    after.mtime()
                ),
                (
                    before.ino(),
                    before.uid(),
                    before.gid(),
                    before.mode(),
                    before.mtime()
                )
            );
            assert_eq!(metadata_xattr(&original), b"local");
            assert_eq!(
                std::fs::read_to_string(&config).unwrap(),
                if replaced { "incoming" } else { current }
            );
            if replaced || pacnew {
                let output = if pacnew { &sidecar } else { &config };
                let installed = std::fs::metadata(output).unwrap();
                assert_ne!(installed.ino(), before.ino());
                assert_eq!(
                    (
                        installed.uid(),
                        installed.gid(),
                        installed.mode() & 0o7777,
                        installed.mtime()
                    ),
                    (65534, 65533, 0o4640, 0)
                );
                assert_eq!(metadata_xattr(output), b"archive\0value");
                assert_eq!(std::fs::read(output).unwrap(), b"incoming");
            }
            if !pacnew {
                assert_eq!(std::fs::metadata(&sidecar).unwrap().ino(), before.ino());
            }
            if !replaced {
                assert_eq!(std::fs::metadata(&config).unwrap().ino(), before.ino());
                assert_eq!(metadata_xattr(&config), b"local");
            }
            assert_eq!(
                std::fs::metadata(root.join("etc/config-copy"))
                    .unwrap()
                    .ino(),
                std::fs::metadata(&config).unwrap().ino()
            );
            assert_eq!(std::fs::read_dir(root.join("etc")).unwrap().count(), 3);
        }
    }

    #[test]
    fn converged_backup_replaces_inode_and_restores_archive_metadata() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        let config = root.join("etc/config");
        let original = root.join("original");
        std::fs::write(&config, b"new").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        set_mtime(&config, 500).unwrap();
        std::fs::hard_link(&config, &original).unwrap();
        let before = std::fs::metadata(&config).unwrap();
        let archive = package(temp.path(), b"new", None);
        let old = HashMap::from([("etc/config".into(), format!("{:x}", md5::compute(b"old")))]);
        let metadata = extract_package(&archive, &root, &old).unwrap();
        let installed = std::fs::metadata(&config).unwrap();
        assert_ne!(installed.ino(), before.ino());
        assert_eq!(
            (
                installed.mtime(),
                installed.mtime_nsec(),
                installed.mode() & 0o7777
            ),
            (0, 0, 0o644)
        );
        let retained = std::fs::metadata(&original).unwrap();
        assert_eq!(
            (retained.ino(), retained.mtime(), retained.mode()),
            (before.ino(), before.mtime(), before.mode())
        );
        assert_eq!(std::fs::read(&config).unwrap(), b"new");
        assert_eq!(std::fs::read(&original).unwrap(), b"new");
        assert!(!root.join("etc/config.pacnew").exists());
        assert!(metadata.warnings.is_empty());
        assert_eq!(
            metadata.backup_md5["etc/config"],
            format!("{:x}", md5::compute(b"new"))
        );
    }

    #[test]
    fn backup_streams_multiple_buffers_and_replaces_regular_pacnew() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/config"), b"local").unwrap();
        std::fs::write(root.join("etc/config.pacnew"), b"old sidecar").unwrap();
        let contents: Vec<u8> = (0..3 * 64 * 1024 + 37).map(|n| (n % 251) as u8).collect();
        let archive = package(temp.path(), &contents, None);
        let metadata = extract_package(&archive, &root, &HashMap::new()).unwrap();
        assert_eq!(std::fs::read(root.join("etc/config")).unwrap(), b"local");
        assert_eq!(
            std::fs::read(root.join("etc/config.pacnew")).unwrap(),
            contents
        );
        assert_eq!(
            metadata.backup_md5["etc/config"],
            format!("{:x}", md5::compute(&contents))
        );
        assert_eq!(std::fs::read_dir(root.join("etc")).unwrap().count(), 2);
    }

    #[test]
    fn md5_streams_empty_and_multi_buffer_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config");
        for size in [0, 64 * 1024, 2 * 64 * 1024 + 37] {
            let data: Vec<u8> = (0..size).map(|n| (n % 251) as u8).collect();
            std::fs::write(&path, &data).unwrap();
            assert_eq!(
                compute_md5(&path).unwrap(),
                format!("{:x}", md5::compute(&data))
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
        header.set_uid(0);
        header.set_gid(0);
        header.set_mode(0o644);
        header.set_size(pkginfo.len() as u64);
        builder
            .append_data(&mut header, ".PKGINFO", pkginfo.as_slice())
            .unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_mode(0o777);
        header.set_size(0);
        builder
            .append_link(&mut header, "usr/link", target)
            .unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
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
    fn regular_file_replaced_by_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let path = "usr/lib/clang/23/lib/linux/clang_rt.crtbegin-i386.o";
        let target = "../i386-pc-linux-gnu/clang_rt.crtbegin.o";
        let dest = root.join(path);
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(&dest, b"old object").unwrap();
        let archive = package(
            temp.path(),
            b"new",
            Some((path, target, tar::EntryType::Symlink)),
        );
        extract_package(&archive, &root, &HashMap::new()).unwrap();
        assert_eq!(std::fs::read_link(&dest).unwrap(), Path::new(target));
    }

    #[test]
    fn symlink_replaced_by_regular_file_preserves_target() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("lib")).unwrap();
        let outside = temp.path().join("outside");
        std::fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("lib/file")).unwrap();
        let archive = overlay_package(temp.path(), "../lib");
        extract_package(&archive, &root, &HashMap::new()).unwrap();
        let dest = root.join("lib/file");
        assert!(std::fs::symlink_metadata(&dest).unwrap().is_file());
        assert_eq!(std::fs::read(&dest).unwrap(), b"payload");
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
    }

    #[test]
    fn symlink_replaced_by_symlink_preserves_target() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let outside = temp.path().join("outside");
        std::fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let archive = package(
            temp.path(),
            b"new",
            Some(("link", "new-target", tar::EntryType::Symlink)),
        );
        extract_package(&archive, &root, &HashMap::new()).unwrap();
        assert_eq!(
            std::fs::read_link(root.join("link")).unwrap(),
            Path::new("new-target")
        );
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
    }

    #[test]
    fn empty_directory_replaced_by_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("data")).unwrap();
        let archive = package(
            temp.path(),
            b"new",
            Some(("data", "other", tar::EntryType::Symlink)),
        );
        extract_package(&archive, &root, &HashMap::new()).unwrap();
        assert_eq!(
            std::fs::read_link(root.join("data")).unwrap(),
            Path::new("other")
        );
    }

    #[test]
    fn real_compiler_rt_upgrade_extracts_when_provided() {
        let (old, new) = match (
            std::env::var_os("PAX_TEST_COMPILER_RT_OLD"),
            std::env::var_os("PAX_TEST_COMPILER_RT_NEW"),
        ) {
            (None, None) => return,
            (Some(old), Some(new)) => (old, new),
            _ => panic!("set both PAX_TEST_COMPILER_RT_OLD and PAX_TEST_COMPILER_RT_NEW"),
        };
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let fresh = temp.path().join("fresh");
        let path = "usr/lib/clang/23/lib/linux/clang_rt.crtbegin-i386.o";
        let old_metadata = extract_package(Path::new(&old), &root, &HashMap::new()).unwrap();
        assert!(
            std::fs::symlink_metadata(root.join(path))
                .unwrap()
                .is_file()
        );
        extract_package(Path::new(&new), &root, &old_metadata.backup_md5).unwrap();
        let metadata = extract_package(Path::new(&new), &fresh, &HashMap::new()).unwrap();
        assert_eq!(
            std::fs::read_link(root.join(path)).unwrap(),
            Path::new("../i386-pc-linux-gnu/clang_rt.crtbegin.o")
        );
        assert!(root.join(path).is_file(), "upgraded link must resolve");
        assert_eq!(
            std::fs::read(root.join(path)).unwrap(),
            std::fs::read(fresh.join(path)).unwrap()
        );
        for path in &metadata.files {
            let expected = fresh.join(path);
            if std::fs::symlink_metadata(&expected)
                .unwrap()
                .file_type()
                .is_symlink()
            {
                assert_eq!(
                    std::fs::read_link(root.join(path)).unwrap(),
                    std::fs::read_link(&expected).unwrap(),
                    "upgraded symlink differs from fresh extraction: {path}"
                );
            }
        }
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
        let error = match extract_package(&archive, &root, &HashMap::new()) {
            Ok(_) => panic!("nonempty directory must not be replaced"),
            Err(error) => error,
        };
        match error {
            ExecError::Extraction { pkg, message } => {
                assert_eq!(pkg, "test.pkg.tar");
                assert!(message.contains("data"), "{message}");
                assert!(
                    message.contains("remove empty destination directory"),
                    "{message}"
                );
                let reason = std::fs::remove_dir(root.join("data")).unwrap_err();
                assert!(message.contains(&reason.to_string()), "{message}");
            }
            error => panic!("missing extraction context: {error}"),
        }
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
