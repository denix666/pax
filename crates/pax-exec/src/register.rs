use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use pax_alpm::desc::{generate_files_content, generate_local_desc_from_pkginfo};
use pax_core::package::{InstallReason, Validation};

use crate::error::{ExecError, Result};
use crate::extract::{PackageMetadata, validate_identity};

// Callers must hold the database lock across planning and these operations.
// RENAME_EXCHANGE is atomic publication, not an inode compare-and-swap.
pub fn register_package(
    db_path: &Path,
    metadata: &PackageMetadata,
    reason: InstallReason,
    validation: &[Validation],
    _root_dir: &Path,
) -> Result<()> {
    register_with_sync(db_path, metadata, reason, validation, File::sync_all)
}

fn register_with_sync(
    db_path: &Path,
    metadata: &PackageMetadata,
    reason: InstallReason,
    validation: &[Validation],
    mut sync_parent: impl FnMut(&File) -> io::Result<()>,
) -> Result<()> {
    // Rendering and every fallible metadata check precede even creating local/.
    let (name, version, installed_size, backup) = validate_metadata(metadata, validation)?;
    let install_date = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let desc = generate_local_desc_from_pkginfo(
        &metadata.pkginfo,
        installed_size,
        install_date,
        reason,
        validation,
    );
    let files = generate_files_content(&metadata.files, &backup);
    let local = open_local(db_path, true)?.expect("create opens local directory");
    let entry = OsString::from(format!("{name}-{version}"));
    let existing = inspect_entry(&local, &entry)?;
    let staging = local.temporary()?;
    let staging_path = local.access(&staging);
    let prepared = (|| {
        write_metadata(
            &staging_path,
            &local.path.join(&staging),
            "desc",
            desc.as_bytes(),
        )?;
        write_metadata(
            &staging_path,
            &local.path.join(&staging),
            "files",
            files.as_bytes(),
        )?;
        if !metadata.mtree.is_empty() {
            write_metadata(
                &staging_path,
                &local.path.join(&staging),
                "mtree",
                &metadata.mtree,
            )?;
        }
        if let Some(install) = &metadata.install {
            write_metadata(
                &staging_path,
                &local.path.join(&staging),
                "install",
                install.as_bytes(),
            )?;
        }
        let directory = context(
            "open staging directory",
            &local.path.join(&staging),
            open_directory(&staging_path),
        )?;
        // tempfile starts private (0700); published pacman DB directories are 0755.
        context(
            "set database directory mode",
            &local.path.join(&staging),
            directory.set_permissions(fs::Permissions::from_mode(0o755)),
        )?;
        context(
            "sync staging directory",
            &local.path.join(&staging),
            directory.sync_all(),
        )
    })();
    if let Err(error) = prepared {
        return Err(discard_staging(&local, &staging, error));
    }

    let flags = if existing {
        libc::RENAME_EXCHANGE
    } else {
        libc::RENAME_NOREPLACE
    };
    if let Err(error) = rename_entry(&local, &staging, &entry, flags) {
        let error = contextual_error("publish database entry", &local.path.join(&entry), error);
        return Err(discard_staging(&local, &staging, error));
    }
    // No TempDir guard survives the rename: after EXCHANGE its name holds the old DB.
    if let Err(error) = sync_parent(&local.directory) {
        return Err(after_publication(
            &local,
            &entry,
            existing.then_some(staging.as_os_str()),
            "sync local directory after publication",
            error,
        ));
    }
    if existing {
        cleanup_retired(&local, &entry, &staging, &mut sync_parent)?;
    }
    Ok(())
}

pub fn remove_db_entry(db_path: &Path, name: &str, version: &str) -> Result<()> {
    remove_with_sync(db_path, name, version, File::sync_all)
}

fn remove_with_sync(
    db_path: &Path,
    name: &str,
    version: &str,
    mut sync_parent: impl FnMut(&File) -> io::Result<()>,
) -> Result<()> {
    validate_identity(name, version)?;
    let Some(local) = open_local(db_path, false)? else {
        return Ok(());
    };
    let entry = OsString::from(format!("{name}-{version}"));
    if !inspect_entry(&local, &entry)? {
        return Ok(());
    }
    let retired = local.temporary()?;
    // Reserve a random name, then release only our empty directory. NOREPLACE
    // refuses a collision in the gap rather than deleting somebody else's entry.
    context(
        "release retirement name",
        &local.path.join(&retired),
        fs::remove_dir(local.access(&retired)),
    )?;
    context(
        "retire database entry",
        &local.path.join(&entry),
        rename_entry(&local, &entry, &retired, libc::RENAME_NOREPLACE),
    )?;
    if let Err(error) = sync_parent(&local.directory) {
        return Err(after_publication(
            &local,
            &entry,
            Some(&retired),
            "sync local directory after retirement",
            error,
        ));
    }
    cleanup_retired(&local, &entry, &retired, &mut sync_parent)
}

type ValidatedMetadata = (String, String, u64, Vec<(String, String)>);

/// Validate archive .PKGINFO before payload extraction, using the same rules as
/// registration. This performs no filesystem operations.
pub(crate) fn validate_pkginfo(pkginfo: &str) -> Result<()> {
    let (name, _) = parse_name_version(pkginfo)?;
    let invalid = |message: String| ExecError::Extraction {
        pkg: name.clone(),
        message,
    };
    let mut scalar_fields = HashSet::new();
    for raw in pkginfo.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = pkginfo_field(line) else {
            return Err(invalid(format!("malformed .PKGINFO line: {raw:?}")));
        };
        if key.is_empty()
            || !safe_value(key)
            || key.chars().any(char::is_whitespace)
            || !safe_value(value)
        {
            return Err(invalid(format!("unsafe .PKGINFO field: {raw:?}")));
        }
        if matches!(
            key,
            "pkgname"
                | "pkgver"
                | "pkgbase"
                | "pkgdesc"
                | "url"
                | "arch"
                | "builddate"
                | "packager"
                | "size"
        ) && !scalar_fields.insert(key)
        {
            return Err(invalid(format!("duplicate .PKGINFO field {key}")));
        }
        if key == "size" || key == "builddate" {
            value
                .parse::<u64>()
                .map_err(|error| invalid(format!("invalid .PKGINFO {key} {value:?}: {error}")))?;
        }
    }
    Ok(())
}

fn validate_metadata(
    metadata: &PackageMetadata,
    validation: &[Validation],
) -> Result<ValidatedMetadata> {
    validate_pkginfo(&metadata.pkginfo)?;
    let (name, version) = parse_name_version(&metadata.pkginfo)?;
    let invalid = |message: String| ExecError::Extraction {
        pkg: name.clone(),
        message,
    };
    let installed_size = metadata
        .pkginfo
        .lines()
        .filter_map(|line| pkginfo_field(line.trim()))
        .find_map(|(key, value)| (key == "size").then_some(value))
        .map(str::parse::<u64>)
        .transpose()
        .map_err(|error| invalid(format!("invalid .PKGINFO size: {error}")))?
        .unwrap_or(0);
    for value in validation {
        if let Validation::Unknown(value) = value {
            if value.is_empty() || !safe_value(value) || value.chars().any(char::is_whitespace) {
                return Err(invalid(format!("unsafe validation value {value:?}")));
            }
        }
    }
    let mut files = HashMap::new();
    for path in &metadata.files {
        let directory = path.ends_with('/');
        if !safe_file_path(path, true)
            || files
                .insert(path.trim_end_matches('/'), directory)
                .is_some_and(|previous_directory| !directory || !previous_directory)
        {
            return Err(invalid(format!("unsafe or duplicate file path {path:?}")));
        }
    }
    let mut backups = HashSet::new();
    let mut backup_with_md5 = Vec::with_capacity(metadata.backup.len());
    for path in &metadata.backup {
        if !safe_file_path(path, false)
            || !backups.insert(path.as_str())
            || files.get(path.as_str()) != Some(&false)
        {
            return Err(invalid(format!(
                "unsafe, duplicate or unlisted backup path {path:?}"
            )));
        }
        let md5 = metadata
            .backup_md5
            .get(path)
            .ok_or_else(|| invalid(format!("missing archive MD5 for backup {path}")))?;
        if md5.len() != 32 || !md5.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid(format!("invalid archive MD5 for backup {path}")));
        }
        backup_with_md5.push((path.clone(), md5.clone()));
    }
    if metadata
        .backup_md5
        .keys()
        .any(|path| !backups.contains(path.as_str()))
    {
        return Err(invalid(
            "archive MD5 supplied for an undeclared backup".into(),
        ));
    }
    // mtree and install are opaque archive contents, not DB field syntax. In
    // particular, do not interpret install as shell code or recompute backups.
    Ok((name, version, installed_size, backup_with_md5))
}

fn safe_value(value: &str) -> bool {
    !value.chars().any(char::is_control) && !(value.starts_with('%') && value.ends_with('%'))
}

pub(crate) fn safe_file_path(value: &str, directory: bool) -> bool {
    let path = if directory {
        value.strip_suffix('/').unwrap_or(value)
    } else {
        value
    };
    !path.is_empty()
        && safe_value(value)
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn pkginfo_field(line: &str) -> Option<(&str, &str)> {
    line.split_once(" = ")
        .or_else(|| line.strip_suffix(" =").map(|key| (key, "")))
}

fn parse_name_version(pkginfo: &str) -> Result<(String, String)> {
    let mut name = None;
    let mut version = None;
    // Match the desc generator's whitespace handling and scan the entire input.
    for line in pkginfo.lines().map(str::trim) {
        let Some((key, value)) = pkginfo_field(line) else {
            continue;
        };
        let slot = match key {
            "pkgname" => &mut name,
            "pkgver" => &mut version,
            _ => continue,
        };
        if slot.replace(value.to_string()).is_some() {
            return Err(ExecError::Extraction {
                pkg: name.unwrap_or_default(),
                message: format!("duplicate {key} in .PKGINFO"),
            });
        }
    }
    match (name, version) {
        (Some(name), Some(version)) => {
            validate_identity(&name, &version)?;
            if name.len().saturating_add(version.len()).saturating_add(1) > 255 {
                return Err(ExecError::Extraction {
                    pkg: name,
                    message: "database name-version exceeds Linux NAME_MAX (255 bytes)".into(),
                });
            }
            Ok((name, version))
        }
        _ => Err(ExecError::Extraction {
            pkg: String::new(),
            message: "missing pkgname or pkgver in .PKGINFO".into(),
        }),
    }
}

struct LocalDirectory {
    directory: File,
    path: PathBuf,
}

impl LocalDirectory {
    fn access(&self, name: &OsStr) -> PathBuf {
        // Anchor local metadata accesses to the validated descriptor instead of
        // traversing DBPath again. Renames below also use this fd.
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd())).join(name)
    }

    fn temporary(&self) -> Result<OsString> {
        let temporary = context(
            "create private database staging directory",
            &self.path,
            tempfile::Builder::new()
                .prefix(".pax-db-")
                .tempdir_in(self.access(OsStr::new(""))),
        )?;
        // Explicit ownership: auto-removal after exchange would destroy old DB.
        let path = temporary.keep();
        Ok(path
            .file_name()
            .expect("temporary directory has a name")
            .to_os_string())
    }
}

fn open_local(db_path: &Path, create: bool) -> Result<Option<LocalDirectory>> {
    // Match journal::canonical_database: reject a link at DBPath itself, but
    // allow trusted parent links before resolving the canonical endpoint.
    let endpoint = match open_directory(db_path) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound && !create => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_missing_database(db_path)?;
            context(
                "open created database endpoint",
                db_path,
                open_directory(db_path),
            )?
        }
        Err(error) => {
            return Err(contextual_error(
                "open database endpoint without following links",
                db_path,
                error,
            ));
        }
    };
    context(
        "validate database endpoint",
        db_path,
        validate_directory(&endpoint),
    )?;
    let mut path = context("canonicalize database", db_path, fs::canonicalize(db_path))?;
    let directory = context(
        "open canonical database directory",
        &path,
        open_directory(&path),
    )?;
    context(
        "validate canonical database directory",
        &path,
        validate_directory(&directory),
    )?;
    path.push("local");
    let Some(directory) = open_child(&directory, OsStr::new("local"), &path, create)? else {
        return Ok(None);
    };
    context(
        "validate local directory",
        &path,
        validate_directory(&directory),
    )?;
    Ok(Some(LocalDirectory { directory, path }))
}

// Direct registration also supports an absent DBPath (unlike journal setup).
// Resolve only existing, trusted ancestors; create missing children using fds,
// without following links that appear at any of the new directory names.
fn create_missing_database(db_path: &Path) -> Result<()> {
    let absolute = context(
        "resolve database path",
        db_path,
        std::path::absolute(db_path),
    )?;
    let mut ancestor = absolute.as_path();
    let mut missing = Vec::new();
    let mut path = loop {
        match fs::canonicalize(ancestor) {
            Ok(path) => break path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = ancestor.file_name().ok_or_else(|| {
                    contextual_error(
                        "resolve missing database ancestor",
                        ancestor,
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "missing path component must be a normal directory name",
                        ),
                    )
                })?;
                missing.push(name);
                ancestor = ancestor
                    .parent()
                    .expect("a named absolute path has a parent");
            }
            Err(error) => {
                return Err(contextual_error(
                    "resolve database ancestor",
                    ancestor,
                    error,
                ));
            }
        }
    };
    let mut directory = context("open database ancestor", &path, open_directory(&path))?;
    for name in missing.into_iter().rev() {
        path.push(name);
        directory =
            open_child(&directory, name, &path, true)?.expect("create opens database child");
        context(
            "validate created database directory",
            &path,
            validate_directory(&directory),
        )?;
    }
    Ok(())
}

fn open_child(parent: &File, name: &OsStr, path: &Path, create: bool) -> Result<Option<File>> {
    let name = context("encode database directory name", path, c_string(name))?;
    let open = || {
        // SAFETY: name is NUL-terminated and parent is an open directory.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: openat returned a new owned descriptor.
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    };
    match open() {
        Ok(directory) => Ok(Some(directory)),
        Err(error) if error.kind() == io::ErrorKind::NotFound && !create => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // SAFETY: arguments have the same validity as the openat above.
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) } != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(contextual_error("create database directory", path, error));
                }
            }
            let directory = context("open created database directory", path, open())?;
            context(
                "sync created database directory",
                path,
                directory.sync_all(),
            )?;
            context(
                "sync parent of created database directory",
                path.parent().unwrap_or(Path::new("/")),
                parent.sync_all(),
            )?;
            Ok(Some(directory))
        }
        Err(error) => Err(contextual_error(
            "open database directory without following links",
            path,
            error,
        )),
    }
}

fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn validate_directory(directory: &File) -> io::Result<()> {
    let metadata = directory.metadata()?;
    // SAFETY: geteuid has no preconditions.
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "database directory must be euid-owned and not group/world writable",
        ));
    }
    Ok(())
}

fn inspect_entry(local: &LocalDirectory, entry: &OsStr) -> Result<bool> {
    let path = local.path.join(entry);
    match open_directory(&local.access(entry)) {
        Ok(directory) => {
            context(
                "validate existing database entry",
                &path,
                validate_directory(&directory),
            )?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(contextual_error(
            "open database entry without following links",
            &path,
            error,
        )),
    }
}

fn write_metadata(directory: &Path, display: &Path, name: &str, contents: &[u8]) -> Result<()> {
    let path = display.join(name);
    let mut file = context(
        "create database metadata file",
        &path,
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join(name)),
    )?;
    context(
        "write database metadata file",
        &path,
        file.write_all(contents),
    )?;
    context(
        "set database file mode",
        &path,
        file.set_permissions(fs::Permissions::from_mode(0o644)),
    )?;
    context("sync database metadata file", &path, file.sync_all())
}

fn c_string(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

fn rename_entry(
    local: &LocalDirectory,
    source: &OsStr,
    destination: &OsStr,
    flags: libc::c_uint,
) -> io::Result<()> {
    let source = c_string(source)?;
    let destination = c_string(destination)?;
    // SAFETY: both names are NUL-terminated and the descriptor remains open.
    let result = unsafe {
        libc::renameat2(
            local.directory.as_raw_fd(),
            source.as_ptr(),
            local.directory.as_raw_fd(),
            destination.as_ptr(),
            flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn discard_staging(local: &LocalDirectory, staging: &OsStr, error: ExecError) -> ExecError {
    match fs::remove_dir_all(local.access(staging)).and_then(|()| local.directory.sync_all()) {
        Ok(()) => error,
        Err(cleanup) => contextual_error(
            "discard unpublished staging",
            &local.path.join(staging),
            io::Error::new(
                cleanup.kind(),
                format!("{error}; staging cleanup failed: {cleanup}"),
            ),
        ),
    }
}

const MAX_RETIRED_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RETIRED_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RETIRED_ITEMS: usize = 65_536;

// Keep a process-local copy until cleanup's final fsync. This is only for
// reporting/repairing cleanup I/O failures, not a crash-recovery journal. A
// storage failure can also prevent restoration; that secondary error is explicit.
struct RetiredContents {
    mode: u32,
    files: Vec<(OsString, u32, Vec<u8>)>,
}

impl RetiredContents {
    fn read(path: &Path) -> io::Result<Self> {
        let directory = open_directory(path)?;
        validate_directory(&directory)?;
        let mut files = Vec::new();
        let mut total_bytes = 0;
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if files.len() == MAX_RETIRED_ITEMS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("retired metadata exceeds {MAX_RETIRED_ITEMS} entries"),
                ));
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(entry.path())?;
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "retired metadata {} is not a regular file",
                        entry.file_name().to_string_lossy()
                    ),
                ));
            }
            let remaining = MAX_RETIRED_TOTAL_BYTES - total_bytes;
            let limit = MAX_RETIRED_FILE_BYTES.min(remaining);
            let oversized = || {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "retired metadata {} exceeds the 64 MiB file or 256 MiB aggregate limit ({} bytes remaining)",
                        entry.file_name().to_string_lossy(),
                        remaining
                    ),
                )
            };
            if metadata.len() > limit {
                return Err(oversized());
            }
            // Bound actual reads as well as stat sizes: a file can grow after
            // fstat. One extra byte detects overflow without unbounded allocation.
            let mut contents = Vec::new();
            file.take(limit + 1).read_to_end(&mut contents)?;
            if contents.len() as u64 > limit {
                return Err(oversized());
            }
            total_bytes += contents.len() as u64;
            files.push((entry.file_name(), metadata.mode() & 0o7777, contents));
        }
        Ok(Self {
            mode: directory.metadata()?.mode() & 0o7777,
            files,
        })
    }

    fn restore(&self, path: &Path, local: &LocalDirectory) -> io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let directory = open_directory(path)?;
        validate_directory(&directory)?;
        for (name, mode, contents) in &self.files {
            let mut file = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path.join(name))
            {
                Ok(file) => file,
                // Cleanup only unlinks whole files; surviving files are unchanged.
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            };
            file.write_all(contents)?;
            file.set_permissions(fs::Permissions::from_mode(*mode))?;
            file.sync_all()?;
        }
        directory.set_permissions(fs::Permissions::from_mode(self.mode))?;
        directory.sync_all()?;
        local.directory.sync_all()
    }
}

fn cleanup_retired(
    local: &LocalDirectory,
    entry: &OsStr,
    retired: &OsStr,
    sync_parent: &mut impl FnMut(&File) -> io::Result<()>,
) -> Result<()> {
    let path = local.access(retired);
    let contents = RetiredContents::read(&path).map_err(|error| {
        after_publication(
            local,
            entry,
            Some(retired),
            "inspect retired metadata before cleanup",
            error,
        )
    })?;
    let mut operation = "unlink retired metadata file";
    let mut failed_path = local.path.join(retired);
    let cleanup = (|| -> io::Result<()> {
        for (name, _, _) in &contents.files {
            failed_path = local.path.join(retired).join(name);
            fs::remove_file(path.join(name))?;
        }
        operation = "sync emptied retired directory";
        failed_path = local.path.join(retired);
        open_directory(&path)?.sync_all()?;
        operation = "remove retired directory";
        fs::remove_dir(&path)?;
        operation = "sync local directory after cleanup";
        failed_path = local.path.clone();
        sync_parent(&local.directory)
    })();
    if let Err(error) = cleanup {
        let restored = contents.restore(&path, local);
        let restoration = match restored {
            Ok(()) => format!(
                "retired metadata restored and retained at {}",
                local.path.join(retired).display()
            ),
            Err(restore_error) => format!(
                "restoring retired metadata at {} also failed: {restore_error}; retained contents may be incomplete",
                local.path.join(retired).display()
            ),
        };
        return Err(contextual_error(
            operation,
            &failed_path,
            io::Error::new(
                error.kind(),
                format!(
                    "{error}; database entry {} was already published/retired; {restoration}",
                    local.path.join(entry).display()
                ),
            ),
        ));
    }
    Ok(())
}

fn after_publication(
    local: &LocalDirectory,
    entry: &OsStr,
    retired: Option<&OsStr>,
    operation: &str,
    error: io::Error,
) -> ExecError {
    let retained = match retired {
        Some(retired) => format!(
            "; old metadata retained at {}",
            local.path.join(retired).display()
        ),
        None => "; no previous entry existed".into(),
    };
    contextual_error(
        operation,
        &local.path.join(entry),
        io::Error::new(
            error.kind(),
            format!("{error}; database entry was already published/retired{retained}"),
        ),
    )
}

fn contextual_error(operation: &str, path: &Path, error: io::Error) -> ExecError {
    ExecError::Io(io::Error::new(
        error.kind(),
        format!("database {}: {operation}: {error}", path.display()),
    ))
}

fn context<T>(operation: &str, path: &Path, result: io::Result<T>) -> Result<T> {
    result.map_err(|error| contextual_error(operation, path, error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::unix::fs::symlink;

    fn metadata() -> PackageMetadata {
        PackageMetadata {
            pkginfo: "pkgname = test\npkgver = 1-1\nsize = 17\n".into(),
            mtree: b"opaque mtree".to_vec(),
            install: Some("post_install() { :; }\n".into()),
            files: vec!["etc/".into(), "etc/config".into()],
            backup: vec!["etc/config".into()],
            backup_md5: HashMap::from([(
                "etc/config".into(),
                "0123456789abcdef0123456789abcdef".into(),
            )]),
            warnings: Vec::new(),
        }
    }

    fn register(db: &Path, metadata: &PackageMetadata) -> Result<()> {
        register_package(db, metadata, InstallReason::Explicit, &[], db)
    }

    fn entries(path: &Path) -> Vec<OsString> {
        let mut entries: Vec<_> = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        entries.sort();
        entries
    }

    fn retained(local: &Path) -> PathBuf {
        let paths: Vec<_> = entries(local)
            .into_iter()
            .filter(|name| name.as_bytes().starts_with(b".pax-db-"))
            .collect();
        assert_eq!(paths.len(), 1);
        local.join(&paths[0])
    }

    #[test]
    fn registration_uses_archive_hash_even_with_local_modifications() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let db = temp.path().join("db");
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(root.join("etc/config"), "local changes").unwrap();
        let metadata = metadata();
        register_package(&db, &metadata, InstallReason::Explicit, &[], &root).unwrap();
        let files = fs::read_to_string(db.join("local/test-1-1/files")).unwrap();
        assert!(files.contains(&format!(
            "etc/config\t{}",
            metadata.backup_md5["etc/config"]
        )));
    }

    #[test]
    fn invalid_metadata_leaves_database_untouched() {
        for invalid in 0..12 {
            let temp = tempfile::tempdir().unwrap();
            let db = temp.path().join("db");
            let mut bad = metadata();
            match invalid {
                0 => bad.backup_md5.clear(),
                1 => bad.pkginfo.push_str("pkgname = other\n"),
                2 => bad.pkginfo.push_str("  pkgver = 2-1  \n"),
                3 => bad.pkginfo.push_str("pkgname = test\n"),
                4 => bad.files.push("../escape".into()),
                5 => bad.files.push("etc/config\n%BACKUP%".into()),
                6 => {
                    bad.backup_md5
                        .insert("etc/config".into(), "not an md5".into());
                }
                7 => bad.pkginfo = "pkgname = test\npkgver = 1-1\nsize = invalid\n".into(),
                8 => bad.backup.push("etc/config".into()),
                9 => bad.pkginfo.push_str("pkgdesc = %VERSION%\n"),
                10 => bad.pkginfo = format!("pkgname = {}\npkgver = 1-1\n", "x".repeat(255)),
                11 => bad.pkginfo.push_str("pkgname = \n"),
                _ => unreachable!(),
            }
            assert!(register(&db, &bad).is_err(), "case {invalid}");
            assert!(!db.exists(), "case {invalid} created the DB");
            register(&db, &metadata()).unwrap();
            let old = fs::read(db.join("local/test-1-1/desc")).unwrap();
            let inode = fs::metadata(db.join("local/test-1-1")).unwrap().ino();
            assert!(register(&db, &bad).is_err(), "case {invalid}");
            assert_eq!(fs::read(db.join("local/test-1-1/desc")).unwrap(), old);
            assert_eq!(
                fs::metadata(db.join("local/test-1-1")).unwrap().ino(),
                inode
            );
            assert_eq!(entries(&db.join("local")), vec![OsString::from("test-1-1")]);
        }
    }

    #[test]
    fn same_version_publication_exchanges_complete_directories() {
        let temp = tempfile::tempdir().unwrap();
        register(temp.path(), &metadata()).unwrap();
        let local = temp.path().join("local");
        let published = local.join("test-1-1");
        let old_directory = File::open(&published).unwrap();
        let old_inode = old_directory.metadata().unwrap().ino();
        let mut incoming = metadata();
        incoming.pkginfo.push_str("pkgdesc = replacement\n");
        incoming.mtree.clear();
        incoming.install = None;
        let mut syncs = 0;
        register_with_sync(
            temp.path(),
            &incoming,
            InstallReason::Dependency,
            &[],
            |directory| {
                syncs += 1;
                assert!(published.is_dir());
                assert_ne!(fs::metadata(&published)?.ino(), old_inode);
                if syncs == 1 {
                    assert_eq!(fs::metadata(retained(&local))?.ino(), old_inode);
                    assert!(published.join("desc").is_file());
                    assert!(published.join("files").is_file());
                }
                directory.sync_all()
            },
        )
        .unwrap();
        assert_eq!(syncs, 2);
        assert_eq!(entries(&local), vec![OsString::from("test-1-1")]);
        assert!(!published.join("mtree").exists());
        assert!(!published.join("install").exists());
        let desc = fs::read_to_string(published.join("desc")).unwrap();
        assert!(desc.contains("replacement"));
        assert!(desc.contains("%REASON%\n1\n"));
    }

    #[test]
    fn empty_optional_pkginfo_fields_and_obsolete_backup_declarations_are_allowed() {
        let temp = tempfile::tempdir().unwrap();
        let mut metadata = metadata();
        metadata
            .pkginfo
            .push_str("pkgdesc = \nurl = \nbackup = obsolete-config\n");
        register(temp.path(), &metadata).unwrap();
        let files = fs::read_to_string(temp.path().join("local/test-1-1/files")).unwrap();
        assert!(!files.contains("obsolete-config"));
    }

    #[test]
    fn normal_database_modes_and_opaque_files() {
        let temp = tempfile::tempdir().unwrap();
        let metadata = metadata();
        register(temp.path(), &metadata).unwrap();
        let entry = temp.path().join("local/test-1-1");
        assert_eq!(fs::metadata(&entry).unwrap().mode() & 0o777, 0o755);
        for name in ["desc", "files", "mtree", "install"] {
            assert_eq!(
                fs::metadata(entry.join(name)).unwrap().mode() & 0o777,
                0o644
            );
        }
        assert_eq!(fs::read(entry.join("mtree")).unwrap(), metadata.mtree);
        assert_eq!(
            fs::read_to_string(entry.join("install")).unwrap(),
            metadata.install.unwrap()
        );
    }

    #[test]
    fn symlink_and_non_directory_destinations_are_refused() {
        for kind in ["directory-link", "dangling-link", "file"] {
            let temp = tempfile::tempdir().unwrap();
            let local = temp.path().join("local");
            let outside = temp.path().join("outside");
            fs::create_dir(&local).unwrap();
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("sentinel"), "keep").unwrap();
            let entry = local.join("test-1-1");
            match kind {
                "directory-link" => symlink(&outside, &entry).unwrap(),
                "dangling-link" => symlink(temp.path().join("missing"), &entry).unwrap(),
                _ => fs::write(&entry, "keep").unwrap(),
            }
            assert!(register(temp.path(), &metadata()).is_err());
            assert!(remove_db_entry(temp.path(), "test", "1-1").is_err());
            assert!(fs::symlink_metadata(&entry).is_ok());
            assert_eq!(
                fs::read_to_string(outside.join("sentinel")).unwrap(),
                "keep"
            );
            assert_eq!(entries(&local), vec![OsString::from("test-1-1")]);
        }
    }

    #[test]
    fn unsafe_local_directory_is_refused_without_writes() {
        for kind in ["link", "writable", "file"] {
            let temp = tempfile::tempdir().unwrap();
            let db = temp.path().join("db");
            let outside = temp.path().join("outside");
            fs::create_dir(&db).unwrap();
            fs::create_dir(&outside).unwrap();
            let local = db.join("local");
            match kind {
                "link" => symlink(&outside, &local).unwrap(),
                "writable" => {
                    fs::create_dir(&local).unwrap();
                    fs::set_permissions(&local, fs::Permissions::from_mode(0o777)).unwrap();
                }
                _ => fs::write(&local, "keep").unwrap(),
            }
            assert!(register(&db, &metadata()).is_err());
            assert!(remove_db_entry(&db, "test", "1-1").is_err());
            assert!(entries(&outside).is_empty());
            if kind == "writable" {
                assert!(entries(&local).is_empty());
            }
        }
    }

    #[test]
    fn foreign_local_directory_is_refused_when_root() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let local = temp.path().join("local");
        fs::create_dir(&local).unwrap();
        let directory = File::open(&local).unwrap();
        // SAFETY: directory is a valid open descriptor; this test requires root.
        assert_eq!(
            unsafe { libc::fchown(directory.as_raw_fd(), 65534, 65534) },
            0
        );
        assert!(register(temp.path(), &metadata()).is_err());
        assert!(remove_db_entry(temp.path(), "test", "1-1").is_err());
        assert!(entries(&local).is_empty());
    }

    #[test]
    fn stale_temporary_paths_are_never_removed() {
        let temp = tempfile::tempdir().unwrap();
        let local = temp.path().join("local");
        fs::create_dir(&local).unwrap();
        for name in [".test-1-1.tmp", ".pax-db-stale"] {
            fs::create_dir(local.join(name)).unwrap();
            fs::write(local.join(name).join("sentinel"), "keep").unwrap();
        }
        register(temp.path(), &metadata()).unwrap();
        register(temp.path(), &metadata()).unwrap();
        remove_db_entry(temp.path(), "test", "1-1").unwrap();
        for name in [".test-1-1.tmp", ".pax-db-stale"] {
            assert_eq!(
                fs::read_to_string(local.join(name).join("sentinel")).unwrap(),
                "keep"
            );
        }
        assert_eq!(entries(&local).len(), 2);
    }

    #[test]
    fn postpublication_sync_failure_retains_old_metadata() {
        let temp = tempfile::tempdir().unwrap();
        register(temp.path(), &metadata()).unwrap();
        let local = temp.path().join("local");
        let old = fs::read(local.join("test-1-1/desc")).unwrap();
        let mut incoming = metadata();
        incoming.pkginfo.push_str("pkgdesc = replacement\n");
        let error =
            register_with_sync(temp.path(), &incoming, InstallReason::Explicit, &[], |_| {
                Err(io::Error::other("injected publication sync"))
            })
            .unwrap_err()
            .to_string();
        let retained = retained(&local);
        assert_eq!(fs::read(retained.join("desc")).unwrap(), old);
        assert!(
            fs::read_to_string(local.join("test-1-1/desc"))
                .unwrap()
                .contains("replacement")
        );
        assert!(error.contains("sync local directory after publication"));
        assert!(error.contains(retained.to_str().unwrap()));
        assert!(error.contains("injected publication sync"));
    }

    #[test]
    fn new_publication_sync_failure_leaves_complete_published_entry() {
        let temp = tempfile::tempdir().unwrap();
        let error = register_with_sync(
            temp.path(),
            &metadata(),
            InstallReason::Explicit,
            &[],
            |_| Err(io::Error::other("injected sync")),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("already published"));
        let local = temp.path().join("local");
        assert_eq!(entries(&local), vec![OsString::from("test-1-1")]);
        for name in ["desc", "files", "mtree", "install"] {
            assert!(local.join("test-1-1").join(name).is_file());
        }
    }

    #[test]
    fn retirement_sync_failure_preserves_the_complete_old_directory() {
        let temp = tempfile::tempdir().unwrap();
        register(temp.path(), &metadata()).unwrap();
        let local = temp.path().join("local");
        let old = fs::read(local.join("test-1-1/desc")).unwrap();
        let inode = fs::metadata(local.join("test-1-1")).unwrap().ino();
        let error = remove_with_sync(temp.path(), "test", "1-1", |_| {
            Err(io::Error::other("injected retirement sync"))
        })
        .unwrap_err()
        .to_string();
        assert!(!local.join("test-1-1").exists());
        let retained = retained(&local);
        assert_eq!(fs::metadata(&retained).unwrap().ino(), inode);
        assert_eq!(fs::read(retained.join("desc")).unwrap(), old);
        assert!(error.contains(retained.to_str().unwrap()));
        assert!(error.contains("sync local directory after retirement"));
    }

    #[test]
    fn cleanup_sync_failure_restores_retired_metadata() {
        for remove in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            register(temp.path(), &metadata()).unwrap();
            let local = temp.path().join("local");
            let old = fs::read(local.join("test-1-1/desc")).unwrap();
            let mut calls = 0;
            let sync = |directory: &File| {
                calls += 1;
                if calls == 2 {
                    Err(io::Error::other("injected cleanup sync"))
                } else {
                    directory.sync_all()
                }
            };
            let error = if remove {
                remove_with_sync(temp.path(), "test", "1-1", sync)
            } else {
                register_with_sync(temp.path(), &metadata(), InstallReason::Explicit, &[], sync)
            }
            .unwrap_err()
            .to_string();
            let retained = retained(&local);
            assert_eq!(fs::read(retained.join("desc")).unwrap(), old);
            assert_eq!(entries(&retained).len(), 4);
            assert_eq!(local.join("test-1-1").exists(), !remove);
            assert!(error.contains("sync local directory after cleanup"));
            assert!(error.contains(retained.to_str().unwrap()));
            assert!(error.contains("restored and retained"));
        }
    }

    #[test]
    fn cleanup_refuses_links_inside_retired_metadata() {
        let temp = tempfile::tempdir().unwrap();
        register(temp.path(), &metadata()).unwrap();
        let local = temp.path().join("local");
        let outside = temp.path().join("sentinel");
        fs::write(&outside, "keep").unwrap();
        symlink(&outside, local.join("test-1-1/extra")).unwrap();
        let error = remove_db_entry(temp.path(), "test", "1-1")
            .unwrap_err()
            .to_string();
        let retired = retained(&local);
        assert!(retired.join("desc").is_file());
        assert!(
            fs::symlink_metadata(retired.join("extra"))
                .unwrap()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(outside).unwrap(), "keep");
        assert!(error.contains(retired.to_str().unwrap()));
    }

    #[test]
    fn rename_noreplace_does_not_clobber_an_existing_entry() {
        let temp = tempfile::tempdir().unwrap();
        let local = open_local(temp.path(), true).unwrap().unwrap();
        for name in ["source", "destination"] {
            fs::create_dir(local.access(OsStr::new(name))).unwrap();
            fs::write(local.access(OsStr::new(name)).join("sentinel"), name).unwrap();
        }
        assert_eq!(
            rename_entry(
                &local,
                OsStr::new("source"),
                OsStr::new("destination"),
                libc::RENAME_NOREPLACE
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::AlreadyExists
        );
        for name in ["source", "destination"] {
            assert_eq!(
                fs::read_to_string(local.access(OsStr::new(name)).join("sentinel")).unwrap(),
                name
            );
        }
    }

    #[test]
    fn removing_missing_entry_does_not_create_database() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("missing");
        remove_db_entry(&db, "test", "1-1").unwrap();
        assert!(!db.exists());
    }
}
