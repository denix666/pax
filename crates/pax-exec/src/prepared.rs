//! Private, temporary archive copies bound to the selected database directory.
//! The caller holds the database lock while preparing and using them. Each copy
//! is removed on drop; existing staging directories and their contents are untouched.
//!
//! Canonical database ancestors and the effective uid are trusted. This protects
//! against mutable cache/source files, not a hostile root process. Only the copied
//! bytes are verified and used; the original source is not reopened after preparation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use pax_core::config::{SigLevel, SigTrust};
use pax_core::package::Validation;

use sha2::{Digest, Sha256};
use tempfile::TempDir;

use crate::download::{DownloadTarget, DownloadedPackage};
use crate::error::{ExecError, Result};
use crate::extract::{PkgFileInfo, read_pkginfo};

use crate::verify::{verify_sha256, verify_signature};

const DIRECTORY: &str = ".pax-prepared";
const PREFIX: &str = "archive-";
const SIGNATURE_LIMIT: u64 = 1024 * 1024;
const SPACE_HEADROOM: u64 = 16 * 1024 * 1024;
const FILENAMES: [&str; 4] = [
    "archive.pkg.tar.zst",
    "archive.pkg.tar.xz",
    "archive.pkg.tar.gz",
    "archive.pkg.tar",
];

#[derive(Debug, Clone)]
pub struct ArchivePolicy {
    pub expected_sha256: Option<String>,
    pub sig_level: SigLevel,
    pub sig_trust: SigTrust,
}

struct CopyProof {
    size: u64,
    sha256: String,
}

pub struct PreparedArchive {
    directory: TempDir,
    path: PathBuf,
    source_path: PathBuf,
    info: PkgFileInfo,
    validations: Vec<Validation>,
    db_path: PathBuf,
    db_device: u64,
    db_inode: u64,
    archive: CopyProof,
    signature: Option<CopyProof>,
}

impl PreparedArchive {
    pub fn prepare(
        source: &Path,
        db_path: &Path,
        gpg_dir: &Path,
        policy: ArchivePolicy,
    ) -> Result<Self> {
        context(
            "prepare archive",
            source,
            Self::prepare_inner(source, db_path, gpg_dir, policy),
        )
    }

    fn prepare_inner(
        source: &Path,
        db_path: &Path,
        gpg_dir: &Path,
        policy: ArchivePolicy,
    ) -> Result<Self> {
        if policy.expected_sha256.as_deref().is_some_and(|hash| {
            hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            return Err(invalid(
                source,
                "expected SHA-256 must contain exactly 64 lowercase hexadecimal digits",
            ));
        }
        let db_path = canonical_database(db_path)?;
        let database = open_directory(&db_path, false)?;
        let db_metadata = context("inspect database", &db_path, database.metadata())?;
        let mut archive = Source::open(source)?;
        let mut signature = if policy.sig_level == SigLevel::Never {
            None
        } else {
            let path = signature_path(source);
            // A dangling symlink is present, not an optional missing signature.
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    let signature = Source::open(&path)?;
                    if signature.metadata.len() > SIGNATURE_LIMIT {
                        return Err(invalid(&path, "signature exceeds 1 MiB"));
                    }
                    Some(signature)
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return context("inspect source signature", &path, Err(error)),
            }
        };
        let signature_size = signature.as_ref().map_or(0, |s| s.metadata.len());
        check_space(
            &database,
            &db_path,
            archive.metadata.len(),
            signature_size,
            signature.is_some(),
        )?;

        let top_path = db_path.join(DIRECTORY);
        let top = create_private_directory(&top_path)?;
        same_device(&top, &top_path, db_metadata.dev())?;
        let directory = context(
            "create private archive directory",
            &top_path,
            tempfile::Builder::new()
                .prefix(PREFIX)
                .tempdir_in(&top_path),
        )?;
        context(
            "set private archive directory permissions",
            directory.path(),
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)),
        )?;
        let staging = open_directory(directory.path(), true)?;
        same_device(&staging, directory.path(), db_metadata.dev())?;
        let filename = staged_filename(&archive.canonical);
        let path = directory.path().join(filename);
        let archive_proof = archive.copy_to(&path)?;
        let signature_path = signature_path(&path);
        let signature_proof = signature
            .as_mut()
            .map(|input| input.copy_to(&signature_path))
            .transpose()?;
        // Check both inputs after both copies, before trusting the copied pair.
        archive.check_unchanged()?;
        if let Some(signature) = &signature {
            signature.check_unchanged()?;
        }

        let mut validations = Vec::new();
        if let Some(expected) = &policy.expected_sha256 {
            context(
                "verify copied SHA-256",
                &path,
                verify_sha256(&path, expected),
            )?;
            validations.push(Validation::Sha256);
        }
        context(
            "verify copied signature",
            &path,
            verify_signature(
                &path,
                signature_proof.as_ref().map(|_| signature_path.as_path()),
                gpg_dir,
                policy.sig_level,
                policy.sig_trust,
            ),
        )?;
        if signature_proof.is_some() && policy.sig_level != SigLevel::Never {
            validations.push(Validation::Pgp);
        }
        if validations.is_empty() {
            validations.push(Validation::None);
        }
        let info = context("read copied package metadata", &path, read_pkginfo(&path))?;
        let prepared = Self {
            directory,
            path,
            source_path: source.to_path_buf(),
            info,
            validations,
            db_path: db_path.clone(),
            db_device: db_metadata.dev(),
            db_inode: db_metadata.ino(),
            archive: archive_proof,
            signature: signature_proof,
        };
        prepared.verify_for_database(&db_path)?;
        Ok(prepared)
    }

    pub fn name(&self) -> &str {
        &self.info.name
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    pub fn info(&self) -> &PkgFileInfo {
        &self.info
    }

    pub fn validations(&self) -> &[Validation] {
        &self.validations
    }

    pub fn verify_for_database(&self, db_path: &Path) -> Result<()> {
        context(
            &format!("verify prepared package {}", self.name()),
            &self.source_path,
            self.verify_inner(db_path),
        )
    }

    fn verify_inner(&self, db_path: &Path) -> Result<()> {
        let db_path = canonical_database(db_path)?;
        let database = open_directory(&db_path, false)?;
        let db_metadata = context("inspect database binding", &db_path, database.metadata())?;
        if self.db_path != db_path
            || self.db_device != db_metadata.dev()
            || self.db_inode != db_metadata.ino()
        {
            return Err(invalid(
                &db_path,
                "prepared archive database binding changed",
            ));
        }
        let top_path = db_path.join(DIRECTORY);
        let top = open_directory(&top_path, true)?;
        same_device(&top, &top_path, self.db_device)?;
        let directory = self.directory.path();
        let staging = open_directory(directory, true)?;
        same_device(&staging, directory, self.db_device)?;
        let signature = signature_path(&self.path);
        let mut expected_entries = BTreeSet::from([self.path.file_name().unwrap().to_os_string()]);
        if self.signature.is_some() {
            expected_entries.insert(signature.file_name().unwrap().to_os_string());
        }
        for entry in context("list archive directory", directory, fs::read_dir(directory))? {
            let entry = context("read archive directory entry", directory, entry)?;
            if !expected_entries.remove(&entry.file_name()) {
                return Err(invalid(
                    &entry.path(),
                    "unexpected entry in prepared archive directory",
                ));
            }
        }
        if !expected_entries.is_empty() {
            return Err(invalid(directory, "missing prepared archive entry"));
        }
        verify_file(&self.path, &self.archive)?;
        if let Some(expected) = &self.signature {
            verify_file(&signature, expected)?;
        }
        Ok(())
    }
}

/// Associate by name, never by vector position. Results follow target order.
/// Download-only callers must not invoke this function.
pub fn prepare_downloaded_packages(
    downloaded: &[DownloadedPackage],
    targets: &[DownloadTarget],
    db_path: &Path,
    gpg_dir: &Path,
) -> Result<Vec<PreparedArchive>> {
    let mut by_name = BTreeMap::new();
    for package in downloaded {
        if by_name.insert(package.name.as_str(), package).is_some() {
            return Err(invalid(
                &package.path,
                format!("duplicate downloaded package {}", package.name),
            ));
        }
    }
    let mut names = BTreeSet::new();
    for target in targets {
        if !names.insert(target.name.as_str()) {
            return Err(invalid(
                db_path,
                format!("duplicate download target {}", target.name),
            ));
        }
        if !by_name.contains_key(target.name.as_str()) {
            return Err(invalid(
                db_path,
                format!("missing download for target {}", target.name),
            ));
        }
    }
    for package in downloaded {
        if !names.contains(package.name.as_str()) {
            return Err(invalid(
                &package.path,
                format!("extra downloaded package {}", package.name),
            ));
        }
    }
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    eprintln!(
        ":: Preparing and verifying {} archive copies...",
        targets.len()
    );
    let progress = ProgressBar::new(targets.len() as u64);
    progress.set_style(
        ProgressStyle::with_template(" {spinner:.green} {msg} [{pos}/{len}]")
            .expect("constant progress template"),
    );
    progress.enable_steady_tick(Duration::from_millis(100));
    let mut prepared = Vec::with_capacity(targets.len());
    for target in targets {
        let package = by_name[target.name.as_str()];
        progress.set_message(format!("Preparing {}", target.name));
        let result = PreparedArchive::prepare(
            &package.path,
            db_path,
            gpg_dir,
            ArchivePolicy {
                expected_sha256: target.expected_sha256.clone(),
                sig_level: target.sig_level,
                sig_trust: target.sig_trust,
            },
        )
        .and_then(|archive| {
            if archive.name() != target.name {
                return Err(invalid(
                    &package.path,
                    format!(
                        "package metadata names {}, expected target {}",
                        archive.name(),
                        target.name
                    ),
                ));
            }
            Ok(archive)
        });
        match context(
            &format!("prepare downloaded package {}", target.name),
            &package.path,
            result,
        ) {
            Ok(archive) => prepared.push(archive),
            Err(error) => {
                progress.abandon_with_message(format!("Preparing {} failed", target.name));
                return Err(error);
            }
        }
        progress.inc(1);
    }
    progress.finish_with_message("Archives prepared");
    Ok(prepared)
}

struct Source {
    supplied: PathBuf,
    canonical: PathBuf,
    file: File,
    metadata: Metadata,
}

impl Source {
    fn open(path: &Path) -> Result<Self> {
        let canonical = context("resolve source", path, fs::canonicalize(path))?;
        let before = context(
            "inspect source endpoint",
            path,
            fs::symlink_metadata(&canonical),
        )?;
        if !before.is_file() {
            return Err(invalid(path, "source endpoint is not a regular file"));
        }
        let file = context("open source endpoint", path, open_file(&canonical))?;
        let metadata = context("inspect opened source", path, file.metadata())?;
        if !metadata.is_file() || !same_metadata(&before, &metadata) {
            return Err(invalid(path, "source endpoint changed while opening"));
        }
        Ok(Self {
            supplied: path.to_path_buf(),
            canonical,
            file,
            metadata,
        })
    }

    fn check_unchanged(&self) -> Result<()> {
        context(
            "check source stability",
            &self.supplied,
            unchanged(&self.canonical, &self.file, &self.metadata),
        )?;
        let current = context(
            "resolve source again",
            &self.supplied,
            fs::canonicalize(&self.supplied),
        )?;
        if current != self.canonical {
            return Err(invalid(
                &self.supplied,
                "source symlink target changed while copying",
            ));
        }
        Ok(())
    }

    fn copy_to(&mut self, destination: &Path) -> Result<CopyProof> {
        let mut output = context("create archive copy", destination, new_file(destination))?;
        let digest = context(
            &format!("copy source {}", self.supplied.display()),
            destination,
            transfer(&mut self.file, self.metadata.len(), |bytes| {
                output.write_all(bytes)
            }),
        )?;
        self.check_unchanged()?;
        context(
            "make archive copy read-only",
            destination,
            output.set_permissions(fs::Permissions::from_mode(0o400)),
        )?;
        context("sync archive copy", destination, output.sync_all())?;
        Ok(CopyProof {
            size: self.metadata.len(),
            sha256: digest,
        })
    }
}

fn staged_filename(canonical: &Path) -> &'static str {
    let name = canonical.file_name().unwrap_or_default().as_bytes();
    if name.ends_with(b".zst") {
        FILENAMES[0]
    } else if name.ends_with(b".xz") {
        FILENAMES[1]
    } else if name.ends_with(b".gz") {
        FILENAMES[2]
    } else {
        FILENAMES[3]
    }
}

fn signature_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".sig");
    PathBuf::from(name)
}

fn open_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn new_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn canonical_database(path: &Path) -> Result<PathBuf> {
    // Reject a direct DBPath symlink before canonicalization hides it.
    open_directory(path, false)?;
    let canonical = context("canonicalize database", path, fs::canonicalize(path))?;
    open_directory(&canonical, false)?;
    Ok(canonical)
}

fn create_private_directory(path: &Path) -> Result<File> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return context("create private directory", path, Err(error)),
    }
    open_directory(path, true)
}

fn open_directory(path: &Path, private: bool) -> Result<File> {
    let file = context(
        "open directory without following symlinks",
        path,
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path),
    )?;
    let metadata = context("inspect directory", path, file.metadata())?;
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
        || (private && metadata.mode() & 0o7777 != 0o700)
    {
        return Err(invalid(
            path,
            "directory must be euid-owned, not group/world writable, and private staging directories must be 0700",
        ));
    }
    Ok(file)
}

fn same_device(directory: &File, path: &Path, device: u64) -> Result<()> {
    if context("inspect directory device", path, directory.metadata())?.dev() != device {
        return Err(invalid(
            path,
            "prepared storage must use the database filesystem",
        ));
    }
    Ok(())
}

fn check_space(
    database: &File,
    path: &Path,
    archive_size: u64,
    signature_size: u64,
    has_signature: bool,
) -> Result<()> {
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(database.as_raw_fd(), &mut stats) } != 0 {
        return context(
            "query database filesystem capacity",
            path,
            Err(io::Error::last_os_error()),
        );
    }
    let needed = u128::from(archive_size) + u128::from(signature_size) + u128::from(SPACE_HEADROOM);
    let available = u128::from(stats.f_bavail) * u128::from(stats.f_frsize);
    if available < needed {
        return Err(invalid(
            path,
            format!(
                "insufficient database filesystem space: need {needed} bytes including 16 MiB headroom, available {available}"
            ),
        ));
    }
    // Two directories, an archive, and optionally a signature. A filesystem
    // reporting f_files == 0 does not provide inode accounting.
    let needed_inodes = 3 + u64::from(has_signature);
    if stats.f_files != 0 && (stats.f_favail as u64) < needed_inodes {
        return Err(invalid(
            path,
            format!(
                "insufficient database filesystem inodes: need {needed_inodes}, available {}",
                stats.f_favail
            ),
        ));
    }
    Ok(())
}

fn same_metadata(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.nlink() == b.nlink()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

fn unchanged(path: &Path, file: &File, initial: &Metadata) -> Result<()> {
    let opened = context("inspect open file stability", path, file.metadata())?;
    let named = context(
        "inspect named file stability",
        path,
        fs::symlink_metadata(path),
    )?;
    if !same_metadata(initial, &opened) || !same_metadata(initial, &named) {
        return Err(invalid(
            path,
            "file identity, size or metadata changed during operation",
        ));
    }
    Ok(())
}

/// Read no more than the initial size plus one byte, even if an input grows.
fn transfer(
    file: &mut File,
    size: u64,
    mut consume: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<String> {
    let limit = size
        .checked_add(1)
        .ok_or_else(|| io::Error::other("file length cannot be bounded"))?;
    let mut reader = file.take(limit);
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    let mut total = 0u64;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > size {
            return Err(io::Error::other("file grew beyond its initial length"));
        }
        consume(&buffer[..count])?;
        digest.update(&buffer[..count]);
    }
    if total != size {
        return Err(io::Error::other(format!(
            "file shrank: expected {size} bytes, read {total}"
        )));
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn private_file(path: &Path, mode: u32) -> Result<(File, Metadata)> {
    let file = context("open private file", path, open_file(path))?;
    let metadata = context("inspect private file", path, file.metadata())?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != mode
        || metadata.nlink() != 1
    {
        return Err(invalid(
            path,
            format!("expected regular euid-owned {mode:04o} file with exactly one link"),
        ));
    }
    Ok((file, metadata))
}

fn verify_file(path: &Path, expected: &CopyProof) -> Result<()> {
    let (mut file, metadata) = private_file(path, 0o400)?;
    if expected.size != metadata.len() {
        return Err(invalid(
            path,
            "prepared file size differs from verified copy",
        ));
    }
    let actual = context(
        "hash prepared copy",
        path,
        transfer(&mut file, metadata.len(), |_| Ok(())),
    )?;
    unchanged(path, &file, &metadata)?;
    if actual != expected.sha256 {
        return Err(invalid(
            path,
            format!(
                "prepared SHA-256 mismatch: expected {}, got {actual}",
                expected.sha256
            ),
        ));
    }
    Ok(())
}

fn context<T, E: Display>(
    operation: &str,
    path: &Path,
    result: std::result::Result<T, E>,
) -> Result<T> {
    result.map_err(|error| invalid(path, format!("{operation}: {error}")))
}

fn invalid(path: &Path, message: impl Display) -> ExecError {
    io::Error::other(format!("prepared archive {}: {message}", path.display())).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::fs::symlink;
    use std::process::{Command, Output};

    #[test]
    fn compressed_oversized_metadata_is_rejected_before_preflight_allocation() {
        let env = Environment::new();
        let source = env.root().join("oversized.pkg.tar.gz");
        let gzip = flate2::write::GzEncoder::new(
            File::create(&source).unwrap(),
            flate2::Compression::fast(),
        );
        let mut archive = tar::Builder::new(gzip);
        let mut header = tar::Header::new_gnu();
        let size = crate::extract::PKGINFO_LIMIT + 1;
        header.set_size(size);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, ".PKGINFO", io::repeat(b' ').take(size))
            .unwrap();
        archive.into_inner().unwrap().finish().unwrap();
        assert!(source.metadata().unwrap().len() < crate::extract::PKGINFO_LIMIT);
        let error = env
            .prepare(
                &source,
                ArchivePolicy {
                    expected_sha256: None,
                    sig_level: SigLevel::Never,
                    sig_trust: SigTrust::TrustedOnly,
                },
            )
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("4 MiB"), "{error}");
        env.assert_no_copies();
    }

    struct Environment {
        temporary: TempDir,
        database: PathBuf,
        gpg: PathBuf,
    }

    impl Environment {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let database = temporary.path().join("database");
            let gpg = temporary.path().join("gpg");
            fs::create_dir(&database).unwrap();
            fs::create_dir(&gpg).unwrap();
            chmod(&database, 0o700);
            chmod(&gpg, 0o700);
            Self {
                temporary,
                database,
                gpg,
            }
        }

        fn root(&self) -> &Path {
            self.temporary.path()
        }

        fn prepare(&self, source: &Path, policy: ArchivePolicy) -> Result<PreparedArchive> {
            PreparedArchive::prepare(source, &self.database, &self.gpg, policy)
        }

        fn assert_no_copies(&self) {
            let top = self.database.join(DIRECTORY);
            match fs::read_dir(&top) {
                Ok(entries) => assert_eq!(entries.count(), 0),
                Err(error) => assert_eq!(error.kind(), io::ErrorKind::NotFound),
            }
        }
    }

    fn chmod(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn policy(level: SigLevel) -> ArchivePolicy {
        ArchivePolicy {
            expected_sha256: None,
            sig_level: level,
            sig_trust: SigTrust::TrustedOnly,
        }
    }

    fn failure<T>(result: Result<T>) -> String {
        match result {
            Ok(_) => panic!("expected operation to fail"),
            Err(error) => error.to_string(),
        }
    }

    fn package(path: &Path, name: &str) {
        let mut tar = tar::Builder::new(Vec::new());
        let pkginfo =
            format!("pkgname = {name}\npkgver = 1:2-3\narch = any\nsize = 7\ndepend = libc>=1\n");
        for (name, bytes) in [
            (".PKGINFO", pkginfo.as_bytes()),
            ("usr/share/prepared", b"payload".as_slice()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, name, bytes).unwrap();
        }
        let bytes = tar.into_inner().unwrap();
        let bytes = match path.extension().and_then(|ext| ext.to_str()) {
            Some("zst") => zstd::stream::encode_all(bytes.as_slice(), 1).unwrap(),
            Some("xz") => {
                let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
                encoder.write_all(&bytes).unwrap();
                encoder.finish().unwrap()
            }
            Some("gz") => {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                encoder.write_all(&bytes).unwrap();
                encoder.finish().unwrap()
            }
            _ => bytes,
        };
        fs::write(path, bytes).unwrap();
    }

    fn fifo(path: &Path) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(path.as_ptr(), 0o600) },
            0,
            "{}",
            io::Error::last_os_error()
        );
    }

    fn target(name: &str, archive: &Path) -> DownloadTarget {
        DownloadTarget {
            name: name.to_owned(),
            filename: archive.file_name().unwrap().to_string_lossy().into_owned(),
            expected_sha256: Some(crate::verify::compute_sha256(archive).unwrap()),
            compressed_size: fs::metadata(archive).unwrap().len(),
            mirrors: Vec::new(),
            sig_level: SigLevel::Optional,
            sig_trust: SigTrust::TrustedOnly,
        }
    }

    fn downloaded(name: &str, path: &Path) -> DownloadedPackage {
        DownloadedPackage {
            name: name.to_owned(),
            path: path.to_path_buf(),
        }
    }

    #[test]
    fn copy_is_private_independent_and_stable_after_original_changes() {
        let env = Environment::new();
        let source = env.root().join("original.pkg.tar.zst");
        package(&source, "snapshot");
        let bytes = fs::read(&source).unwrap();
        let expected = crate::verify::compute_sha256(&source).unwrap();
        let mut requested = policy(SigLevel::Optional);
        requested.expected_sha256 = Some(expected.clone());
        let prepared = env.prepare(&source, requested).unwrap();
        let path = prepared.path().to_path_buf();
        assert_eq!(prepared.source_path(), source);
        assert_eq!(prepared.name(), "snapshot");
        assert_eq!(prepared.info().version, "1:2-3");
        assert_eq!(prepared.info().installed_size, 7);
        assert_eq!(prepared.validations(), &[Validation::Sha256]);
        assert_eq!(prepared.archive.sha256, expected);
        assert_eq!(prepared.archive.size, bytes.len() as u64);
        let original = fs::metadata(&source).unwrap();
        let copy = fs::metadata(&path).unwrap();
        assert_ne!((original.dev(), original.ino()), (copy.dev(), copy.ino()));
        assert_eq!(copy.nlink(), 1);
        assert_eq!(copy.mode() & 0o7777, 0o400);
        assert_eq!(copy.uid(), unsafe { libc::geteuid() });
        for directory in [
            path.parent().unwrap(),
            path.parent().unwrap().parent().unwrap(),
        ] {
            assert_eq!(fs::metadata(directory).unwrap().mode() & 0o7777, 0o700);
        }
        let entries: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(entries, [path.clone()]);
        fs::write(&source, b"original replaced after preparation").unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        prepared.verify_for_database(&env.database).unwrap();
        fs::remove_file(&source).unwrap();
        prepared.verify_for_database(&env.database).unwrap();
        assert_eq!(prepared.info().name, "snapshot");
        drop(prepared);
        assert!(!path.parent().unwrap().exists());
        env.assert_no_copies();
    }

    #[test]
    fn staging_byte_tampering_is_rejected_even_with_original_length_and_mode() {
        let env = Environment::new();
        let source = env.root().join("original.pkg.tar");
        package(&source, "snapshot");
        let prepared = env.prepare(&source, policy(SigLevel::Never)).unwrap();
        let mut bytes = fs::read(prepared.path()).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        chmod(prepared.path(), 0o600);
        fs::write(prepared.path(), bytes).unwrap();
        chmod(prepared.path(), 0o400);
        assert!(failure(prepared.verify_for_database(&env.database)).contains("SHA-256 mismatch"));
    }

    #[test]
    fn suffix_comes_from_canonical_filename_not_source_alias() {
        let env = Environment::new();
        for (extension, expected) in [
            ("zst", FILENAMES[0]),
            ("xz", FILENAMES[1]),
            ("gz", FILENAMES[2]),
            ("other", FILENAMES[3]),
        ] {
            let source = env.root().join(format!("package.{extension}"));
            package(&source, "suffix");
            let alias = env.root().join(format!("alias-{extension}.pkg.tar.gz"));
            symlink(&source, &alias).unwrap();
            let prepared = env.prepare(&alias, policy(SigLevel::Never)).unwrap();
            assert_eq!(prepared.path().file_name().unwrap(), expected);
            assert_eq!(prepared.source_path(), alias);
            assert_eq!(prepared.name(), "suffix");
            prepared.verify_for_database(&env.database).unwrap();
        }
    }

    #[test]
    fn validation_evidence_reflects_only_checks_actually_performed() {
        let env = Environment::new();
        let source = env.root().join("package.pkg.tar");
        package(&source, "policy");
        for level in [SigLevel::Optional, SigLevel::Never] {
            let prepared = env.prepare(&source, policy(level)).unwrap();
            assert_eq!(prepared.validations(), &[Validation::None]);
            assert!(prepared.signature.is_none());
        }
        let error = failure(env.prepare(&source, policy(SigLevel::Required)));
        assert!(error.contains("required signature is missing"));
        assert!(error.contains(&source.display().to_string()));
        let mut requested = policy(SigLevel::Never);
        requested.expected_sha256 = Some("0".repeat(64));
        assert!(failure(env.prepare(&source, requested)).contains("checksum mismatch"));
        fs::write(&source, b"not an archive").unwrap();
        assert!(
            failure(env.prepare(&source, policy(SigLevel::Never)))
                .contains("read copied package metadata")
        );
        package(&source, "../invalid");
        assert!(env.prepare(&source, policy(SigLevel::Never)).is_err());
        env.assert_no_copies();
    }

    #[test]
    fn optional_rejects_present_unsafe_signatures_and_never_ignores_them() {
        for kind in [
            "directory",
            "fifo",
            "dangling",
            "oversized",
            "invalid",
            "unreadable",
        ] {
            if kind == "unreadable" && unsafe { libc::geteuid() } == 0 {
                continue; // Root can actually read a mode-000 regular file.
            }
            let env = Environment::new();
            let source = env.root().join("package.pkg.tar");
            package(&source, "signature");
            let signature = signature_path(&source);
            match kind {
                "directory" => fs::create_dir(&signature).unwrap(),
                "fifo" => fifo(&signature),
                "dangling" => symlink(env.root().join("missing"), &signature).unwrap(),
                "oversized" => File::create(&signature)
                    .unwrap()
                    .set_len(SIGNATURE_LIMIT + 1)
                    .unwrap(),
                "invalid" => fs::write(&signature, b"invalid signature").unwrap(),
                "unreadable" => {
                    fs::write(&signature, b"unreadable signature").unwrap();
                    chmod(&signature, 0);
                }
                _ => unreachable!(),
            }
            assert!(
                env.prepare(&source, policy(SigLevel::Optional)).is_err(),
                "{kind}"
            );
            env.assert_no_copies();
            let prepared = env.prepare(&source, policy(SigLevel::Never)).unwrap();
            assert_eq!(prepared.validations(), &[Validation::None]);
            assert!(prepared.signature.is_none());
            assert!(!signature_path(prepared.path()).exists());
        }
    }

    #[test]
    fn unsafe_sources_and_staging_roots_are_rejected() {
        for kind in ["directory", "fifo", "device", "dangling", "unreadable"] {
            if kind == "unreadable" && unsafe { libc::geteuid() } == 0 {
                continue;
            }
            let env = Environment::new();
            let source = env.root().join("source");
            match kind {
                "directory" => fs::create_dir(&source).unwrap(),
                "fifo" => fifo(&source),
                "device" => symlink("/dev/null", &source).unwrap(),
                "dangling" => symlink(env.root().join("missing"), &source).unwrap(),
                "unreadable" => {
                    package(&source, "unreadable");
                    chmod(&source, 0);
                }
                _ => unreachable!(),
            }
            assert!(
                env.prepare(&source, policy(SigLevel::Never)).is_err(),
                "{kind}"
            );
            env.assert_no_copies();
        }
        for kind in [
            "symlink", "file", "fifo", "public", "writable", "special", "owner",
        ] {
            if kind == "owner" && unsafe { libc::geteuid() } != 0 {
                continue;
            }
            let env = Environment::new();
            let source = env.root().join("source.pkg.tar");
            package(&source, "unsafe");
            let top = env.database.join(DIRECTORY);
            match kind {
                "symlink" => symlink(env.root(), &top).unwrap(),
                "file" => fs::write(&top, b"not a directory").unwrap(),
                "fifo" => fifo(&top),
                _ => {
                    fs::create_dir(&top).unwrap();
                    chmod(
                        &top,
                        match kind {
                            "public" => 0o755,
                            "writable" => 0o770,
                            "special" => 0o1700,
                            _ => 0o700,
                        },
                    );
                    if kind == "owner" {
                        let name = CString::new(top.as_os_str().as_bytes()).unwrap();
                        assert_eq!(unsafe { libc::chown(name.as_ptr(), 1, 1) }, 0);
                    }
                }
            }
            assert!(
                env.prepare(&source, policy(SigLevel::Never)).is_err(),
                "{kind}"
            );
        }
    }

    #[test]
    fn cleanup_only_removes_its_own_temporary_directory() {
        let env = Environment::new();
        let source = env.root().join("package.pkg.tar");
        package(&source, "cleanup");
        let top = env.database.join(DIRECTORY);
        create_private_directory(&top).unwrap();
        let existing = top.join("archive-existing");
        create_private_directory(&existing).unwrap();
        let old_data = existing.join("old-data");
        fs::write(&old_data, b"leave existing data untouched").unwrap();
        let prepared = env.prepare(&source, policy(SigLevel::Never)).unwrap();
        let directory = prepared.path().parent().unwrap().to_path_buf();
        drop(prepared);
        assert!(!directory.exists());
        assert!(env.prepare(&source, policy(SigLevel::Required)).is_err());
        assert_eq!(
            fs::read(&old_data).unwrap(),
            b"leave existing data untouched"
        );
        let entries: Vec<_> = fs::read_dir(&top)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(entries, [existing]);
        assert_eq!(fs::read_dir(&entries[0]).unwrap().count(), 1);
        assert_eq!(fs::metadata(&top).unwrap().mode() & 0o7777, 0o700);
    }

    #[test]
    fn private_storage_tampering_is_rejected() {
        for kind in [
            "archive_mode",
            "archive_link",
            "archive_symlink",
            "archive_fifo",
            "archive_size",
            "extra",
            "missing_archive",
            "directory_mode",
            "directory_symlink",
            "top_mode",
            "top_symlink",
        ] {
            let env = Environment::new();
            let source = env.root().join("package.pkg.tar");
            package(&source, "tamper");
            let prepared = env.prepare(&source, policy(SigLevel::Never)).unwrap();
            let directory = prepared.path().parent().unwrap();
            let victim = prepared.path();
            let outside = env.root().join("outside");
            match kind {
                "archive_mode" => chmod(victim, 0o644),
                "archive_link" => fs::hard_link(victim, &outside).unwrap(),
                "archive_symlink" => {
                    fs::rename(victim, &outside).unwrap();
                    symlink(&outside, victim).unwrap();
                }
                "archive_fifo" => {
                    fs::remove_file(victim).unwrap();
                    fifo(victim);
                }
                "archive_size" => {
                    chmod(victim, 0o600);
                    OpenOptions::new()
                        .write(true)
                        .open(victim)
                        .unwrap()
                        .set_len(prepared.archive.size + 1)
                        .unwrap();
                    chmod(victim, 0o400);
                }
                "extra" => fs::write(directory.join("extra"), b"unexpected").unwrap(),
                "missing_archive" => fs::remove_file(prepared.path()).unwrap(),

                "directory_mode" => chmod(directory, 0o755),
                "directory_symlink" => {
                    fs::rename(directory, &outside).unwrap();
                    symlink(&outside, directory).unwrap();
                }
                "top_mode" => chmod(&env.database.join(DIRECTORY), 0o755),
                "top_symlink" => {
                    let top = env.database.join(DIRECTORY);
                    fs::rename(&top, &outside).unwrap();
                    symlink(&outside, &top).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                prepared.verify_for_database(&env.database).is_err(),
                "{kind}"
            );
        }
    }

    #[test]
    fn expected_hash_policy_is_bounded_before_staging() {
        let env = Environment::new();
        let source = env.root().join("package.pkg.tar");
        package(&source, "policy");
        for expected in [
            String::new(),
            "0".repeat(63),
            "0".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            "0".repeat(1024 * 1024 + 1),
        ] {
            let mut requested = policy(SigLevel::Never);
            requested.expected_sha256 = Some(expected);
            let error = failure(env.prepare(&source, requested));
            assert!(error.contains("64 lowercase hexadecimal digits"), "{error}");
            assert!(error.len() < 1024);
            assert!(!env.database.join(DIRECTORY).exists());
        }
    }

    #[test]
    fn database_binding_rejects_moving_storage_and_replacing_database_inode() {
        for replace_inode in [false, true] {
            let env = Environment::new();
            let source = env.root().join("package.pkg.tar");
            package(&source, "bound");
            let prepared = env.prepare(&source, policy(SigLevel::Never)).unwrap();
            let other = env.root().join("other-db");
            let destination = if replace_inode {
                fs::rename(&env.database, &other).unwrap();
                fs::create_dir(&env.database).unwrap();
                chmod(&env.database, 0o700);
                fs::rename(other.join(DIRECTORY), env.database.join(DIRECTORY)).unwrap();
                env.database.clone()
            } else {
                fs::create_dir(&other).unwrap();
                chmod(&other, 0o700);
                fs::rename(env.database.join(DIRECTORY), other.join(DIRECTORY)).unwrap();
                other
            };
            assert!(
                failure(prepared.verify_for_database(&destination)).contains("database binding")
            );
        }
        let env = Environment::new();
        let source = env.root().join("package.pkg.tar");
        package(&source, "bound");
        let prepared = env.prepare(&source, policy(SigLevel::Never)).unwrap();
        let other = env.root().join("other-db");
        fs::create_dir(&other).unwrap();
        chmod(&other, 0o700);
        assert!(failure(prepared.verify_for_database(&other)).contains("database binding"));
        assert!(!other.join(DIRECTORY).exists());
        prepared.verify_for_database(&env.database).unwrap();
        let alias = env.root().join("db-alias");
        symlink(&env.database, &alias).unwrap();
        assert!(prepared.verify_for_database(&alias).is_err());
        assert!(
            PreparedArchive::prepare(&source, &alias, &env.gpg, policy(SigLevel::Never)).is_err()
        );
        chmod(&env.database, 0o777);
        assert!(prepared.verify_for_database(&env.database).is_err());
        assert!(env.prepare(&source, policy(SigLevel::Never)).is_err());
    }

    #[test]
    fn copy_rejects_source_growth_shrink_replacement_and_symlink_retargeting() {
        for change in ["grow", "shrink", "same_size", "replace", "retarget"] {
            let env = Environment::new();
            let path = env.root().join("source");
            fs::write(&path, b"original").unwrap();
            let alias = env.root().join("alias");
            symlink(&path, &alias).unwrap();
            let mut source = Source::open(&alias).unwrap();
            match change {
                "grow" => OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(b"more")
                    .unwrap(),
                "shrink" => fs::write(&path, b"short").unwrap(),
                "same_size" => {
                    fs::write(&path, b"modified").unwrap();
                    // Also change mode so this is deterministic on coarse timestamp filesystems.
                    chmod(&path, 0o400);
                }
                "replace" => {
                    fs::rename(&path, env.root().join("previous")).unwrap();
                    fs::write(&path, b"original").unwrap();
                }
                "retarget" => {
                    let other = env.root().join("other");
                    fs::write(&other, b"original").unwrap();
                    fs::remove_file(&alias).unwrap();
                    symlink(other, &alias).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                source.copy_to(&env.root().join("copy")).is_err(),
                "{change}"
            );
        }
    }

    #[test]
    fn filesystem_capacity_reservation_is_checked_without_overflow() {
        let env = Environment::new();
        let database = open_directory(&env.database, false).unwrap();
        assert!(
            failure(check_space(
                &database,
                &env.database,
                u64::MAX,
                SIGNATURE_LIMIT,
                true
            ))
            .contains("filesystem space")
        );
    }

    #[test]
    fn downloaded_packages_are_associated_by_exact_name_not_position() {
        let env = Environment::new();
        let one = env.root().join("one.pkg.tar");
        let two = env.root().join("two.pkg.tar.gz");
        package(&one, "one");
        package(&two, "two");
        let prepared = prepare_downloaded_packages(
            &[downloaded("two", &two), downloaded("one", &one)],
            &[target("one", &one), target("two", &two)],
            &env.database,
            &env.gpg,
        )
        .unwrap();
        assert_eq!(
            prepared
                .iter()
                .map(PreparedArchive::name)
                .collect::<Vec<_>>(),
            ["one", "two"]
        );
        assert_eq!(prepared[0].source_path(), one);
        assert_eq!(prepared[1].source_path(), two);
        for archive in &prepared {
            assert_eq!(archive.validations(), &[Validation::Sha256]);
            archive.verify_for_database(&env.database).unwrap();
        }
        drop(prepared);
        env.assert_no_copies();
    }

    #[test]
    fn invalid_download_associations_policies_and_metadata_fail_closed() {
        let env = Environment::new();
        let one = env.root().join("one.pkg.tar");
        let two = env.root().join("two.pkg.tar");
        package(&one, "one");
        package(&two, "two");
        for case in [
            "duplicate_download",
            "duplicate_target",
            "missing",
            "extra",
            "metadata",
            "checksum",
            "signature",
        ] {
            let mut downloads = vec![downloaded("one", &one), downloaded("two", &two)];
            let mut targets = vec![target("one", &one), target("two", &two)];
            match case {
                "duplicate_download" => downloads.push(downloaded("one", &one)),
                "duplicate_target" => targets.push(target("one", &one)),
                "missing" => {
                    downloads.pop();
                }
                "extra" => {
                    targets.pop();
                }
                "metadata" => {
                    downloads[1].path = one.clone();
                    targets[1].expected_sha256 = targets[0].expected_sha256.clone();
                }
                "checksum" => targets[1].expected_sha256 = Some("0".repeat(64)),
                "signature" => targets[1].sig_level = SigLevel::Required,
                _ => unreachable!(),
            }
            let error = failure(prepare_downloaded_packages(
                &downloads,
                &targets,
                &env.database,
                &env.gpg,
            ));
            assert!(
                error.contains("one") || error.contains("two"),
                "{case}: {error}"
            );
            env.assert_no_copies();
        }
        assert!(
            prepare_downloaded_packages(&[], &[], &env.database, &env.gpg)
                .unwrap()
                .is_empty()
        );
    }

    fn gpg(home: &Path) -> Command {
        let mut command = Command::new("gpg");
        command
            .args(["--no-options", "--batch", "--no-tty", "--homedir"])
            .arg(home);
        command
    }

    fn run(command: &mut Command) -> Output {
        let output = command
            .output()
            .expect("GPG is required for the signing regression");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    #[test]
    fn real_signatures_use_supplied_sidecar_exact_trust_and_copied_bytes() {
        let env = Environment::new();
        let signing = tempfile::tempdir().unwrap();
        run(gpg(signing.path()).args([
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            "Pax prepared regression <prepared@example.invalid>",
            "ed25519",
            "sign",
            "0",
        ]));
        let source = env.root().join("signed.pkg.tar.zst");
        package(&source, "signed");
        let signature = signature_path(&source);
        run(gpg(signing.path())
            .args([
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--output",
            ])
            .arg(&signature)
            .arg("--detach-sign")
            .arg(&source));
        let public = run(gpg(signing.path()).arg("--export")).stdout;
        let public_path = env.root().join("public.pgp");
        fs::write(&public_path, public).unwrap();
        run(gpg(&env.gpg).arg("--import").arg(&public_path));

        let alias = env.root().join("selected.pkg.tar.gz");
        symlink(&source, &alias).unwrap();
        assert!(
            failure(env.prepare(&alias, policy(SigLevel::Required)))
                .contains("required signature is missing")
        );
        let absent = env.prepare(&alias, policy(SigLevel::Optional)).unwrap();
        assert_eq!(absent.validations(), &[Validation::None]);
        drop(absent);
        symlink(&signature, signature_path(&alias)).unwrap();
        for level in [SigLevel::Required, SigLevel::Optional] {
            assert!(failure(env.prepare(&alias, policy(level))).contains("not trusted"));
            let mut requested = policy(level);
            requested.sig_trust = SigTrust::TrustAll;
            let prepared = env.prepare(&alias, requested).unwrap();
            assert_eq!(prepared.validations(), &[Validation::Pgp]);
            prepared.verify_for_database(&env.database).unwrap();
            let copy = fs::metadata(signature_path(prepared.path())).unwrap();
            let original = fs::metadata(&signature).unwrap();
            assert_ne!((copy.dev(), copy.ino()), (original.dev(), original.ino()));
            assert_eq!(copy.nlink(), 1);
            assert_eq!(copy.mode() & 0o7777, 0o400);
        }
        let trusted = PreparedArchive::prepare(
            &alias,
            &env.database,
            signing.path(),
            policy(SigLevel::Required),
        )
        .unwrap();
        assert_eq!(trusted.validations(), &[Validation::Pgp]);
        drop(trusted);
        let mut target = target("signed", &source);
        target.sig_level = SigLevel::Required;
        target.sig_trust = SigTrust::TrustAll;
        let prepared = prepare_downloaded_packages(
            &[downloaded("signed", &alias)],
            &[target],
            &env.database,
            &env.gpg,
        )
        .unwrap();
        let prepared = &prepared[0];
        assert_eq!(
            prepared.validations(),
            &[Validation::Sha256, Validation::Pgp]
        );
        assert!(prepared.signature.is_some());
        fs::write(&signature, b"broken original signature").unwrap();
        fs::write(&source, b"broken original archive").unwrap();
        fs::rename(&env.gpg, env.root().join("removed-keyring")).unwrap();
        prepared.verify_for_database(&env.database).unwrap();

        let staged_signature = signature_path(prepared.path());
        let original_bytes = fs::read(&staged_signature).unwrap();
        let mut modified = original_bytes.clone();
        modified[0] ^= 1;
        chmod(&staged_signature, 0o600);
        fs::write(&staged_signature, modified).unwrap();
        chmod(&staged_signature, 0o400);
        assert!(failure(prepared.verify_for_database(&env.database)).contains("SHA-256 mismatch"));
        chmod(&staged_signature, 0o600);
        fs::write(&staged_signature, original_bytes).unwrap();
        chmod(&staged_signature, 0o400);
        let link = env.root().join("signature-hardlink");
        fs::hard_link(&staged_signature, &link).unwrap();
        assert!(prepared.verify_for_database(&env.database).is_err());
        fs::remove_file(link).unwrap();
        prepared.verify_for_database(&env.database).unwrap();
        fs::remove_file(staged_signature).unwrap();
        assert!(prepared.verify_for_database(&env.database).is_err());
    }
}
