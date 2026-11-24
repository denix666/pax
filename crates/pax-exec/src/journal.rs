//! Durable diagnostics, not rollback or proof of package/database consistency.
//!
//! The caller must hold the ALPM database lock for the lifetime of `Journal`.
//! Every existing active.json (including corrupt or unsupported data) blocks begin.
//! Dropping a Journal does nothing: an interrupted process leaves its last marker.
//! RootDir is trusted configuration; journal data is never executed or used to
//! select a different database. The canonical DBPath and its ancestors are trusted;
//! the database directory and journal directories themselves are checked below.

use std::ffi::CString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{ExecError, Result};

const VERSION: u32 = 1;
const MAX_RECORD_BYTES: u64 = 8 * 1024 * 1024;
const DIRECTORY: &str = "pax-transactions";
const ACTIVE: &str = "active.json";
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Preparing,
    Applying,
    Hooks,
    Completed,
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalRecord {
    pub version: u32,
    pub id: String,
    pub root: PathBuf,
    pub db_path: PathBuf,
    pub state: Phase,
    pub current_operation: Option<String>,
    pub planned_operations: Vec<String>,
    pub completed_operations: Vec<String>,
    pub failure: Option<String>,
}

pub struct Journal {
    directory: PathBuf,
    record: JournalRecord,
    archived: bool,
}

impl Journal {
    pub fn begin(db_path: &Path, root: &Path, operations: Vec<String>) -> Result<Self> {
        let db_path = canonical_database(db_path)?;
        let directory = db_path.join(DIRECTORY);
        let dir = create_private_directory(&directory)?;
        require_absent(&directory.join(ACTIVE))?;
        let root = context("canonicalize root", root, fs::canonicalize(root))?;
        if !context("inspect root", &root, fs::metadata(&root))?.is_dir() {
            return Err(invalid(&root, "root is not a directory"));
        }
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| invalid(&directory, format!("create transaction id: {error}")))?;
        let record = JournalRecord {
            version: VERSION,
            id: format!(
                "{:032x}-{:08x}-{:016x}",
                time.as_nanos(),
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed),
            ),
            root,
            db_path,
            state: Phase::Preparing,
            current_operation: None,
            planned_operations: operations,
            completed_operations: Vec::new(),
            failure: None,
        };
        write_record(&directory, &dir, &record, true)?;
        Ok(Self {
            directory,
            record,
            archived: false,
        })
    }

    /// Persist before starting the operation. Dynamic steps need not be in planned.
    /// A failed step may be followed by another intent; its failure is retained.
    pub fn intent(&mut self, phase: Phase, operation: &str) -> Result<()> {
        if !matches!(phase, Phase::Preparing | Phase::Applying | Phase::Hooks) {
            return Err(invalid(
                &self.directory,
                "intent requires a nonterminal phase",
            ));
        }
        if self.record.current_operation.is_some() && self.record.state != Phase::Interrupted {
            return Err(invalid(
                &self.directory,
                "previous intent has not been applied or failed",
            ));
        }
        let mut next = self.record.clone();
        next.state = phase;
        next.current_operation = Some(operation.to_string());
        self.persist(next)
    }

    /// Record an intent before entering code that can change the target system.
    /// On error the caller decides whether to stop or record a nonfatal failure.
    pub(crate) fn step<T>(
        &mut self,
        phase: Phase,
        operation: &str,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.intent(phase, operation)?;
        let result = action()?;
        self.applied(operation)?;
        Ok(result)
    }

    /// Acknowledges exactly the current intent, without asserting filesystem health.
    pub fn applied(&mut self, operation: &str) -> Result<()> {
        if self.record.current_operation.as_deref() != Some(operation) {
            return Err(invalid(
                &self.directory,
                "applied operation does not match current intent",
            ));
        }
        let mut next = self.record.clone();
        next.completed_operations.push(operation.to_string());
        next.current_operation = None;
        self.persist(next)
    }

    /// Retains the current intent and every supplied cause, including earlier ones.
    pub fn failure(&mut self, cause: &str) -> Result<()> {
        let mut next = self.record.clone();
        next.state = Phase::Interrupted;
        match &mut next.failure {
            Some(previous) => {
                previous.push('\n');
                previous.push_str(cause);
            }
            None => next.failure = Some(cause.to_string()),
        }
        self.persist(next)
    }

    /// Archives only a journal without failures or a pending intent.
    /// On a post-rename sync error, attempts to restore active without clobbering
    /// another entry. Recovery is best effort: an unwritable filesystem cannot
    /// guarantee a durable guard. The caller must retain the returned diagnostics.
    /// Success here means only that the journal writes/rename were synced.
    pub fn complete(&mut self) -> Result<()> {
        self.complete_with_sync(|_, directory| directory.sync_all())
    }

    // The closure permits narrowly injecting finalization/recovery sync failures
    // in unit tests; intent and record persistence still use real fsync.
    fn complete_with_sync(
        &mut self,
        mut sync: impl FnMut(&Path, &File) -> io::Result<()>,
    ) -> Result<()> {
        if self.record.failure.is_some() || self.record.state == Phase::Interrupted {
            return Err(invalid(
                &self.directory,
                "cannot complete an interrupted journal or one with recorded failures",
            ));
        }
        if self.record.current_operation.is_some() {
            return Err(invalid(
                &self.directory,
                "cannot complete an unacknowledged intent",
            ));
        }
        let dir = self.checked_active()?;
        let history_path = self.directory.join("history");
        let history = create_private_directory(&history_path)?;
        let active = self.directory.join(ACTIVE);
        let destination = history_path.join(format!("{}.json", self.record.id));
        require_absent(&destination)?;
        let mut next = self.record.clone();
        next.state = Phase::Completed;
        write_record(&self.directory, &dir, &next, false)?;
        self.record = next;
        context(
            "archive active record",
            &destination,
            rename_noreplace(&active, &destination),
        )?;
        // Persist the destination before the removal from the source directory.
        let synced = sync(&history_path, &history)
            .map_err(|error| (history_path.as_path(), error))
            .and_then(|()| {
                sync(&self.directory, &dir).map_err(|error| (self.directory.as_path(), error))
            });
        if let Err((path, error)) = synced {
            let mut cause = format!(
                "journal: sync directory {} after archive {} -> {}: {error}",
                path.display(),
                active.display(),
                destination.display(),
            );
            let restored = match rename_noreplace(&destination, &active) {
                Ok(()) => {
                    cause.push_str(&format!(
                        "\nrestored {} -> {} without replacing another entry",
                        destination.display(),
                        active.display(),
                    ));
                    true
                }
                Err(restore_error) => {
                    // Our record remains on the history side of the failed move;
                    // never let a later failure() overwrite an unrelated active.
                    self.archived = true;
                    cause.push_str(&format!(
                        "\nrestore {} -> {} failed: {restore_error}; recovery did not delete the history record; inspect both paths",
                        destination.display(), active.display(),
                    ));
                    false
                }
            };
            let mut recovery_synced = true;
            // After restoration active is the destination. Attempt both syncs,
            // even if restoration or its first sync failed, preserving all causes.
            for (path, directory) in [(&self.directory, &dir), (&history_path, &history)] {
                if let Err(sync_error) = sync(path, directory) {
                    recovery_synced = false;
                    cause.push_str(&format!(
                        "\nrecovery sync directory {} failed: {sync_error}",
                        path.display(),
                    ));
                }
            }
            if !restored || !recovery_synced {
                cause.push_str("\nactive guard/durability cannot be guaranteed; do not retry before inspecting the journal paths");
            }
            return Err(io::Error::new(error.kind(), cause).into());
        }
        self.archived = true;
        Ok(())
    }

    fn persist(&mut self, next: JournalRecord) -> Result<()> {
        let dir = self.checked_active()?;
        write_record(&self.directory, &dir, &next, false)?;
        self.record = next;
        Ok(())
    }

    fn checked_active(&self) -> Result<File> {
        if self.archived {
            return Err(invalid(
                &self.directory,
                format!(
                    "journal is no longer writable through {}; archive location: {} (archived or active restoration failed); inspect both paths if finalization failed",
                    self.directory.join(ACTIVE).display(),
                    self.directory
                        .join("history")
                        .join(format!("{}.json", self.record.id))
                        .display(),
                ),
            ));
        }
        context(
            "open database directory",
            &self.record.db_path,
            open_directory(&self.record.db_path, false),
        )?;
        let dir = context(
            "open journal directory",
            &self.directory,
            open_directory(&self.directory, true),
        )?;
        let current = read_record(&self.directory, &self.record.db_path)?;
        if current.as_ref() != Some(&self.record) {
            return Err(invalid(
                &self.directory,
                "active record is missing or has changed",
            ));
        }
        Ok(dir)
    }
}

/// Read-only inspection. None means no active entry; malformed, oversized,
/// unsupported or unsafe entries return Err, never None. Callers must fail closed.
pub fn inspect(db_path: &Path) -> Result<Option<JournalRecord>> {
    let db_path = canonical_database(db_path)?;
    let directory = db_path.join(DIRECTORY);
    match open_directory(&directory, true) {
        Ok(_) => read_record(&directory, &db_path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => context("open journal directory", &directory, Err(error)),
    }
}

fn canonical_database(path: &Path) -> Result<PathBuf> {
    // Check the configured endpoint before canonicalizing, so a direct DBPath
    // symlink cannot disappear into an otherwise safe-looking canonical path.
    context("open database directory", path, open_directory(path, false))?;
    let canonical = context("canonicalize database", path, fs::canonicalize(path))?;
    context(
        "open canonical database directory",
        &canonical,
        open_directory(&canonical, false),
    )?;
    Ok(canonical)
}

fn open_directory(path: &Path, private: bool) -> io::Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = directory.metadata()?;
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
        || (private && metadata.mode() & 0o7777 != 0o700)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "directory must be owned by euid, not group/world writable, and journal directories must have mode 0700",
        ));
    }
    Ok(directory)
}

fn create_private_directory(path: &Path) -> Result<File> {
    let created = match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => return context("create private directory", path, Err(error)),
    };
    let dir = context("open private directory", path, open_directory(path, true))?;
    if created {
        let parent = path
            .parent()
            .ok_or_else(|| invalid(path, "missing parent"))?;
        let parent_dir = context(
            "open parent directory",
            parent,
            open_directory(parent, false),
        )?;
        context("sync parent directory", parent, parent_dir.sync_all())?;
    }
    Ok(dir)
}

fn require_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "journal {}: entry already exists; inspect it before proceeding",
                path.display()
            ),
        )
        .into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => context("inspect existing entry", path, Err(error)),
    }
}

fn read_record(directory: &Path, db_path: &Path) -> Result<Option<JournalRecord>> {
    let path = directory.join(ACTIVE);
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return context("open active record", &path, Err(error)),
    };
    let metadata = context("inspect active record", &path, file.metadata())?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(invalid(
            &path,
            "active record must be a regular euid-owned 0600 file with one link",
        ));
    }
    if metadata.len() > MAX_RECORD_BYTES {
        return Err(invalid(&path, "active record exceeds 8 MiB"));
    }
    let mut bytes = Vec::new();
    context(
        "read active record",
        &path,
        file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes),
    )?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid(&path, "active record exceeds 8 MiB"));
    }
    let record: JournalRecord = serde_json::from_slice(&bytes)
        .map_err(|error| invalid(&path, format!("decode active record: {error}")))?;
    if record.version != VERSION {
        return Err(invalid(
            &path,
            format!("unsupported journal version {}", record.version),
        ));
    }
    if record.id.is_empty()
        || record.id.len() > 128
        || !record
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !record.root.is_absolute()
        || record.db_path != db_path
    {
        return Err(invalid(&path, "invalid id, root or database identity"));
    }
    Ok(Some(record))
}

fn write_record(directory: &Path, dir: &File, record: &JournalRecord, begin: bool) -> Result<()> {
    let active = directory.join(ACTIVE);
    let bytes = serde_json::to_vec_pretty(record)
        .map_err(|error| invalid(&active, format!("encode active record: {error}")))?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(invalid(&active, "active record exceeds 8 MiB"));
    }
    let mut temporary = context(
        "create temporary record",
        directory,
        tempfile::Builder::new()
            .prefix(".active-")
            .tempfile_in(directory),
    )?;
    context(
        "set record permissions",
        temporary.path(),
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600)),
    )?;
    context(
        "write temporary record",
        &active,
        temporary.write_all(&bytes),
    )?;
    context(
        "sync temporary record",
        temporary.path(),
        temporary.as_file().sync_all(),
    )?;
    let renamed = if begin {
        rename_noreplace(temporary.path(), &active)
    } else {
        fs::rename(temporary.path(), &active)
    };
    context("publish active record", &active, renamed)?;
    context("sync journal directory", directory, dir.sync_all())
}

// Linux renameat2 gives both begin and archival atomic no-clobber semantics.
// No copy fallback: EXDEV or unsupported filesystem semantics leave the source.
fn rename_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    let source = CString::new(source.as_os_str().as_bytes())?;
    let destination = CString::new(destination.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn context<T>(operation: &str, path: &Path, result: io::Result<T>) -> Result<T> {
    result.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("journal: {operation} {}: {error}", path.display()),
        )
        .into()
    })
}

fn invalid(path: &Path, message: impl std::fmt::Display) -> ExecError {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("journal {}: {message}", path.display()),
    )
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn paths() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("db");
        let root = temp.path().join("root");
        fs::create_dir(&db).unwrap();
        fs::create_dir(&root).unwrap();
        (temp, db, root)
    }

    fn begin(db: &Path, root: &Path) -> Journal {
        Journal::begin(db, root, vec!["install example".into()]).unwrap()
    }

    fn active(db: &Path) -> PathBuf {
        db.join(DIRECTORY).join(ACTIVE)
    }

    fn history(db: &Path, id: &str) -> PathBuf {
        db.join(DIRECTORY)
            .join("history")
            .join(format!("{id}.json"))
    }

    #[test]
    fn restart_keeps_intent_and_blocks_another_begin() {
        let (_temp, db, root) = paths();
        assert!(inspect(&db).unwrap().is_none());
        assert!(!db.join(DIRECTORY).exists());
        let mut journal = begin(&db, &root.join("."));
        let prepared = inspect(&db).unwrap().unwrap();
        assert_eq!(prepared.version, 1);
        assert_eq!(prepared.state, Phase::Preparing);
        assert_eq!(prepared.root, root.canonicalize().unwrap());
        assert_eq!(prepared.db_path, db.canonicalize().unwrap());
        assert_eq!(prepared.planned_operations, ["install example"]);
        assert_eq!(
            fs::metadata(db.join(DIRECTORY)).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(active(&db)).unwrap().mode() & 0o777, 0o600);
        journal.intent(Phase::Applying, "install example").unwrap();
        let applying = inspect(&db).unwrap().unwrap();
        assert_eq!(applying.state, Phase::Applying);
        assert_eq!(
            applying.current_operation.as_deref(),
            Some("install example")
        );
        assert!(applying.completed_operations.is_empty());
        drop(journal);
        assert_eq!(inspect(&db).unwrap().unwrap(), applying);
        assert!(Journal::begin(&db, &root, vec![]).is_err());
        assert_eq!(inspect(&db).unwrap().unwrap(), applying);
    }

    #[test]
    fn applied_and_completed_markers_are_readable_and_archived() {
        let (_temp, db, root) = paths();
        let mut journal = begin(&db, &root);
        journal.intent(Phase::Applying, "install example").unwrap();
        journal.applied("install example").unwrap();
        let applied = inspect(&db).unwrap().unwrap();
        assert_eq!(applied.completed_operations, ["install example"]);
        assert!(applied.current_operation.is_none());
        journal.intent(Phase::Hooks, "post hooks").unwrap();
        assert_eq!(inspect(&db).unwrap().unwrap().state, Phase::Hooks);
        journal.applied("post hooks").unwrap();
        journal.complete().unwrap();
        assert!(inspect(&db).unwrap().is_none());
        let archived: JournalRecord =
            serde_json::from_slice(&fs::read(history(&db, &applied.id)).unwrap()).unwrap();
        assert_eq!(archived.state, Phase::Completed);
        assert_eq!(
            archived.completed_operations,
            ["install example", "post hooks"]
        );
        assert!(archived.failure.is_none());
        assert_eq!(
            fs::metadata(history(&db, &applied.id)).unwrap().mode() & 0o777,
            0o600
        );
        assert!(journal.failure("too late").is_err());
        assert!(journal.complete().is_err());
        assert!(Journal::begin(&db, &root, vec![]).is_ok());
    }

    #[test]
    fn failures_survive_continuation_and_block_completion() {
        let (_temp, db, root) = paths();
        let mut journal = begin(&db, &root);
        journal.intent(Phase::Applying, "install example").unwrap();
        journal
            .failure("example pre_install: exit status 42")
            .unwrap();
        let failed = inspect(&db).unwrap().unwrap();
        assert!(journal.complete().is_err());
        assert_eq!(inspect(&db).unwrap().unwrap(), failed);
        assert!(!history(&db, &failed.id).exists());
        journal.intent(Phase::Hooks, "post hooks").unwrap();
        journal.failure("initramfs: no space left").unwrap();
        journal.intent(Phase::Hooks, "last hook").unwrap();
        journal.applied("last hook").unwrap();
        let continued = inspect(&db).unwrap().unwrap();
        assert!(continued.current_operation.is_none());
        assert_eq!(continued.state, Phase::Hooks);
        assert_eq!(
            continued.failure.as_deref(),
            Some("example pre_install: exit status 42\ninitramfs: no space left")
        );
        assert!(journal.complete().is_err());
        assert_eq!(inspect(&db).unwrap().unwrap(), continued);
        assert!(!history(&db, &failed.id).exists());
        assert!(Journal::begin(&db, &root, vec![]).is_err());
    }

    #[test]
    fn interrupted_state_without_a_cause_cannot_be_archived() {
        let (_temp, db, root) = paths();
        let mut journal = begin(&db, &root);
        let mut interrupted = journal.record.clone();
        interrupted.state = Phase::Interrupted;
        journal.persist(interrupted.clone()).unwrap();
        assert!(journal.complete().is_err());
        assert_eq!(inspect(&db).unwrap().unwrap(), interrupted);
        assert!(!history(&db, &interrupted.id).exists());
    }

    #[test]
    fn finalization_sync_failure_restores_active_for_failure_recording() {
        for fail_at in [1, 2] {
            let (_temp, db, root) = paths();
            let mut journal = begin(&db, &root);
            journal.intent(Phase::Applying, "install example").unwrap();
            journal.applied("install example").unwrap();
            let id = journal.record.id.clone();
            let destination = history(&db, &id);
            let mut synced = Vec::new();
            let error = journal
                .complete_with_sync(|path, directory| {
                    synced.push(path.to_path_buf());
                    if synced.len() == fail_at {
                        assert!(!active(&db).exists());
                        assert!(destination.exists());
                        Err(io::Error::other("injected finalization sync failure"))
                    } else {
                        directory.sync_all()
                    }
                })
                .unwrap_err();
            let message = error.to_string();
            assert!(message.contains("injected finalization sync failure"));
            assert!(message.contains(&active(&db).display().to_string()));
            assert!(message.contains(&destination.display().to_string()));
            assert_eq!(
                &synced[fail_at..],
                &[db.join(DIRECTORY), db.join(DIRECTORY).join("history")]
            );
            assert!(!journal.archived);
            assert!(!destination.exists());
            let restored = inspect(&db).unwrap().unwrap();
            assert_eq!(restored.id, id);
            assert_eq!(restored.completed_operations, ["install example"]);
            assert!(Journal::begin(&db, &root, vec![]).is_err());
            journal.failure(&message).unwrap();
            let interrupted = inspect(&db).unwrap().unwrap();
            assert_eq!(interrupted.state, Phase::Interrupted);
            assert_eq!(interrupted.failure.as_deref(), Some(message.as_str()));
            assert!(journal.complete().is_err());
        }
    }

    #[test]
    fn restoration_does_not_clobber_active_or_discard_history() {
        let (_temp, db, root) = paths();
        let mut journal = begin(&db, &root);
        let destination = history(&db, &journal.record.id);
        let mut calls = 0;
        let error = journal
            .complete_with_sync(|_, directory| {
                calls += 1;
                if calls == 1 {
                    let mut other = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(active(&db))
                        .unwrap();
                    other.write_all(b"another diagnosis").unwrap();
                    other.sync_all().unwrap();
                    Err(io::Error::other(
                        "injected sync failure with active collision",
                    ))
                } else {
                    directory.sync_all()
                }
            })
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("injected sync failure with active collision"));
        assert!(message.contains("restore"));
        assert!(message.contains("failed:"));
        assert!(message.contains(&active(&db).display().to_string()));
        assert!(message.contains(&destination.display().to_string()));
        assert!(message.contains("guard/durability cannot be guaranteed"));
        assert_eq!(calls, 3);
        assert!(journal.archived);
        let archived = fs::read(&destination).unwrap();
        let record: JournalRecord = serde_json::from_slice(&archived).unwrap();
        assert_eq!(record.id, journal.record.id);
        let failure = journal.failure(&message).unwrap_err().to_string();
        assert!(failure.contains(&destination.display().to_string()));
        assert_eq!(fs::read(&destination).unwrap(), archived);
        assert_eq!(fs::read(active(&db)).unwrap(), b"another diagnosis");
    }

    #[test]
    fn recovery_sync_errors_preserve_original_cause_and_both_sync_attempts() {
        let (_temp, db, root) = paths();
        let mut journal = begin(&db, &root);
        let destination = history(&db, &journal.record.id);
        let mut calls = 0;
        let error = journal
            .complete_with_sync(|_, _| {
                calls += 1;
                Err(io::Error::other(format!("injected sync failure {calls}")))
            })
            .unwrap_err();
        let message = error.to_string();
        assert_eq!(calls, 3);
        for failure in 1..=3 {
            assert!(message.contains(&format!("injected sync failure {failure}")));
        }
        assert!(message.contains(&active(&db).display().to_string()));
        assert!(message.contains(&destination.display().to_string()));
        assert!(message.contains("guard/durability cannot be guaranteed"));
        assert!(inspect(&db).unwrap().is_some());
        assert!(!destination.exists());
        assert!(!journal.archived);
        assert!(Journal::begin(&db, &root, vec![]).is_err());
    }

    #[test]
    fn invalid_transitions_and_replaced_records_do_not_overwrite_diagnostics() {
        let (_temp, db, root) = paths();
        let mut journal = begin(&db, &root);
        assert!(journal.intent(Phase::Completed, "bad").is_err());
        assert!(journal.intent(Phase::Interrupted, "bad").is_err());
        journal.intent(Phase::Applying, "install example").unwrap();
        assert!(journal.applied("different step").is_err());
        assert!(journal.intent(Phase::Hooks, "premature").is_err());
        assert!(journal.complete().is_err());
        let mut altered = inspect(&db).unwrap().unwrap();
        altered.current_operation = Some("external change".into());
        fs::write(active(&db), serde_json::to_vec(&altered).unwrap()).unwrap();
        assert!(journal.failure("must not overwrite").is_err());
        assert_eq!(inspect(&db).unwrap().unwrap(), altered);
    }

    #[test]
    fn corrupt_truncated_unsupported_and_oversized_active_records_block() {
        for kind in ["corrupt", "truncated", "version", "oversized"] {
            let (_temp, db, root) = paths();
            drop(begin(&db, &root));
            let bytes = match kind {
                "corrupt" => b"not json".to_vec(),
                "truncated" => b"{\"version\":1,".to_vec(),
                "version" => {
                    let mut record = inspect(&db).unwrap().unwrap();
                    record.version = 2;
                    serde_json::to_vec(&record).unwrap()
                }
                _ => vec![b' '; MAX_RECORD_BYTES as usize + 1],
            };
            fs::write(active(&db), &bytes).unwrap();
            assert!(inspect(&db).is_err(), "{kind}");
            assert!(Journal::begin(&db, &root, vec![]).is_err(), "{kind}");
            assert_eq!(fs::read(active(&db)).unwrap(), bytes);
        }
    }

    #[test]
    fn unsafe_symlinks_are_rejected_without_touching_targets() {
        for endpoint in ["database", "journal", "active", "history"] {
            let (temp, db, root) = paths();
            let outside = temp.path().join("outside");
            fs::create_dir(&outside).unwrap();
            let marker = outside.join("marker");
            fs::write(&marker, "keep").unwrap();
            match endpoint {
                "database" => {
                    let alias = temp.path().join("db-link");
                    symlink(&db, &alias).unwrap();
                    assert!(inspect(&alias).is_err());
                    assert!(Journal::begin(&alias, &root, vec![]).is_err());
                }
                "journal" => {
                    symlink(&outside, db.join(DIRECTORY)).unwrap();
                    assert!(inspect(&db).is_err());
                    assert!(Journal::begin(&db, &root, vec![]).is_err());
                }
                "active" => {
                    let mut journal = begin(&db, &root);
                    fs::remove_file(active(&db)).unwrap();
                    symlink(&marker, active(&db)).unwrap();
                    assert!(inspect(&db).is_err());
                    assert!(journal.failure("must not follow").is_err());
                    assert!(Journal::begin(&db, &root, vec![]).is_err());
                }
                _ => {
                    let mut journal = begin(&db, &root);
                    symlink(&outside, db.join(DIRECTORY).join("history")).unwrap();
                    assert!(journal.complete().is_err());
                    assert!(inspect(&db).unwrap().is_some());
                }
            }
            assert_eq!(fs::read_to_string(marker).unwrap(), "keep");
            assert_eq!(fs::read_dir(outside).unwrap().count(), 1);
        }
    }

    #[test]
    fn dangling_link_and_nonregular_active_are_not_absence() {
        let (_temp, db, root) = paths();
        drop(begin(&db, &root));
        fs::remove_file(active(&db)).unwrap();
        symlink("missing-target", active(&db)).unwrap();
        assert!(inspect(&db).is_err());
        assert!(Journal::begin(&db, &root, vec![]).is_err());
        fs::remove_file(active(&db)).unwrap();
        fs::create_dir(active(&db)).unwrap();
        assert!(inspect(&db).is_err());
        assert!(Journal::begin(&db, &root, vec![]).is_err());
    }

    #[test]
    fn unsafe_permissions_and_hardlinked_active_are_rejected() {
        for (endpoint, mode) in [
            ("database", 0o775),
            ("journal", 0o770),
            ("active", 0o660),
            ("active", 0o644),
        ] {
            let (_temp, db, root) = paths();
            let mut journal = begin(&db, &root);
            let path = match endpoint {
                "database" => db.clone(),
                "journal" => db.join(DIRECTORY),
                _ => active(&db),
            };
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(inspect(&db).is_err());
            assert!(journal.failure("must not write").is_err());
            assert!(Journal::begin(&db, &root, vec![]).is_err());
        }
        let (temp, db, root) = paths();
        let mut journal = begin(&db, &root);
        fs::hard_link(active(&db), temp.path().join("hardlink")).unwrap();
        assert!(inspect(&db).is_err());
        assert!(journal.failure("must not write").is_err());
    }

    #[test]
    fn wrong_owner_is_rejected_when_chown_is_available() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        for endpoint in ["journal", "active"] {
            let (_temp, db, root) = paths();
            let mut journal = begin(&db, &root);
            let path = if endpoint == "journal" {
                db.join(DIRECTORY)
            } else {
                active(&db)
            };
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe { libc::chown(path.as_ptr(), 1, libc::gid_t::MAX) },
                0
            );
            assert!(inspect(&db).is_err());
            assert!(journal.failure("must not write").is_err());
        }
    }

    #[test]
    fn history_collision_preserves_active_and_existing_diagnosis() {
        let (_temp, db, root) = paths();
        let mut journal = begin(&db, &root);
        let record = inspect(&db).unwrap().unwrap();
        create_private_directory(&db.join(DIRECTORY).join("history")).unwrap();
        let destination = history(&db, &record.id);
        fs::write(&destination, "existing diagnosis").unwrap();
        assert!(journal.complete().is_err());
        assert_eq!(inspect(&db).unwrap().unwrap(), record);
        assert_eq!(
            fs::read_to_string(destination).unwrap(),
            "existing diagnosis"
        );
    }

    #[test]
    fn oversized_update_keeps_the_previous_intent() {
        let (_temp, db, root) = paths();
        let mut journal = begin(&db, &root);
        journal.intent(Phase::Applying, "install example").unwrap();
        let before = inspect(&db).unwrap().unwrap();
        assert!(
            journal
                .failure(&"x".repeat(MAX_RECORD_BYTES as usize))
                .is_err()
        );
        assert_eq!(inspect(&db).unwrap().unwrap(), before);
    }
}
