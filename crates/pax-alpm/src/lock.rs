use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

/// A diagnostic journal is not a stale-lock signal. Never discard it, even if
/// malformed, or let a fresh mutating command hide an interrupted transaction.
pub fn ensure_no_active_transaction(db_path: &Path) -> std::io::Result<()> {
    let directory = db_path.join("pax-transactions");
    match std::fs::symlink_metadata(&directory) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "unsafe transaction journal directory: {}",
                    directory.display()
                ),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    let active = directory.join("active.json");
    match std::fs::symlink_metadata(&active) {
        Ok(_) => Err(std::io::Error::new(
            ErrorKind::AlreadyExists,
            format!(
                "unfinished transaction journal {}; inspect with pax transaction-status using the same --config/--dbpath/--root; do not remove db.lck or retry before reconciling the system (automatic recovery is not available)",
                active.display()
            ),
        )),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub struct DbLock {
    path: PathBuf,
    acquired: bool,
}

impl DbLock {
    pub fn acquire(db_path: &Path) -> std::io::Result<Self> {
        Self::acquire_with_timeout(db_path, Duration::from_secs(30))
    }

    pub fn acquire_with_timeout(db_path: &Path, timeout: Duration) -> std::io::Result<Self> {
        ensure_no_active_transaction(db_path)?;
        std::fs::create_dir_all(db_path)?;
        let path = db_path.join("db.lck");
        let started = Instant::now();
        let mut notified = false;
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => {
                    if notified {
                        eprintln!(":: Lock acquired.");
                    }
                    let lock = Self {
                        path,
                        acquired: true,
                    };
                    // The preceding owner could have left a journal while we waited.
                    ensure_no_active_transaction(db_path)?;
                    return Ok(lock);
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    if !notified {
                        eprintln!("{} is present.", path.display());
                        eprintln!("There may be another Pacman instance running. Waiting...");
                        notified = true;
                    }
                    let remaining = timeout.saturating_sub(started.elapsed());
                    if remaining.is_zero() {
                        return Err(std::io::Error::new(
                            ErrorKind::TimedOut,
                            format!(
                                "timed out waiting for {}; check whether another package manager is running",
                                path.display()
                            ),
                        ));
                    }
                    thread::sleep(remaining.min(Duration::from_millis(100)));
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl Drop for DbLock {
    fn drop(&mut self) {
        if self.acquired {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn journal_blocks_even_with_missing_or_stale_lock() {
        use std::os::unix::fs::symlink;
        let directory =
            std::env::temp_dir().join(format!("pax-journal-lock-{}", std::process::id()));
        std::fs::create_dir_all(directory.join("pax-transactions")).unwrap();
        let active = directory.join("pax-transactions/active.json");
        std::fs::write(&active, "corrupt journal").unwrap();
        assert!(DbLock::acquire_with_timeout(&directory, Duration::ZERO).is_err());
        assert!(!directory.join("db.lck").exists());
        std::fs::write(directory.join("db.lck"), "previous owner").unwrap();
        assert!(DbLock::acquire_with_timeout(&directory, Duration::ZERO).is_err());
        assert_eq!(
            std::fs::read_to_string(directory.join("db.lck")).unwrap(),
            "previous owner"
        );
        std::fs::remove_file(&active).unwrap();
        symlink("missing", &active).unwrap();
        assert!(ensure_no_active_transaction(&directory).is_err());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn contention_times_out_without_removing_another_owners_lock() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "pax-lock-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let owner = DbLock::acquire(&directory).unwrap();
        let error = DbLock::acquire_with_timeout(&directory, Duration::ZERO)
            .err()
            .unwrap();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert!(directory.join("db.lck").exists());
        drop(owner);
        assert!(!directory.join("db.lck").exists());
        drop(DbLock::acquire_with_timeout(&directory, Duration::ZERO).unwrap());
        std::fs::remove_dir(directory).unwrap();
    }
}
