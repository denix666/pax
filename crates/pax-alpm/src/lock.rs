use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

pub struct DbLock {
    path: PathBuf,
    acquired: bool,
}

impl DbLock {
    pub fn acquire(db_path: &Path) -> std::io::Result<Self> {
        Self::acquire_with_timeout(db_path, Duration::from_secs(30))
    }

    pub fn acquire_with_timeout(db_path: &Path, timeout: Duration) -> std::io::Result<Self> {
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
                    return Ok(Self {
                        path,
                        acquired: true,
                    });
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
