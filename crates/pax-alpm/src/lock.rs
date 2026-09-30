use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

pub struct DbLock {
    path: PathBuf,
    acquired: bool,
}

impl DbLock {
    pub fn acquire(db_path: &Path) -> std::io::Result<Self> {
        let path = db_path.join("db.lck");
        let mut notified = false;
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => {
                    eprintln!(":: Lock acquired.");
                    return Ok(Self { path, acquired: true });
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    if !notified {
                        eprintln!("{} is present.", path.display());
                        eprintln!("There may be another Pacman instance running. Waiting...");
                        notified = true;
                    }
                    thread::sleep(Duration::from_secs(1));
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
