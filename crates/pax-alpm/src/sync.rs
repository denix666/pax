use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use flate2::read::GzDecoder;
use rayon::prelude::*;

use pax_core::config::Repository;
use pax_core::error::{PaxError, Result};
use pax_core::package::SyncPackage;

use crate::desc::{desc_to_sync_package, parse_desc};

pub struct RepoDb {
    pub name: String,
    pub packages: HashMap<String, SyncPackage>,
}

pub struct SyncDb {
    repos: Vec<RepoDb>,
}

fn contains_ci(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    if needle_lower.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle_lower.len()).any(|w| {
        w.iter()
            .zip(needle_lower)
            .all(|(h, n)| h.to_ascii_lowercase() == *n)
    })
}

impl SyncDb {
    pub fn open(db_path: &Path, repos: &[Repository]) -> Result<Self> {
        let sync_path = db_path.join("sync");

        let repo_dbs: Result<Vec<_>> = repos
            .par_iter()
            .map(|repo| {
                let db_file = sync_path.join(format!("{}.db", repo.name));
                Self::read_repo_db(&db_file, &repo.name).map_err(|e| {
                    PaxError::Database(format!(
                        "repository {} ({}): {e}",
                        repo.name,
                        db_file.display()
                    ))
                })
            })
            .collect();

        Ok(SyncDb { repos: repo_dbs? })
    }

    fn read_repo_db(path: &Path, repo_name: &str) -> Result<RepoDb> {
        let compressed = std::fs::read(path)?;
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::with_capacity(compressed.len() * 6);
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| PaxError::Database(e.to_string()))?;

        let mut archive = tar::Archive::new(&decompressed[..]);
        let mut desc_entries: Vec<String> = Vec::with_capacity(4096);

        for entry in archive
            .entries()
            .map_err(|e| PaxError::Database(e.to_string()))?
        {
            let mut entry = entry.map_err(|e| PaxError::Database(e.to_string()))?;

            let is_desc = entry.path_bytes().ends_with(b"/desc");

            if is_desc {
                let mut content = String::new();
                entry
                    .read_to_string(&mut content)
                    .map_err(|e| PaxError::Database(e.to_string()))?;
                desc_entries.push(content);
            }
        }

        let packages: Result<HashMap<String, SyncPackage>> = desc_entries
            .par_iter()
            .map(|content| {
                let map = parse_desc(content);
                let pkg = desc_to_sync_package(&map, repo_name)?;
                Ok((pkg.info.name.clone(), pkg))
            })
            .collect();

        Ok(RepoDb {
            name: repo_name.to_string(),
            packages: packages?,
        })
    }

    pub fn search(&self, query: &str) -> Vec<&SyncPackage> {
        let query_lower: Vec<u8> = query.bytes().map(|b| b.to_ascii_lowercase()).collect();

        let mut results: Vec<&SyncPackage> = self
            .repos
            .iter()
            .flat_map(|repo| {
                repo.packages.values().filter(|pkg| {
                    contains_ci(pkg.info.name.as_bytes(), &query_lower)
                        || contains_ci(pkg.info.description.as_bytes(), &query_lower)
                })
            })
            .collect();
        results.sort_unstable_by(|a, b| a.info.name.cmp(&b.info.name));
        results
    }

    pub fn get(&self, name: &str) -> Option<&SyncPackage> {
        for repo in &self.repos {
            if let Some(pkg) = repo.packages.get(name) {
                return Some(pkg);
            }
        }
        None
    }

    pub fn find_single(
        db_path: &Path,
        repos: &[Repository],
        name: &str,
    ) -> Result<Option<SyncPackage>> {
        let db = Self::open(db_path, repos)?;
        Ok(db.get(name).cloned())
    }

    pub fn all_packages(&self) -> impl Iterator<Item = &SyncPackage> {
        self.repos.iter().flat_map(|r| r.packages.values())
    }

    pub fn repos_iter(&self) -> impl Iterator<Item = &RepoDb> {
        self.repos.iter()
    }

    pub fn repo_count(&self) -> usize {
        self.repos.len()
    }

    pub fn package_count(&self) -> usize {
        self.repos.iter().map(|r| r.packages.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "pax-sync-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(path.join("sync")).unwrap();
            Self(path)
        }

        fn archive(&self, name: &str, desc: Option<&str>) {
            let file =
                std::fs::File::create(self.0.join("sync").join(format!("{name}.db"))).unwrap();
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);
            if let Some(content) = desc {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                archive
                    .append_data(&mut header, "app-1-1/desc", content.as_bytes())
                    .unwrap();
            }
            archive
                .into_inner()
                .unwrap()
                .finish()
                .unwrap()
                .flush()
                .unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn repository(name: &str) -> Repository {
        Repository {
            name: name.into(),
            servers: vec![],
            sig_level: None,
        }
    }

    #[test]
    fn configured_missing_repository_is_an_error() {
        let fixture = Fixture::new();
        let repos = [repository("missing")];
        let error = SyncDb::open(&fixture.0, &repos).err().unwrap().to_string();
        assert!(error.contains("missing"));
        assert!(SyncDb::find_single(&fixture.0, &repos, "app").is_err());
    }

    #[test]
    fn corrupt_repository_and_invalid_package_are_errors() {
        let fixture = Fixture::new();
        let repos = [repository("broken")];
        std::fs::write(fixture.0.join("sync/broken.db"), b"not gzip").unwrap();
        assert!(SyncDb::open(&fixture.0, &repos).is_err());
        fixture.archive("broken", Some("%NAME%\napp\n"));
        assert!(SyncDb::open(&fixture.0, &repos).is_err());
    }

    #[test]
    fn empty_repositories_preserve_configured_indices() {
        let fixture = Fixture::new();
        fixture.archive("first", None);
        fixture.archive("second", None);
        let db = SyncDb::open(&fixture.0, &[repository("first"), repository("second")]).unwrap();
        let names: Vec<_> = db.repos_iter().map(|repo| repo.name.as_str()).collect();
        assert_eq!(names, ["first", "second"]);
    }
}
