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
    haystack
        .windows(needle_lower.len())
        .any(|w| w.iter().zip(needle_lower).all(|(h, n)| h.to_ascii_lowercase() == *n))
}

impl SyncDb {
    pub fn open(db_path: &Path, repos: &[Repository]) -> Result<Self> {
        let sync_path = db_path.join("sync");

        let repo_dbs: Vec<_> = repos
            .par_iter()
            .filter_map(|repo| {
                let db_file = sync_path.join(format!("{}.db", repo.name));
                if !db_file.exists() {
                    return None;
                }
                Self::read_repo_db(&db_file, &repo.name).ok()
            })
            .collect();

        Ok(SyncDb { repos: repo_dbs })
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
            let mut entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let is_desc = entry.path_bytes().ends_with(b"/desc");

            if is_desc {
                let mut content = String::new();
                if entry.read_to_string(&mut content).is_ok() {
                    desc_entries.push(content);
                }
            }
        }

        let packages: HashMap<String, SyncPackage> = desc_entries
            .par_iter()
            .filter_map(|content| {
                let map = parse_desc(content);
                let pkg = desc_to_sync_package(&map, repo_name).ok()?;
                Some((pkg.info.name.clone(), pkg))
            })
            .collect();

        Ok(RepoDb {
            name: repo_name.to_string(),
            packages,
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

    pub fn find_single(db_path: &Path, repos: &[Repository], name: &str) -> Result<Option<SyncPackage>> {
        let sync_path = db_path.join("sync");
        let prefix = format!("{name}-");

        for repo in repos {
            let db_file = sync_path.join(format!("{}.db", repo.name));
            if !db_file.exists() {
                continue;
            }

            let compressed = std::fs::read(&db_file)?;
            let mut decoder = GzDecoder::new(&compressed[..]);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| PaxError::Database(e.to_string()))?;

            let mut archive = tar::Archive::new(&decompressed[..]);

            for entry in archive.entries().map_err(|e| PaxError::Database(e.to_string()))? {
                let mut entry = match entry {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                let entry_path = match entry.path() {
                    Ok(p) => p.to_path_buf(),
                    Err(_) => continue,
                };

                let path_str = entry_path.to_string_lossy();
                if !path_str.ends_with("/desc") {
                    continue;
                }
                if let Some(dir) = path_str.strip_suffix("/desc") {
                    if !dir.starts_with(&prefix) {
                        continue;
                    }
                }

                let mut content = String::new();
                if entry.read_to_string(&mut content).is_ok() {
                    let map = parse_desc(&content);
                    if let Ok(pkg) = desc_to_sync_package(&map, &repo.name) {
                        if pkg.info.name == name {
                            return Ok(Some(pkg));
                        }
                    }
                }
            }
        }

        Ok(None)
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
