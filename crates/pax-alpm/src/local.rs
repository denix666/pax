use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use pax_core::error::{PaxError, Result};
use pax_core::package::{InstallReason, LocalPackage};
use pax_core::version::split_namever;

use crate::desc::{desc_to_local_package, parse_desc};
use crate::files::parse_files;

pub struct LocalDb {
    path: PathBuf,
    packages: HashMap<String, LocalPackage>,
}

impl LocalDb {
    pub fn open(db_path: &Path) -> Result<Self> {
        let local_path = db_path.join("local");
        if !local_path.is_dir() {
            return Err(PaxError::Database(format!(
                "local database not found at {}",
                local_path.display()
            )));
        }

        let entries: Vec<_> = std::fs::read_dir(&local_path)?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
            .collect();

        let parsed: Vec<_> = entries
            .par_iter()
            .filter_map(|entry| {
                let dir_name = entry.file_name();
                let dir_name = dir_name.to_string_lossy();
                split_namever(&dir_name)?;

                let desc_path = entry.path().join("desc");
                let content = std::fs::read_to_string(&desc_path).ok()?;
                let map = parse_desc(&content);
                let pkg = desc_to_local_package(&map).ok()?;
                Some((pkg.info.name.clone(), pkg))
            })
            .collect();

        let packages: HashMap<String, LocalPackage> = parsed.into_iter().collect();

        Ok(LocalDb {
            path: local_path,
            packages,
        })
    }

    pub fn packages(&self) -> impl Iterator<Item = &LocalPackage> {
        self.packages.values()
    }

    pub fn get(&self, name: &str) -> Option<&LocalPackage> {
        self.packages.get(name)
    }

    pub fn len(&self) -> usize {
        self.packages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    pub fn explicit_packages(&self) -> impl Iterator<Item = &LocalPackage> {
        self.packages
            .values()
            .filter(|p| p.reason == InstallReason::Explicit)
    }

    pub fn orphan_packages(&self) -> Vec<&LocalPackage> {
        let mut required: HashSet<&str> = HashSet::new();

        for pkg in self.packages.values() {
            for dep in &pkg.info.depends {
                required.insert(&dep.name);
            }
        }

        self.packages
            .values()
            .filter(|pkg| {
                if pkg.reason != InstallReason::Dependency {
                    return false;
                }
                if required.contains(pkg.info.name.as_str()) {
                    return false;
                }
                for prov in &pkg.info.provides {
                    if required.contains(prov.name.as_str()) {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    pub fn files_for(&self, name: &str) -> Result<Vec<String>> {
        let pkg = self
            .packages
            .get(name)
            .ok_or_else(|| PaxError::PackageNotFound(name.to_string()))?;

        let pkg_dir = format!("{}-{}", pkg.info.name, pkg.info.version);
        let files_path = self.path.join(&pkg_dir).join("files");

        if !files_path.exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(&files_path)?;
        let parsed = parse_files(&content);
        Ok(parsed.files)
    }

    pub fn find_owner(&self, file_path: &str) -> Result<Vec<(&LocalPackage, String)>> {
        let search_path = file_path.strip_prefix('/').unwrap_or(file_path);

        let pkg_dirs: Vec<_> = self
            .packages
            .values()
            .map(|pkg| {
                let dir_name = format!("{}-{}", pkg.info.name, pkg.info.version);
                (pkg, self.path.join(&dir_name).join("files"))
            })
            .collect();

        let results: Vec<_> = pkg_dirs
            .par_iter()
            .filter_map(|(pkg, files_path)| {
                let content = std::fs::read_to_string(files_path).ok()?;
                let parsed = parse_files(&content);
                for file in &parsed.files {
                    if file.strip_suffix('/').unwrap_or(file) == search_path
                        || file == search_path
                    {
                        return Some((*pkg, file.clone()));
                    }
                }
                None
            })
            .collect();

        Ok(results)
    }
}
