use pax_core::config::PacmanConfig;
use pax_core::error::Result;
use pax_core::package::{LocalPackage, SyncPackage};

use crate::local::LocalDb;
use crate::sync::SyncDb;

pub struct DatabaseHandle {
    pub config: PacmanConfig,
    local: Option<LocalDb>,
    sync: Option<SyncDb>,
}

impl DatabaseHandle {
    pub fn new(config: PacmanConfig) -> Self {
        DatabaseHandle {
            config,
            local: None,
            sync: None,
        }
    }

    /// Discard snapshots before planning under the database lock or after mutation.
    pub fn invalidate(&mut self) {
        self.local = None;
        self.sync = None;
    }

    pub fn local(&mut self) -> Result<&LocalDb> {
        if self.local.is_none() {
            self.local = Some(LocalDb::open(&self.config.db_path)?);
        }
        Ok(self.local.as_ref().unwrap())
    }

    pub fn sync(&mut self) -> Result<&SyncDb> {
        if self.sync.is_none() {
            self.sync = Some(SyncDb::open(&self.config.db_path, &self.config.repos)?);
        }
        Ok(self.sync.as_ref().unwrap())
    }

    pub fn ensure_both(&mut self) -> Result<()> {
        self.local()?;
        self.sync()?;
        Ok(())
    }

    pub fn search_sync(&mut self, query: &str) -> Result<Vec<&SyncPackage>> {
        self.sync()?;
        Ok(self.sync.as_ref().unwrap().search(query))
    }

    pub fn sync_info(&mut self, name: &str) -> Result<Option<&SyncPackage>> {
        self.sync()?;
        Ok(self.sync.as_ref().unwrap().get(name))
    }

    pub fn local_info(&mut self, name: &str) -> Result<Option<&LocalPackage>> {
        self.local()?;
        Ok(self.local.as_ref().unwrap().get(name))
    }

    pub fn is_installed(&self, name: &str) -> bool {
        self.local.as_ref().is_some_and(|db| db.get(name).is_some())
    }

    pub fn installed_packages(&mut self) -> Result<Vec<&LocalPackage>> {
        self.local()?;
        let local = self.local.as_ref().unwrap();
        let mut pkgs: Vec<_> = local.packages().collect();
        pkgs.sort_by(|a, b| a.info.name.cmp(&b.info.name));
        Ok(pkgs)
    }

    pub fn explicit_packages(&mut self) -> Result<Vec<&LocalPackage>> {
        self.local()?;
        let local = self.local.as_ref().unwrap();
        let mut pkgs: Vec<_> = local.explicit_packages().collect();
        pkgs.sort_by(|a, b| a.info.name.cmp(&b.info.name));
        Ok(pkgs)
    }

    pub fn orphan_packages(&mut self) -> Result<Vec<&LocalPackage>> {
        self.local()?;
        let local = self.local.as_ref().unwrap();
        let mut pkgs = local.orphan_packages();
        pkgs.sort_by(|a, b| a.info.name.cmp(&b.info.name));
        Ok(pkgs)
    }

    pub fn package_files(&mut self, name: &str) -> Result<Vec<String>> {
        self.local()?;
        self.local.as_ref().unwrap().files_for(name)
    }

    pub fn file_owner(&mut self, path: &str) -> Result<Vec<(&LocalPackage, String)>> {
        self.local()?;
        self.local.as_ref().unwrap().find_owner(path)
    }

    pub fn sync_packages_with_repo_index(&mut self) -> Result<Vec<(&SyncPackage, u16)>> {
        self.sync()?;
        let sync = self.sync.as_ref().unwrap();
        let mut result = Vec::new();
        for (repo_idx, repo) in sync.repos_iter().enumerate() {
            for pkg in repo.packages.values() {
                result.push((pkg, repo_idx as u16));
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn invalidation_reloads_installed_state() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "pax-db-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(directory.join("local")).unwrap();
        let mut config = PacmanConfig::default();
        config.db_path = directory.clone();
        let mut db = DatabaseHandle::new(config);
        assert!(db.installed_packages().unwrap().is_empty());
        let package = directory.join("local/app-1-1");
        std::fs::create_dir(&package).unwrap();
        std::fs::write(package.join("desc"), "%NAME%\napp\n\n%VERSION%\n1-1\n").unwrap();
        assert!(db.installed_packages().unwrap().is_empty());
        db.invalidate();
        assert_eq!(db.installed_packages().unwrap()[0].info.name, "app");
        std::fs::remove_dir_all(&package).unwrap();
        db.invalidate();
        assert!(db.installed_packages().unwrap().is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
