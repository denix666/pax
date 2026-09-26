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
