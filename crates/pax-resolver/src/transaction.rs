use pax_core::version::Version;

use crate::pool::{PackagePool, PackageSource};
use crate::resolve::ResolvedSet;

#[derive(Debug, Clone)]
pub struct InstallAction {
    pub name: String,
    pub version: Version,
    pub repository: String,
    pub download_size: u64,
    pub installed_size: u64,
    pub explicit: bool,
}

#[derive(Debug, Clone)]
pub struct UpgradeAction {
    pub name: String,
    pub old_version: Version,
    pub new_version: Version,
    pub repository: String,
    pub download_size: u64,
    pub installed_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemovalReason {
    Replaced,
    Conflict { with: String },
}

#[derive(Debug, Clone)]
pub struct RemovalAction {
    pub name: String,
    pub version: Version,
    pub reason: RemovalReason,
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub installs: Vec<InstallAction>,
    pub upgrades: Vec<UpgradeAction>,
    pub removals: Vec<RemovalAction>,
    pub total_download_size: u64,
    pub total_installed_size: u64,
}

impl Transaction {
    pub fn is_empty(&self) -> bool {
        self.installs.is_empty() && self.upgrades.is_empty() && self.removals.is_empty()
    }
}

pub fn build_transaction<P: PackagePool>(
    pool: &P,
    resolved: &ResolvedSet,
    targets: &[String],
    sync_sizes: &dyn Fn(&str) -> (u64, u64),
    reinstall: bool,
) -> Transaction {
    let target_set: std::collections::HashSet<&str> =
        targets.iter().map(|s| s.as_str()).collect();

    let mut installs = Vec::new();
    let mut upgrades = Vec::new();
    let mut total_download: u64 = 0;
    let mut total_installed: u64 = 0;

    for pkg in &resolved.to_install {
        let repo_name = match pkg.source {
            PackageSource::Sync { repo_index } => format!("repo:{repo_index}"),
            PackageSource::Local => "local".to_string(),
        };

        let (dl_size, inst_size) = sync_sizes(&pkg.name);

        if let Some(installed_ver) = pool.installed_version(&pkg.name) {
            let dominated = pkg.version > *installed_ver;
            let same = pkg.version == *installed_ver;
            if dominated || (same && reinstall && target_set.contains(pkg.name.as_str())) {
                total_download += dl_size;
                total_installed += inst_size;
                upgrades.push(UpgradeAction {
                    name: pkg.name.clone(),
                    old_version: installed_ver.clone(),
                    new_version: pkg.version.clone(),
                    repository: repo_name,
                    download_size: dl_size,
                    installed_size: inst_size,
                });
            }
        } else {
            total_download += dl_size;
            total_installed += inst_size;
            installs.push(InstallAction {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                repository: repo_name,
                download_size: dl_size,
                installed_size: inst_size,
                explicit: target_set.contains(pkg.name.as_str()),
            });
        }
    }

    let mut removals = Vec::new();
    for (name, reason) in &resolved.to_remove {
        let version = pool
            .installed_version(name)
            .cloned()
            .unwrap_or_else(|| Version::parse("0-0").unwrap());
        removals.push(RemovalAction {
            name: name.clone(),
            version,
            reason: reason.clone(),
        });
    }

    Transaction {
        installs,
        upgrades,
        removals,
        total_download_size: total_download,
        total_installed_size: total_installed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::ConcretePool;
    use crate::resolve::{resolve, ResolveOptions};
    use pax_core::package::{Dependency, PackageInfo};
    use pax_core::version::Version;
    use std::collections::HashSet;

    fn make_pkg(name: &str, ver: &str, deps: &[&str]) -> PackageInfo {
        PackageInfo {
            name: name.to_string(),
            version: Version::parse(ver).unwrap(),
            base: None,
            description: String::new(),
            url: None,
            arch: "x86_64".to_string(),
            build_date: 0,
            packager: String::new(),
            licenses: vec![],
            groups: vec![],
            depends: deps.iter().map(|d| Dependency::parse(d).unwrap()).collect(),
            optdepends: vec![],
            provides: vec![],
            conflicts: vec![],
            replaces: vec![],
            xdata: vec![],
        }
    }

    #[test]
    fn new_install_transaction() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("app", "1.0-1", &["lib"]), 0);
        pool.add_sync(make_pkg("lib", "1.0-1", &[]), 0);

        let resolved =
            resolve(&pool, &["app".to_string()], &ResolveOptions::default()).unwrap();
        let tx = build_transaction(&pool, &resolved, &["app".to_string()], &|_| (1000, 5000), false);

        assert_eq!(tx.installs.len(), 2);
        assert!(tx.upgrades.is_empty());

        let app_install = tx.installs.iter().find(|i| i.name == "app").unwrap();
        assert!(app_install.explicit);

        let lib_install = tx.installs.iter().find(|i| i.name == "lib").unwrap();
        assert!(!lib_install.explicit);
    }

    #[test]
    fn upgrade_transaction() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("app", "1.0-1", &[]));
        pool.add_sync(make_pkg("app", "2.0-1", &[]), 0);

        let resolved =
            resolve(&pool, &["app".to_string()], &ResolveOptions::default()).unwrap();
        let tx = build_transaction(&pool, &resolved, &["app".to_string()], &|_| (1000, 5000), false);

        assert!(tx.installs.is_empty());
        assert_eq!(tx.upgrades.len(), 1);
        assert_eq!(tx.upgrades[0].name, "app");
    }
}
