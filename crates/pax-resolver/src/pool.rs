use std::collections::{HashMap, HashSet};

use pax_core::package::PackageInfo;
use pax_core::version::Version;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PackageId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageSource {
    Local,
    Sync { repo_index: u16 },
}

pub struct PackageCandidate<'a> {
    pub id: PackageId,
    pub source: PackageSource,
    pub info: &'a PackageInfo,
}

pub trait PackagePool {
    fn candidates(&self, name: &str) -> Vec<PackageCandidate<'_>>;
    fn providers(&self, name: &str) -> Vec<PackageCandidate<'_>>;
    fn get(&self, id: PackageId) -> Option<PackageCandidate<'_>>;
    fn installed_version(&self, name: &str) -> Option<&Version>;
    fn all_installed(&self) -> Vec<PackageCandidate<'_>>;
    fn is_ignored(&self, name: &str) -> bool;
}

struct StoredPackage {
    source: PackageSource,
    info: PackageInfo,
}

pub struct ConcretePool {
    packages: Vec<StoredPackage>,
    name_index: HashMap<String, Vec<PackageId>>,
    provides_index: HashMap<String, Vec<PackageId>>,
    installed_versions: HashMap<String, Version>,
    ignored: HashSet<String>,
}

impl ConcretePool {
    pub fn new(ignored: HashSet<String>) -> Self {
        Self::with_capacity(ignored, 0)
    }

    pub fn with_capacity(ignored: HashSet<String>, capacity: usize) -> Self {
        ConcretePool {
            packages: Vec::with_capacity(capacity),
            name_index: HashMap::with_capacity(capacity),
            provides_index: HashMap::new(),
            installed_versions: HashMap::new(),
            ignored,
        }
    }

    pub fn add_local(&mut self, info: PackageInfo) -> PackageId {
        let id = PackageId(self.packages.len() as u32);
        self.installed_versions
            .insert(info.name.clone(), info.version.clone());
        self.register(&info, id);
        self.packages.push(StoredPackage {
            source: PackageSource::Local,
            info,
        });
        id
    }

    pub fn add_sync(&mut self, info: PackageInfo, repo_index: u16) -> PackageId {
        let id = PackageId(self.packages.len() as u32);
        self.register(&info, id);
        self.packages.push(StoredPackage {
            source: PackageSource::Sync { repo_index },
            info,
        });
        id
    }

    fn register(&mut self, info: &PackageInfo, id: PackageId) {
        self.name_index
            .entry(info.name.clone())
            .or_default()
            .push(id);

        for prov in &info.provides {
            self.provides_index
                .entry(prov.name.clone())
                .or_default()
                .push(id);
        }
    }

    fn make_candidate(&self, id: PackageId) -> PackageCandidate<'_> {
        let stored = &self.packages[id.0 as usize];
        PackageCandidate {
            id,
            source: stored.source,
            info: &stored.info,
        }
    }
}

impl PackagePool for ConcretePool {
    fn candidates(&self, name: &str) -> Vec<PackageCandidate<'_>> {
        let Some(ids) = self.name_index.get(name) else {
            return Vec::new();
        };
        let mut result: Vec<_> = ids.iter().map(|&id| self.make_candidate(id)).collect();
        result.sort_by_key(|c| match c.source {
            PackageSource::Local => (0, 0),
            PackageSource::Sync { repo_index } => (1, repo_index),
        });
        result
    }

    fn providers(&self, name: &str) -> Vec<PackageCandidate<'_>> {
        let Some(ids) = self.provides_index.get(name) else {
            return Vec::new();
        };
        let mut result: Vec<_> = ids.iter().map(|&id| self.make_candidate(id)).collect();
        result.sort_by_key(|c| match c.source {
            PackageSource::Local => (0, 0),
            PackageSource::Sync { repo_index } => (1, repo_index),
        });
        result
    }

    fn get(&self, id: PackageId) -> Option<PackageCandidate<'_>> {
        if (id.0 as usize) < self.packages.len() {
            Some(self.make_candidate(id))
        } else {
            None
        }
    }

    fn installed_version(&self, name: &str) -> Option<&Version> {
        self.installed_versions.get(name)
    }

    fn all_installed(&self) -> Vec<PackageCandidate<'_>> {
        self.packages
            .iter()
            .enumerate()
            .filter(|(_, s)| s.source == PackageSource::Local)
            .map(|(i, _)| self.make_candidate(PackageId(i as u32)))
            .collect()
    }

    fn is_ignored(&self, name: &str) -> bool {
        self.ignored.contains(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pax_core::package::Dependency;

    fn make_pkg(name: &str, ver: &str) -> PackageInfo {
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
            depends: vec![],
            optdepends: vec![],
            provides: vec![],
            conflicts: vec![],
            replaces: vec![],
            xdata: vec![],
        }
    }

    #[test]
    fn name_lookup() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("gcc", "14.1-1"), 0);
        pool.add_sync(make_pkg("glibc", "2.39-1"), 0);

        let cands = pool.candidates("gcc");
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].info.name, "gcc");

        assert!(pool.candidates("nonexistent").is_empty());
    }

    #[test]
    fn provides_lookup() {
        let mut pool = ConcretePool::new(HashSet::new());
        let mut bash = make_pkg("bash", "5.2-1");
        bash.provides = vec![Dependency::parse("sh").unwrap()];
        pool.add_sync(bash, 0);

        let providers = pool.providers("sh");
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].info.name, "bash");
    }

    #[test]
    fn local_preferred_over_sync() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("gcc", "14.1-1"));
        pool.add_sync(make_pkg("gcc", "14.2-1"), 0);

        let cands = pool.candidates("gcc");
        assert_eq!(cands.len(), 2);
        assert_eq!(cands[0].source, PackageSource::Local);
    }

    #[test]
    fn installed_version_tracking() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("gcc", "14.1-1"));

        assert!(pool.installed_version("gcc").is_some());
        assert!(pool.installed_version("glibc").is_none());
    }

    #[test]
    fn ignored_packages() {
        let ignored: HashSet<String> = ["linux"].iter().map(|s| s.to_string()).collect();
        let pool = ConcretePool::new(ignored);
        assert!(pool.is_ignored("linux"));
        assert!(!pool.is_ignored("gcc"));
    }

    #[test]
    fn repo_ordering() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("gcc", "14.1-1"), 2);
        pool.add_sync(make_pkg("gcc", "14.1-1"), 0);

        let cands = pool.candidates("gcc");
        assert_eq!(cands.len(), 2);
        assert_eq!(
            cands[0].source,
            PackageSource::Sync { repo_index: 0 }
        );
    }
}
