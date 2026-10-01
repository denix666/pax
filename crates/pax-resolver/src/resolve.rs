use std::collections::{HashMap, HashSet};

use pax_core::package::{Dependency, InstallReason};
use pax_core::version::Version;

use crate::error::{ResolveError, Result};
use crate::pool::{PackageCandidate, PackageId, PackagePool, PackageSource};
use crate::transaction::RemovalReason;

pub struct ResolveOptions {
    pub reinstall: bool,
}

impl Default for ResolveOptions {
    fn default() -> Self {
        ResolveOptions { reinstall: false }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedPackage {
    pub id: PackageId,
    pub name: String,
    pub version: Version,
    pub source: PackageSource,
    pub reason: InstallReason,
}

pub struct ResolvedSet {
    pub to_install: Vec<ResolvedPackage>,
    pub to_remove: Vec<(String, RemovalReason)>,
}

struct Resolver<'a, P: PackagePool> {
    pool: &'a P,
    options: &'a ResolveOptions,
    selected: HashMap<String, PackageId>,
    reasons: HashMap<String, InstallReason>,
    dep_chains: HashMap<String, Vec<String>>,
    in_progress: HashSet<String>,
    conflicts: Vec<(String, Dependency)>,
    replaces: Vec<(String, String, RemovalReason)>,
    targets: HashSet<String>,
}

pub fn resolve<P: PackagePool>(
    pool: &P,
    targets: &[String],
    options: &ResolveOptions,
) -> Result<ResolvedSet> {
    let mut resolver = Resolver {
        pool,
        options,
        selected: HashMap::new(),
        reasons: HashMap::new(),
        dep_chains: HashMap::new(),
        in_progress: HashSet::new(),
        conflicts: Vec::new(),
        replaces: Vec::new(),
        targets: targets.iter().cloned().collect(),
    };

    for target in targets {
        resolver.resolve_target(target, &[])?;
    }

    resolver.check_conflicts()?;
    Ok(resolver.into_resolved_set())
}

impl<'a, P: PackagePool> Resolver<'a, P> {
    fn resolve_target(&mut self, name: &str, chain: &[String]) -> Result<()> {
        if self.selected.contains_key(name) {
            return Ok(());
        }

        if self.in_progress.contains(name) {
            return Ok(());
        }

        if !self.options.reinstall {
            if self.pool.installed_version(name).is_some() && !self.targets.contains(name) {
                return Ok(());
            }
        }

        let candidates = self.pool.candidates(name);
        let candidate = if candidates.is_empty() {
            let providers = self.pool.providers(name);
            if providers.is_empty() {
                return Err(ResolveError::TargetNotFound {
                    name: name.to_string(),
                });
            }
            let provider_name = providers[0].info.name.clone();
            return self.resolve_target(&provider_name, chain);
        } else {
            self.pick_candidate(&candidates)
        };

        let pkg_name = candidate.info.name.clone();
        let pkg_id = candidate.id;
        let deps = candidate.info.depends.clone();
        let pkg_conflicts = candidate.info.conflicts.clone();
        let pkg_replaces = candidate.info.replaces.clone();

        let reason = if self.targets.contains(&pkg_name) {
            InstallReason::Explicit
        } else {
            InstallReason::Dependency
        };

        self.selected.insert(pkg_name.clone(), pkg_id);
        self.reasons.insert(pkg_name.clone(), reason);
        self.dep_chains.insert(pkg_name.clone(), chain.to_vec());
        self.in_progress.insert(pkg_name.clone());

        for conflict in pkg_conflicts {
            self.conflicts.push((pkg_name.clone(), conflict));
        }

        for replace in &pkg_replaces {
            if self.pool.installed_version(&replace.name).is_some() {
                self.replaces
                    .push((pkg_name.clone(), replace.name.clone(), RemovalReason::Replaced));
            }
        }

        let mut next_chain = chain.to_vec();
        next_chain.push(pkg_name.clone());

        for dep in &deps {
            self.resolve_dep(dep, &next_chain)?;
        }

        self.in_progress.remove(&pkg_name);
        Ok(())
    }

    fn resolve_dep(&mut self, dep: &Dependency, chain: &[String]) -> Result<()> {
        if let Some(installed_ver) = self.pool.installed_version(&dep.name) {
            if dep.satisfies(installed_ver) {
                return Ok(());
            }
        }

        if let Some(&id) = self.selected.get(&dep.name) {
            if let Some(candidate) = self.pool.get(id) {
                if dep.satisfies(&candidate.info.version) {
                    return Ok(());
                }
            }
        }

        if self.check_provides_satisfied(dep) {
            return Ok(());
        }

        let candidates = self.pool.candidates(&dep.name);
        if candidates.iter().any(|c| dep.satisfies(&c.info.version)) {
            return self.resolve_target(&dep.name, chain);
        }

        let providers = self.pool.providers(&dep.name);
        for provider in &providers {
            if self.provider_satisfies(provider, dep) {
                let name = provider.info.name.clone();
                return self.resolve_target(&name, chain);
            }
        }

        if let Some(installed_ver) = self.pool.installed_version(&dep.name) {
            return Err(ResolveError::VersionConflict {
                pkg: dep.name.clone(),
                installed: installed_ver.clone(),
                dep: dep.clone(),
                chain: chain.to_vec(),
            });
        }

        Err(ResolveError::DependencyNotFound {
            dep: dep.clone(),
            chain: chain.to_vec(),
        })
    }

    fn check_provides_satisfied(&self, dep: &Dependency) -> bool {
        for (_name, &id) in &self.selected {
            if let Some(candidate) = self.pool.get(id) {
                for prov in &candidate.info.provides {
                    if prov.name == dep.name {
                        if self.provider_satisfies(&candidate, dep) {
                            return true;
                        }
                    }
                }
            }
        }

        for pkg in self.pool.all_installed() {
            for prov in &pkg.info.provides {
                if prov.name == dep.name {
                    let candidate = PackageCandidate {
                        id: pkg.id,
                        source: pkg.source,
                        info: pkg.info,
                    };
                    if self.provider_satisfies(&candidate, dep) {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn provider_satisfies(&self, provider: &PackageCandidate, dep: &Dependency) -> bool {
        for prov in &provider.info.provides {
            if prov.name == dep.name {
                match (&dep.constraint, &prov.constraint) {
                    (None, _) => return true,
                    (Some(_), Some((_, prov_ver))) => {
                        if dep.satisfies(prov_ver) {
                            return true;
                        }
                    }
                    (Some(_), None) => {
                        if dep.satisfies(&provider.info.version) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn pick_candidate<'b>(&self, candidates: &[PackageCandidate<'b>]) -> PackageCandidate<'b>
    where
        'a: 'b,
    {
        let mut best: Option<&PackageCandidate<'b>> = None;
        for c in candidates {
            if matches!(c.source, PackageSource::Sync { .. }) {
                match best {
                    Some(prev) => {
                        if c.info.version > prev.info.version {
                            best = Some(c);
                        }
                    }
                    None => best = Some(c),
                }
            }
        }
        let c = best.unwrap_or(&candidates[0]);
        PackageCandidate {
            id: c.id,
            source: c.source,
            info: c.info,
        }
    }

    fn removal_blocker(&self, name: &str) -> Option<String> {
        if self.targets.contains(name) {
            return Some("explicit target".to_string());
        }
        let will_remove: HashSet<&str> = self
            .replaces
            .iter()
            .map(|(_, old, _)| old.as_str())
            .collect();
        for pkg in self.pool.all_installed() {
            if self.selected.contains_key(&pkg.info.name) {
                continue;
            }
            if will_remove.contains(pkg.info.name.as_str()) {
                continue;
            }
            for dep in &pkg.info.depends {
                if dep.name == name {
                    return Some(pkg.info.name.clone());
                }
            }
        }
        None
    }

    fn check_conflicts(&mut self) -> Result<()> {
        let conflicts: Vec<(String, Dependency)> = self.conflicts.clone();
        for (pkg_name, conflict) in &conflicts {
            let conflict_present = self.selected.get(&conflict.name)
                .and_then(|&id| self.pool.get(id))
                .map(|c| conflict.satisfies(&c.info.version))
                .unwrap_or(false)
                || self.pool.installed_version(&conflict.name)
                    .map(|v| conflict.satisfies(v))
                    .unwrap_or(false);

            if conflict_present && conflict.name != *pkg_name {
                if let Some(blocked_by) = self.removal_blocker(&conflict.name) {
                    let chain_a = self
                        .dep_chains
                        .get(pkg_name)
                        .cloned()
                        .unwrap_or_default();
                    let chain_b = self
                        .dep_chains
                        .get(&conflict.name)
                        .cloned()
                        .unwrap_or_default();
                    return Err(ResolveError::PackageConflict {
                        pkg_a: pkg_name.clone(),
                        pkg_b: conflict.name.clone(),
                        chain_a,
                        chain_b,
                        blocked_by,
                    });
                }
                let already_removing = self
                    .replaces
                    .iter()
                    .any(|(_, old, _)| old == &conflict.name);
                if !already_removing {
                    self.replaces.push((
                        pkg_name.clone(),
                        conflict.name.clone(),
                        RemovalReason::Conflict { with: pkg_name.clone() },
                    ));
                }
            }
        }
        Ok(())
    }

    fn into_resolved_set(self) -> ResolvedSet {
        let mut to_install: Vec<ResolvedPackage> = self
            .selected
            .iter()
            .filter_map(|(name, &id)| {
                let candidate = self.pool.get(id)?;
                if matches!(candidate.source, PackageSource::Local)
                    && !self.targets.contains(name)
                {
                    return None;
                }
                Some(ResolvedPackage {
                    id,
                    name: name.clone(),
                    version: candidate.info.version.clone(),
                    source: candidate.source,
                    reason: self
                        .reasons
                        .get(name)
                        .copied()
                        .unwrap_or(InstallReason::Dependency),
                })
            })
            .collect();

        to_install.sort_by(|a, b| a.name.cmp(&b.name));

        let to_remove: Vec<(String, RemovalReason)> = self
            .replaces
            .into_iter()
            .map(|(_, old, reason)| (old, reason))
            .collect();

        ResolvedSet {
            to_install,
            to_remove,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::ConcretePool;
    use pax_core::package::Dependency;

    fn make_pkg(name: &str, ver: &str, deps: &[&str]) -> pax_core::package::PackageInfo {
        pax_core::package::PackageInfo {
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
    fn simple_dep_chain() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("a", "1.0-1", &["b"]), 0);
        pool.add_sync(make_pkg("b", "1.0-1", &["c"]), 0);
        pool.add_sync(make_pkg("c", "1.0-1", &[]), 0);

        let resolved =
            resolve(&pool, &["a".to_string()], &ResolveOptions::default()).unwrap();
        assert_eq!(resolved.to_install.len(), 3);
        let names: Vec<_> = resolved.to_install.iter().map(|p| &p.name).collect();
        assert!(names.contains(&&"a".to_string()));
        assert!(names.contains(&&"b".to_string()));
        assert!(names.contains(&&"c".to_string()));
    }

    #[test]
    fn already_installed_skipped() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("b", "1.0-1", &[]));
        pool.add_sync(make_pkg("a", "1.0-1", &["b"]), 0);
        pool.add_sync(make_pkg("b", "1.0-1", &[]), 0);

        let resolved =
            resolve(&pool, &["a".to_string()], &ResolveOptions::default()).unwrap();
        assert_eq!(resolved.to_install.len(), 1);
        assert_eq!(resolved.to_install[0].name, "a");
    }

    #[test]
    fn virtual_package_provides() {
        let mut pool = ConcretePool::new(HashSet::new());
        let mut bash = make_pkg("bash", "5.2-1", &[]);
        bash.provides = vec![Dependency::parse("sh").unwrap()];
        pool.add_sync(bash, 0);
        pool.add_sync(make_pkg("some-tool", "1.0-1", &["sh"]), 0);

        let resolved = resolve(
            &pool,
            &["some-tool".to_string()],
            &ResolveOptions::default(),
        )
        .unwrap();
        assert_eq!(resolved.to_install.len(), 2);
        let names: Vec<_> = resolved.to_install.iter().map(|p| &p.name).collect();
        assert!(names.contains(&&"bash".to_string()));
    }

    #[test]
    fn version_constraint_satisfied() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("openssl", "3.1-1", &[]), 0);
        pool.add_sync(make_pkg("app", "1.0-1", &["openssl>=3.0"]), 0);

        let resolved =
            resolve(&pool, &["app".to_string()], &ResolveOptions::default()).unwrap();
        assert_eq!(resolved.to_install.len(), 2);
    }

    #[test]
    fn target_not_found() {
        let pool = ConcretePool::new(HashSet::new());
        let err = resolve(
            &pool,
            &["nonexistent".to_string()],
            &ResolveOptions::default(),
        );
        assert!(matches!(
            err,
            Err(ResolveError::TargetNotFound { .. })
        ));
    }

    #[test]
    fn dependency_cycle_tolerated() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("a", "1.0-1", &["b"]), 0);
        pool.add_sync(make_pkg("b", "1.0-1", &["a"]), 0);

        let resolved =
            resolve(&pool, &["a".to_string()], &ResolveOptions::default()).unwrap();
        assert_eq!(resolved.to_install.len(), 2);
    }

    #[test]
    fn conflict_detected() {
        let mut pool = ConcretePool::new(HashSet::new());
        let mut a = make_pkg("a", "1.0-1", &[]);
        a.conflicts = vec![Dependency::parse("b").unwrap()];
        pool.add_sync(a, 0);
        pool.add_local(make_pkg("b", "1.0-1", &[]));
        pool.add_local(make_pkg("c", "1.0-1", &["b"]));

        let err = resolve(
            &pool,
            &["a".to_string()],
            &ResolveOptions::default(),
        );
        assert!(matches!(
            err,
            Err(ResolveError::PackageConflict { .. })
        ));
    }

    #[test]
    fn conflict_auto_resolved() {
        let mut pool = ConcretePool::new(HashSet::new());
        let mut a = make_pkg("a", "1.0-1", &[]);
        a.conflicts = vec![Dependency::parse("b").unwrap()];
        pool.add_sync(a, 0);
        pool.add_local(make_pkg("b", "1.0-1", &[]));

        let resolved = resolve(
            &pool,
            &["a".to_string()],
            &ResolveOptions::default(),
        ).unwrap();
        assert!(resolved.to_remove.iter().any(|(name, reason)| {
            name == "b" && matches!(reason, crate::transaction::RemovalReason::Conflict { .. })
        }));
    }

    #[test]
    fn replaces_marks_removal() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("old-pkg", "1.0-1", &[]));
        let mut new_pkg = make_pkg("new-pkg", "2.0-1", &[]);
        new_pkg.replaces = vec![Dependency::parse("old-pkg").unwrap()];
        pool.add_sync(new_pkg, 0);

        let resolved = resolve(
            &pool,
            &["new-pkg".to_string()],
            &ResolveOptions::default(),
        )
        .unwrap();
        assert!(resolved.to_remove.iter().any(|(name, _)| name == "old-pkg"));
    }

    #[test]
    fn install_reason_correct() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("app", "1.0-1", &["lib"]), 0);
        pool.add_sync(make_pkg("lib", "1.0-1", &[]), 0);

        let resolved =
            resolve(&pool, &["app".to_string()], &ResolveOptions::default()).unwrap();
        for pkg in &resolved.to_install {
            if pkg.name == "app" {
                assert_eq!(pkg.reason, InstallReason::Explicit);
            } else if pkg.name == "lib" {
                assert_eq!(pkg.reason, InstallReason::Dependency);
            }
        }
    }
}
