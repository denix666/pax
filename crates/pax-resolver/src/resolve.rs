use std::collections::{HashMap, HashSet};

use pax_core::package::{Dependency, InstallReason};
use pax_core::version::Version;

use crate::error::{ResolveError, Result};
use crate::pool::{PackageId, PackagePool, PackageSource, package_satisfies, preferred_sync};
use crate::transaction::RemovalReason;

pub struct ResolveOptions {
    pub reinstall: bool,
    /// Apply repository replacement metadata. Disable for local artifact installs;
    /// explicit conflicts are still handled.
    pub apply_replacements: bool,
}

impl Default for ResolveOptions {
    fn default() -> Self {
        ResolveOptions {
            reinstall: false,
            apply_replacements: true,
        }
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
        replaces: Vec::new(),
        targets: targets.iter().cloned().collect(),
    };

    for target in targets {
        resolver.resolve_target(target, &[])?;
    }

    resolver.plan_removals()?;
    resolver.validate_final_state()?;
    Ok(resolver.into_resolved_set())
}

impl<'a, P: PackagePool> Resolver<'a, P> {
    fn resolve_target(&mut self, name: &str, chain: &[String]) -> Result<()> {
        if let Some(&id) = self.selected.get(name) {
            self.reasons
                .insert(name.to_string(), InstallReason::Explicit);
            return self.select(id, chain, InstallReason::Explicit);
        }
        let candidate = preferred_sync(self.pool, name)
            .or_else(|| self.pool.candidates(name).into_iter().next())
            .or_else(|| {
                self.pool.providers(name).into_iter().find(|candidate| {
                    matches!(candidate.source, PackageSource::Local)
                        || preferred_sync(self.pool, &candidate.info.name)
                            .is_some_and(|preferred| preferred.id == candidate.id)
                })
            })
            .ok_or_else(|| ResolveError::TargetNotFound {
                name: name.to_string(),
            })?;
        self.select(candidate.id, chain, InstallReason::Explicit)
    }

    fn select(&mut self, id: PackageId, chain: &[String], reason: InstallReason) -> Result<()> {
        let candidate = self.pool.get(id).expect("candidate belongs to pool");
        let name = candidate.info.name.clone();
        if let Some(&selected) = self.selected.get(&name) {
            if selected == id {
                return Ok(());
            }
            return Err(ResolveError::DependencyNotFound {
                dep: Dependency {
                    name,
                    constraint: None,
                },
                chain: chain.to_vec(),
            });
        }
        let deps = candidate.info.depends.clone();
        self.selected.insert(name.clone(), id);
        self.reasons.insert(name.clone(), reason);
        self.dep_chains.insert(name.clone(), chain.to_vec());
        let mut next_chain = chain.to_vec();
        next_chain.push(name);
        for dep in &deps {
            self.resolve_dep(dep, &next_chain)?;
        }
        Ok(())
    }

    fn resolve_dep(&mut self, dep: &Dependency, chain: &[String]) -> Result<()> {
        if self
            .final_packages()
            .iter()
            .any(|candidate| package_satisfies(candidate.info, dep))
        {
            return Ok(());
        }
        let direct = preferred_sync(self.pool, &dep.name).filter(|candidate| {
            !self.selected.contains_key(&candidate.info.name)
                && package_satisfies(candidate.info, dep)
        });
        let candidate = direct.or_else(|| {
            self.pool
                .providers(&dep.name)
                .into_iter()
                .find(|candidate| {
                    package_satisfies(candidate.info, dep)
                        && !self.selected.contains_key(&candidate.info.name)
                        && match candidate.source {
                            PackageSource::Local => {
                                !self.selected.contains_key(&candidate.info.name)
                            }
                            PackageSource::Sync { .. } => {
                                preferred_sync(self.pool, &candidate.info.name)
                                    .is_some_and(|preferred| preferred.id == candidate.id)
                            }
                        }
                })
        });
        if let Some(candidate) = candidate {
            if !self.selected.contains_key(&candidate.info.name) {
                return self.select(candidate.id, chain, InstallReason::Dependency);
            }
        }
        if let Some(installed) = self.pool.installed_version(&dep.name) {
            return Err(ResolveError::VersionConflict {
                pkg: dep.name.clone(),
                installed: installed.clone(),
                dep: dep.clone(),
                chain: chain.to_vec(),
            });
        }
        Err(ResolveError::DependencyNotFound {
            dep: dep.clone(),
            chain: chain.to_vec(),
        })
    }

    fn final_packages(&self) -> Vec<crate::pool::PackageCandidate<'a>> {
        let mut packages: Vec<_> = self
            .selected
            .values()
            .filter_map(|&id| self.pool.get(id))
            .collect();
        packages.extend(self.pool.all_installed().into_iter().filter(|candidate| {
            !self.selected.contains_key(&candidate.info.name)
                && !self
                    .replaces
                    .iter()
                    .any(|(_, old, _)| old == &candidate.info.name)
        }));
        packages.sort_by(|a, b| a.info.name.cmp(&b.info.name));
        packages
    }

    fn conflict_error(&self, a: &str, b: &str, blocked_by: String) -> ResolveError {
        ResolveError::PackageConflict {
            pkg_a: a.to_string(),
            pkg_b: b.to_string(),
            chain_a: self.dep_chains.get(a).cloned().unwrap_or_default(),
            chain_b: self.dep_chains.get(b).cloned().unwrap_or_default(),
            blocked_by,
        }
    }

    fn plan_removals(&mut self) -> Result<()> {
        let mut selected: Vec<_> = self.selected.values().copied().collect();
        selected.sort_by_key(|id| self.pool.get(*id).unwrap().info.name.clone());
        for id in selected {
            let candidate = self.pool.get(id).unwrap();
            if !self.options.apply_replacements || matches!(candidate.source, PackageSource::Local)
            {
                continue;
            }
            for replacement in &candidate.info.replaces {
                for installed in self.pool.all_installed() {
                    if installed.info.name != replacement.name
                        || !replacement.satisfies(&installed.info.version)
                        || installed.info.name == candidate.info.name
                    {
                        continue;
                    }
                    if self.selected.contains_key(&installed.info.name)
                        || self.targets.contains(&installed.info.name)
                    {
                        return Err(self.conflict_error(
                            &candidate.info.name,
                            &installed.info.name,
                            "selected package".to_string(),
                        ));
                    }
                    if !self
                        .replaces
                        .iter()
                        .any(|(_, old, _)| old == &installed.info.name)
                    {
                        self.replaces.push((
                            candidate.info.name.clone(),
                            installed.info.name.clone(),
                            RemovalReason::Replaced,
                        ));
                    }
                }
            }
        }
        loop {
            let packages = self.final_packages();
            let mut removal = None;
            'pairs: for a in &packages {
                for b in &packages {
                    if a.info.name == b.info.name
                        || !a
                            .info
                            .conflicts
                            .iter()
                            .any(|dep| package_satisfies(b.info, dep))
                    {
                        continue;
                    }
                    let a_selected = self.selected.contains_key(&a.info.name);
                    let b_selected = self.selected.contains_key(&b.info.name);
                    if !a_selected && !b_selected {
                        continue;
                    }
                    let (keep, remove) = if b_selected { (b, a) } else { (a, b) };
                    if self.selected.contains_key(&remove.info.name)
                        || self.targets.contains(&remove.info.name)
                    {
                        return Err(self.conflict_error(
                            &keep.info.name,
                            &remove.info.name,
                            "selected package".to_string(),
                        ));
                    }
                    removal = Some((keep.info.name.clone(), remove.info.name.clone()));
                    break 'pairs;
                }
            }
            let Some((keep, remove)) = removal else { break };
            self.replaces
                .push((keep.clone(), remove, RemovalReason::Conflict { with: keep }));
        }
        Ok(())
    }

    fn validate_final_state(&self) -> Result<()> {
        let packages = self.final_packages();
        let installed = self.pool.all_installed();
        for candidate in &packages {
            let incoming = matches!(candidate.source, PackageSource::Sync { .. });
            for dep in &candidate.info.depends {
                if packages
                    .iter()
                    .any(|other| package_satisfies(other.info, dep))
                {
                    continue;
                }
                // Retained packages may already be broken. Only reject a newly
                // broken dependency; incoming metadata must always be satisfied.
                if !incoming
                    && !installed
                        .iter()
                        .any(|other| package_satisfies(other.info, dep))
                {
                    continue;
                }
                if let Some((new, old, _)) = self.replaces.iter().find(|(_, old, _)| {
                    self.pool.candidates(old).iter().any(|old_candidate| {
                        matches!(old_candidate.source, PackageSource::Local)
                            && package_satisfies(old_candidate.info, dep)
                    })
                }) {
                    return Err(self.conflict_error(new, old, candidate.info.name.clone()));
                }
                return Err(ResolveError::DependencyNotFound {
                    dep: dep.clone(),
                    chain: vec![candidate.info.name.clone()],
                });
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
                    && (!self.options.reinstall || !self.targets.contains(name))
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

        let resolved = resolve(&pool, &["a".to_string()], &ResolveOptions::default()).unwrap();
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

        let resolved = resolve(&pool, &["a".to_string()], &ResolveOptions::default()).unwrap();
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

        let resolved = resolve(&pool, &["app".to_string()], &ResolveOptions::default()).unwrap();
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
        assert!(matches!(err, Err(ResolveError::TargetNotFound { .. })));
    }

    #[test]
    fn dependency_cycle_tolerated() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("a", "1.0-1", &["b"]), 0);
        pool.add_sync(make_pkg("b", "1.0-1", &["a"]), 0);

        let resolved = resolve(&pool, &["a".to_string()], &ResolveOptions::default()).unwrap();
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

        let err = resolve(&pool, &["a".to_string()], &ResolveOptions::default());
        assert!(matches!(err, Err(ResolveError::PackageConflict { .. })));
    }

    #[test]
    fn conflict_auto_resolved() {
        let mut pool = ConcretePool::new(HashSet::new());
        let mut a = make_pkg("a", "1.0-1", &[]);
        a.conflicts = vec![Dependency::parse("b").unwrap()];
        pool.add_sync(a, 0);
        pool.add_local(make_pkg("b", "1.0-1", &[]));

        let resolved = resolve(&pool, &["a".to_string()], &ResolveOptions::default()).unwrap();
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

        let resolved =
            resolve(&pool, &["new-pkg".to_string()], &ResolveOptions::default()).unwrap();
        assert!(resolved.to_remove.iter().any(|(name, _)| name == "old-pkg"));
    }

    #[test]
    fn install_reason_correct() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("app", "1.0-1", &["lib"]), 0);
        pool.add_sync(make_pkg("lib", "1.0-1", &[]), 0);

        let resolved = resolve(&pool, &["app".to_string()], &ResolveOptions::default()).unwrap();
        for pkg in &resolved.to_install {
            if pkg.name == "app" {
                assert_eq!(pkg.reason, InstallReason::Explicit);
            } else if pkg.name == "lib" {
                assert_eq!(pkg.reason, InstallReason::Dependency);
            }
        }
    }

    #[test]
    fn dependency_upgrades_unsatisfying_installed_version() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("lib", "1", &[]));
        pool.add_sync(make_pkg("lib", "2", &[]), 0);
        pool.add_sync(make_pkg("app", "1", &["lib>=2"]), 0);
        let resolved = resolve(&pool, &["app".into()], &ResolveOptions::default()).unwrap();
        assert!(
            resolved
                .to_install
                .iter()
                .any(|pkg| pkg.name == "lib" && pkg.version == Version::parse("2").unwrap())
        );
    }

    #[test]
    fn first_repository_wins_over_newer_version() {
        let mut pool = ConcretePool::new(HashSet::new());
        let first = pool.add_sync(make_pkg("lib", "1", &[]), 0);
        pool.add_sync(make_pkg("lib", "9", &[]), 1);
        let resolved = resolve(&pool, &["lib".into()], &ResolveOptions::default()).unwrap();
        assert_eq!(resolved.to_install[0].id, first);
    }

    #[test]
    fn dependency_cannot_fall_through_repository_priority() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("lib", "1", &[]), 0);
        pool.add_sync(make_pkg("lib", "2", &[]), 1);
        pool.add_sync(make_pkg("app", "1", &["lib>=2"]), 0);
        assert!(resolve(&pool, &["app".into()], &ResolveOptions::default()).is_err());
    }

    #[test]
    fn provider_selection_keeps_the_matching_candidate() {
        let mut pool = ConcretePool::new(HashSet::new());
        let mut provider = make_pkg("provider", "1", &[]);
        provider.provides = vec![Dependency::parse("virtual=2").unwrap()];
        let expected = pool.add_sync(provider, 0);
        pool.add_sync(make_pkg("provider", "9", &[]), 1);
        pool.add_sync(make_pkg("app", "1", &["virtual>=2"]), 0);
        let resolved = resolve(&pool, &["app".into()], &ResolveOptions::default()).unwrap();
        assert!(resolved.to_install.iter().any(|pkg| pkg.id == expected));
    }

    #[test]
    fn unversioned_provide_does_not_satisfy_versioned_dependency() {
        let mut pool = ConcretePool::new(HashSet::new());
        let mut provider = make_pkg("provider", "9", &[]);
        provider.provides = vec![Dependency::parse("virtual").unwrap()];
        pool.add_sync(provider, 0);
        pool.add_sync(make_pkg("app", "1", &["virtual>=2"]), 0);
        assert!(resolve(&pool, &["app".into()], &ResolveOptions::default()).is_err());
    }

    #[test]
    fn final_state_rejects_incompatible_selected_dependency_in_either_target_order() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("lib", "1", &[]));
        pool.add_sync(make_pkg("lib", "2", &[]), 0);
        pool.add_sync(make_pkg("app", "1", &["lib<2"]), 0);
        for targets in [["app".into(), "lib".into()], ["lib".into(), "app".into()]] {
            assert!(resolve(&pool, &targets, &ResolveOptions::default()).is_err());
        }
    }

    #[test]
    fn upgrade_validates_retained_reverse_dependencies() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("lib", "1", &[]));
        pool.add_local(make_pkg("consumer", "1", &["lib<2"]));
        pool.add_sync(make_pkg("lib", "2", &[]), 0);
        assert!(resolve(&pool, &["lib".into()], &ResolveOptions::default()).is_err());
    }

    #[test]
    fn upgraded_provider_cannot_use_stale_installed_provisions() {
        let mut pool = ConcretePool::new(HashSet::new());
        let mut old = make_pkg("provider", "1", &[]);
        old.provides = vec![Dependency::parse("virtual=1").unwrap()];
        pool.add_local(old);
        pool.add_local(make_pkg("consumer", "1", &["virtual=1"]));
        pool.add_sync(make_pkg("provider", "2", &[]), 0);
        assert!(resolve(&pool, &["provider".into()], &ResolveOptions::default()).is_err());
    }

    #[test]
    fn selected_conflicts_cannot_schedule_noninstalled_removal() {
        let mut pool = ConcretePool::new(HashSet::new());
        let mut a = make_pkg("a", "1", &["b"]);
        a.conflicts = vec![Dependency::parse("b").unwrap()];
        pool.add_sync(a, 0);
        pool.add_sync(make_pkg("b", "1", &[]), 0);
        assert!(matches!(
            resolve(&pool, &["a".into()], &ResolveOptions::default()),
            Err(ResolveError::PackageConflict { .. })
        ));
    }

    #[test]
    fn retained_package_conflicts_with_new_virtual_provider() {
        let mut pool = ConcretePool::new(HashSet::new());
        let mut installed = make_pkg("installed", "1", &[]);
        installed.conflicts = vec![Dependency::parse("virtual>=2").unwrap()];
        pool.add_local(installed);
        let mut new = make_pkg("new", "1", &[]);
        new.provides = vec![Dependency::parse("virtual=2").unwrap()];
        pool.add_sync(new, 0);
        let resolved = resolve(&pool, &["new".into()], &ResolveOptions::default()).unwrap();
        assert!(
            resolved
                .to_remove
                .iter()
                .any(|(name, _)| name == "installed")
        );
    }

    #[test]
    fn obsolete_installed_conflict_does_not_affect_upgrade() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("lib", "1", &[]));
        pool.add_sync(make_pkg("lib", "2", &[]), 0);
        let mut app = make_pkg("app", "1", &[]);
        app.conflicts = vec![Dependency::parse("lib<2").unwrap()];
        pool.add_sync(app, 0);
        let resolved = resolve(
            &pool,
            &["app".into(), "lib".into()],
            &ResolveOptions::default(),
        )
        .unwrap();
        assert!(resolved.to_remove.is_empty());
    }

    #[test]
    fn versioned_replaces_only_remove_matching_installed_versions() {
        for (version, removed) in [("1", true), ("2", false)] {
            let mut pool = ConcretePool::new(HashSet::new());
            pool.add_local(make_pkg("old", version, &[]));
            let mut new = make_pkg("new", "1", &[]);
            new.replaces = vec![Dependency::parse("old<2").unwrap()];
            pool.add_sync(new, 0);
            let resolved = resolve(&pool, &["new".into()], &ResolveOptions::default()).unwrap();
            assert_eq!(
                resolved.to_remove.iter().any(|(name, _)| name == "old"),
                removed
            );
        }
    }

    #[test]
    fn replacement_cannot_break_versioned_virtual_reverse_dependency() {
        let mut pool = ConcretePool::new(HashSet::new());
        let mut old = make_pkg("old", "1", &[]);
        old.provides = vec![Dependency::parse("virtual=2").unwrap()];
        pool.add_local(old);
        pool.add_local(make_pkg("consumer", "1", &["virtual>=2"]));
        let mut new = make_pkg("new", "1", &[]);
        new.replaces = vec![Dependency::parse("old").unwrap()];
        pool.add_sync(new, 0);
        assert!(matches!(
            resolve(&pool, &["new".into()], &ResolveOptions::default()),
            Err(ResolveError::PackageConflict { .. })
        ));
    }

    #[test]
    fn alternate_provider_allows_removal_and_removals_are_deduplicated() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("old", "1", &[]));
        pool.add_local(make_pkg("consumer", "1", &["old>=1"]));
        let mut new = make_pkg("new", "2", &[]);
        new.replaces = vec![
            Dependency::parse("old").unwrap(),
            Dependency::parse("old<2").unwrap(),
        ];
        new.conflicts = vec![Dependency::parse("old").unwrap()];
        new.provides = vec![Dependency::parse("old=2").unwrap()];
        pool.add_sync(new, 0);
        let resolved = resolve(&pool, &["new".into()], &ResolveOptions::default()).unwrap();
        assert_eq!(resolved.to_remove.len(), 1);
        assert_eq!(resolved.to_remove[0].0, "old");
    }

    #[test]
    fn replacement_cannot_remove_an_explicit_target() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("old", "1", &[]));
        let mut new = make_pkg("new", "2", &[]);
        new.replaces = vec![Dependency::parse("old").unwrap()];
        pool.add_sync(new, 0);
        assert!(matches!(
            resolve(
                &pool,
                &["new".into(), "old".into()],
                &ResolveOptions::default()
            ),
            Err(ResolveError::PackageConflict { .. })
        ));
    }
    #[test]
    fn replacement_uses_upgraded_consumers_final_dependencies() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("old", "1", &[]));
        pool.add_local(make_pkg("consumer", "1", &["old"]));
        pool.add_sync(make_pkg("consumer", "2", &["new>=2"]), 0);
        let mut new = make_pkg("new", "2", &[]);
        new.replaces = vec![Dependency::parse("old").unwrap()];
        pool.add_sync(new, 0);
        let resolved = resolve(
            &pool,
            &["consumer".into(), "new".into()],
            &ResolveOptions::default(),
        )
        .unwrap();
        assert_eq!(resolved.to_remove.len(), 1);
        assert_eq!(resolved.to_remove[0].0, "old");
    }

    #[test]
    fn removed_consumers_do_not_block_removal_of_their_dependency() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("old", "1", &[]));
        pool.add_local(make_pkg("consumer", "1", &["old"]));
        let mut new = make_pkg("new", "2", &[]);
        new.replaces = vec![
            Dependency::parse("old").unwrap(),
            Dependency::parse("consumer").unwrap(),
        ];
        pool.add_sync(new, 0);
        let resolved = resolve(&pool, &["new".into()], &ResolveOptions::default()).unwrap();
        assert_eq!(resolved.to_remove.len(), 2);
    }
    #[test]
    fn preexisting_missing_dependency_allows_unrelated_install() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("broken", "1", &["missing>=2"]));
        pool.add_sync(make_pkg("tool", "1", &[]), 0);
        let resolved = resolve(&pool, &["tool".into()], &ResolveOptions::default()).unwrap();
        assert_eq!(resolved.to_install.len(), 1);
        assert_eq!(resolved.to_install[0].name, "tool");
    }

    #[test]
    fn preexisting_missing_dependency_allows_partial_repair() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("broken", "1", &["missing-a", "missing-b"]));
        pool.add_sync(make_pkg("missing-a", "1", &[]), 0);
        let resolved = resolve(&pool, &["missing-a".into()], &ResolveOptions::default()).unwrap();
        assert_eq!(resolved.to_install[0].name, "missing-a");
    }

    #[test]
    fn incoming_package_cannot_preserve_preexisting_missing_dependency() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("broken", "1", &["missing"]));
        pool.add_sync(make_pkg("broken", "2", &["missing"]), 0);
        assert!(matches!(
            resolve(&pool, &["broken".into()], &ResolveOptions::default()),
            Err(ResolveError::DependencyNotFound { .. })
        ));
    }

    #[test]
    fn incoming_dependency_is_validated_after_removals() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("old", "1", &[]));
        pool.add_sync(make_pkg("tool", "1", &["old"]), 0);
        let mut replacement = make_pkg("new", "1", &[]);
        replacement.replaces = vec![Dependency::parse("old").unwrap()];
        pool.add_sync(replacement, 0);
        assert!(matches!(
            resolve(
                &pool,
                &["tool".into(), "new".into()],
                &ResolveOptions::default()
            ),
            Err(ResolveError::PackageConflict { .. })
        ));
    }

    #[test]
    fn local_artifact_replacements_can_be_disabled_without_disabling_conflicts() {
        for conflicts in [false, true] {
            let mut pool = ConcretePool::new(HashSet::new());
            pool.add_local(make_pkg("old", "1", &[]));
            let mut artifact = make_pkg("artifact", "1", &[]);
            artifact.replaces = vec![Dependency::parse("old").unwrap()];
            if conflicts {
                artifact.conflicts = vec![Dependency::parse("old").unwrap()];
            }
            pool.add_sync(artifact, 0);
            let options = ResolveOptions {
                reinstall: true,
                apply_replacements: false,
            };
            let resolved = resolve(&pool, &["artifact".into()], &options).unwrap();
            assert_eq!(resolved.to_remove.len(), usize::from(conflicts));
            if conflicts {
                assert_eq!(resolved.to_remove[0].0, "old");
                assert!(matches!(
                    resolved.to_remove[0].1,
                    RemovalReason::Conflict { .. }
                ));
            }
        }
    }
}
