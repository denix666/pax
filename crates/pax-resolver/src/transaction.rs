use pax_core::version::Version;

use crate::error::{ResolveError, Result};
use crate::planning::execution_plan;
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
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalLink {
    pub incoming: String,
    pub reason: RemovalReason,
}

#[derive(Debug, Clone)]
pub struct RemovalAction {
    pub name: String,
    pub version: Version,
    pub links: Vec<RemovalLink>,
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub installs: Vec<InstallAction>,
    pub upgrades: Vec<UpgradeAction>,
    pub removals: Vec<RemovalAction>,
    /// Incoming actions in the resolver's dependency order, interleaving installs and upgrades.
    pub package_order: Vec<String>,
    pub total_download_size: u64,
    pub total_installed_size: u64,
}

impl Transaction {
    pub fn is_empty(&self) -> bool {
        self.installs.is_empty() && self.upgrades.is_empty() && self.removals.is_empty()
    }
}

/// Build actions from the caller-ordered resolved set and validate their execution
/// plan against pool metadata. No-op actions cannot serve as removal anchors.
pub fn build_transaction<P: PackagePool>(
    pool: &P,
    resolved: &ResolvedSet,
    targets: &[String],
    sync_sizes: &dyn Fn(&str) -> (u64, u64),
    reinstall: bool,
) -> Result<Transaction> {
    let target_set: std::collections::HashSet<&str> = targets.iter().map(|s| s.as_str()).collect();

    let mut installs = Vec::new();
    let mut upgrades = Vec::new();
    let mut package_order = Vec::new();
    let mut total_download: u64 = 0;
    let mut total_installed: u64 = 0;
    let mut incoming = Vec::new();
    let mut selected_names = std::collections::HashSet::new();

    for pkg in &resolved.to_install {
        if !selected_names.insert(pkg.name.as_str()) {
            return Err(ResolveError::InvalidExecutionPlan {
                message: format!("duplicate resolved package: {}", pkg.name),
            });
        }
        let candidate = pool
            .get(pkg.id)
            .ok_or_else(|| ResolveError::InvalidExecutionPlan {
                message: format!(
                    "missing pool metadata for resolved package {} {}",
                    pkg.name, pkg.version
                ),
            })?;
        if candidate.info.name != pkg.name
            || candidate.info.version != pkg.version
            || candidate.source != pkg.source
        {
            return Err(ResolveError::InvalidExecutionPlan {
                message: format!(
                    "stale pool metadata for resolved package {} {}",
                    pkg.name, pkg.version
                ),
            });
        }
        let repo_name = match pkg.source {
            PackageSource::Sync { repo_index } => format!("repo:{repo_index}"),
            PackageSource::Local => "local".to_string(),
        };

        let (dl_size, inst_size) = sync_sizes(&pkg.name);

        if let Some(installed_ver) = pool.installed_version(&pkg.name) {
            let different = pkg.version != *installed_ver;
            if different || (reinstall && target_set.contains(pkg.name.as_str())) {
                incoming.push(candidate.info.clone());
                package_order.push(pkg.name.clone());
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
            incoming.push(candidate.info.clone());
            package_order.push(pkg.name.clone());
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
    for (name, links) in &resolved.to_remove {
        let version = pool.installed_version(name).cloned().ok_or_else(|| {
            ResolveError::InvalidExecutionPlan {
                message: format!("cannot remove {name}: package is not installed"),
            }
        })?;
        removals.push(RemovalAction {
            name: name.clone(),
            version,
            links: links.clone(),
        });
    }

    let tx = Transaction {
        installs,
        upgrades,
        removals,
        package_order,
        total_download_size: total_download,
        total_installed_size: total_installed,
    };
    let installed: Vec<_> = pool
        .all_installed()
        .iter()
        .map(|pkg| pkg.info.clone())
        .collect();
    execution_plan(&tx, &installed, &incoming)?;
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::ConcretePool;
    use crate::resolve::{ResolveOptions, resolve};
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

        let resolved = resolve(&pool, &["app".to_string()], &ResolveOptions::default()).unwrap();
        let tx = build_transaction(
            &pool,
            &resolved,
            &["app".to_string()],
            &|_| (1000, 5000),
            false,
        )
        .unwrap();

        assert_eq!(tx.installs.len(), 2);
        assert!(tx.upgrades.is_empty());

        let app_install = tx.installs.iter().find(|i| i.name == "app").unwrap();
        assert!(app_install.explicit);

        let lib_install = tx.installs.iter().find(|i| i.name == "lib").unwrap();
        assert!(!lib_install.explicit);
    }

    #[test]
    fn preserves_interleaved_dependency_order_without_keyring_priority() {
        use crate::resolve::ResolvedPackage;
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("middle", "1-1", &[]));
        let packages = ["dependency", "middle", "app-keyring"];
        let to_install = packages
            .iter()
            .map(|name| {
                let info = make_pkg(name, "2-1", &[]);
                let id = pool.add_sync(info.clone(), 0);
                ResolvedPackage {
                    id,
                    name: info.name,
                    version: info.version,
                    source: PackageSource::Sync { repo_index: 0 },
                    reason: pax_core::package::InstallReason::Explicit,
                }
            })
            .collect();
        let resolved = ResolvedSet {
            to_install,
            to_remove: vec![],
        };
        let tx = build_transaction(&pool, &resolved, &[], &|_| (1, 2), false).unwrap();
        assert_eq!(tx.package_order, packages);
        assert_eq!(tx.installs.len(), 2);
        assert_eq!(tx.upgrades[0].name, "middle");
    }

    #[test]
    fn selected_downgrade_creates_an_action() {
        use crate::resolve::ResolvedPackage;
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("app", "2-1", &[]));
        let id = pool.add_sync(make_pkg("app", "1-1", &[]), 0);
        let resolved = ResolvedSet {
            to_install: vec![ResolvedPackage {
                id,
                name: "app".into(),
                version: Version::parse("1-1").unwrap(),
                source: PackageSource::Sync { repo_index: 0 },
                reason: pax_core::package::InstallReason::Explicit,
            }],
            to_remove: vec![],
        };
        let tx =
            build_transaction(&pool, &resolved, &["app".into()], &|_| (10, 20), false).unwrap();
        assert_eq!(tx.package_order, ["app"]);
        assert_eq!(tx.upgrades.len(), 1);
        assert_eq!(tx.upgrades[0].new_version.to_string(), "1-1");
        assert_eq!(tx.total_download_size, 10);
    }

    #[test]
    fn removal_link_to_filtered_equal_version_action_is_not_discarded() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("old", "1", &[]));
        pool.add_local(make_pkg("new", "1", &[]));
        let mut new = make_pkg("new", "1", &[]);
        new.replaces = vec![Dependency::parse("old").unwrap()];
        pool.add_sync(new, 0);
        let targets = ["new".into()];
        let resolved = resolve(&pool, &targets, &ResolveOptions::default()).unwrap();
        let error = build_transaction(&pool, &resolved, &targets, &|_| (0, 0), false).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("old"));
        assert!(message.contains("missing incoming action new"));
        // Explicit reinstall creates a real anchor instead of a removal-only transaction.
        let tx = build_transaction(&pool, &resolved, &targets, &|_| (0, 0), true).unwrap();
        assert_eq!(tx.package_order, ["new"]);
        assert_eq!(tx.removals.len(), 1);
    }

    #[test]
    fn missing_outgoing_package_never_gets_a_synthetic_version() {
        let pool = ConcretePool::new(HashSet::new());
        let resolved = ResolvedSet {
            to_install: vec![],
            to_remove: vec![(
                "absent".into(),
                vec![RemovalLink {
                    incoming: "new".into(),
                    reason: RemovalReason::Replaced,
                }],
            )],
        };
        let error = build_transaction(&pool, &resolved, &[], &|_| (0, 0), false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot remove absent: package is not installed")
        );
    }

    #[test]
    fn builder_schedules_linked_removal_chain_after_resolution() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("old-lib", "1", &[]));
        pool.add_local(make_pkg("old-app", "1", &["old-lib"]));
        let mut lib = make_pkg("new-lib", "1", &[]);
        lib.replaces = vec![Dependency::parse("old-lib").unwrap()];
        let mut app = make_pkg("new-app", "1", &["new-lib"]);
        app.replaces = vec![Dependency::parse("old-app").unwrap()];
        pool.add_sync(lib, 0);
        pool.add_sync(app, 0);
        let targets = ["new-lib".into(), "new-app".into()];
        let mut resolved = resolve(&pool, &targets, &ResolveOptions::default()).unwrap();
        crate::topo::topological_sort(&pool, &mut resolved);
        let tx = build_transaction(&pool, &resolved, &targets, &|_| (0, 0), false).unwrap();
        assert_eq!(tx.package_order, ["new-lib", "new-app"]);
        let installed = pool
            .all_installed()
            .iter()
            .map(|pkg| pkg.info.clone())
            .collect::<Vec<_>>();
        let incoming = resolved
            .to_install
            .iter()
            .map(|pkg| pool.get(pkg.id).unwrap().info.clone())
            .collect::<Vec<_>>();
        let steps = execution_plan(&tx, &installed, &incoming).unwrap();
        assert_eq!(steps[0].remove_before, ["old-app", "old-lib"]);
        assert!(steps[1].remove_before.is_empty());
    }

    #[test]
    fn builder_uses_selected_metadata_and_rejects_stale_or_duplicate_selections() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("app", "1", &[]), 0);
        pool.add_sync(make_pkg("app", "9", &["not-selected"]), 1);
        let mut resolved = resolve(&pool, &["app".into()], &ResolveOptions::default()).unwrap();
        assert!(build_transaction(&pool, &resolved, &[], &|_| (0, 0), false).is_ok());
        let original = resolved.to_install[0].clone();
        resolved.to_install.push(original.clone());
        assert!(build_transaction(&pool, &resolved, &[], &|_| (0, 0), false).is_err());
        resolved.to_install.pop();
        resolved.to_install[0].version = Version::parse("9").unwrap();
        assert!(build_transaction(&pool, &resolved, &[], &|_| (0, 0), false).is_err());
        resolved.to_install[0] = original;
        resolved.to_install[0].id = crate::pool::PackageId(u32::MAX);
        assert!(build_transaction(&pool, &resolved, &[], &|_| (0, 0), false).is_err());
    }

    #[test]
    fn upgrade_transaction() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("app", "1.0-1", &[]));
        pool.add_sync(make_pkg("app", "2.0-1", &[]), 0);

        let resolved = resolve(&pool, &["app".to_string()], &ResolveOptions::default()).unwrap();
        let tx = build_transaction(
            &pool,
            &resolved,
            &["app".to_string()],
            &|_| (1000, 5000),
            false,
        )
        .unwrap();

        assert!(tx.installs.is_empty());
        assert_eq!(tx.upgrades.len(), 1);
        assert_eq!(tx.upgrades[0].name, "app");
    }
}
