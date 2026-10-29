use crate::pool::{PackagePool, preferred_sync};
use crate::transaction::UpgradeAction;

pub fn compute_upgrades<P: PackagePool>(pool: &P) -> Vec<UpgradeAction> {
    let mut upgrades = Vec::new();

    for installed in pool.all_installed() {
        if pool.is_ignored(&installed.info.name) {
            continue;
        }

        let replacement = pool
            .replacements(&installed.info.name)
            .into_iter()
            .find(|candidate| {
                candidate.info.name != installed.info.name
                    && !pool.is_ignored(&candidate.info.name)
                    && preferred_sync(pool, &candidate.info.name)
                        .is_some_and(|preferred| preferred.id == candidate.id)
                    && candidate.info.replaces.iter().any(|replacement| {
                        replacement.name == installed.info.name
                            && replacement.satisfies(&installed.info.version)
                    })
            });
        if let Some(replacement) = replacement {
            if !upgrades
                .iter()
                .any(|upgrade: &UpgradeAction| upgrade.name == replacement.info.name)
            {
                upgrades.push(UpgradeAction {
                    name: replacement.info.name.clone(),
                    old_version: installed.info.version.clone(),
                    new_version: replacement.info.version.clone(),
                    repository: String::new(),
                    download_size: 0,
                    installed_size: 0,
                });
            }
            continue;
        }

        if let Some(sync) = preferred_sync(pool, &installed.info.name) {
            if sync.info.version > installed.info.version {
                upgrades.push(UpgradeAction {
                    name: installed.info.name.clone(),
                    old_version: installed.info.version.clone(),
                    new_version: sync.info.version.clone(),
                    repository: String::new(),
                    download_size: 0,
                    installed_size: 0,
                });
            }
        }
    }

    upgrades.sort_by(|a, b| a.name.cmp(&b.name));
    upgrades.dedup_by(|a, b| a.name == b.name);
    upgrades
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::ConcretePool;
    use pax_core::package::PackageInfo;
    use pax_core::version::Version;
    use std::collections::HashSet;

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
    fn detects_upgrades() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("gcc", "14.1-1"));
        pool.add_sync(make_pkg("gcc", "14.2-1"), 0);
        pool.add_local(make_pkg("glibc", "2.39-1"));
        pool.add_sync(make_pkg("glibc", "2.39-1"), 0);

        let upgrades = compute_upgrades(&pool);
        assert_eq!(upgrades.len(), 1);
        assert_eq!(upgrades[0].name, "gcc");
    }

    #[test]
    fn respects_ignore() {
        let ignored: HashSet<String> = ["gcc"].iter().map(|s| s.to_string()).collect();
        let mut pool = ConcretePool::new(ignored);
        pool.add_local(make_pkg("gcc", "14.1-1"));
        pool.add_sync(make_pkg("gcc", "14.2-1"), 0);

        let upgrades = compute_upgrades(&pool);
        assert!(upgrades.is_empty());
    }
    #[test]
    fn renamed_replacement_is_discovered_without_a_version_increase() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("old", "9"));
        let mut replacement = make_pkg("new", "1");
        replacement.replaces = vec![pax_core::package::Dependency::parse("old>=9").unwrap()];
        pool.add_sync(replacement, 0);
        let upgrades = compute_upgrades(&pool);
        assert_eq!(upgrades.len(), 1);
        assert_eq!(upgrades[0].name, "new");
    }

    #[test]
    fn replacements_respect_versions_ignores_and_repository_priority() {
        for ignored in [HashSet::new(), HashSet::from(["new".to_string()])] {
            let mut pool = ConcretePool::new(ignored);
            pool.add_local(make_pkg("old", "2"));
            let mut replacement = make_pkg("new", "1");
            replacement.replaces = vec![pax_core::package::Dependency::parse("old<2").unwrap()];
            pool.add_sync(replacement.clone(), 0);
            replacement.replaces = vec![pax_core::package::Dependency::parse("old").unwrap()];
            pool.add_sync(replacement, 1);
            assert!(compute_upgrades(&pool).is_empty());
        }
    }

    #[test]
    fn replacement_for_multiple_installed_packages_is_deduplicated() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("old-a", "1"));
        pool.add_local(make_pkg("old-b", "1"));
        let mut replacement = make_pkg("new", "1");
        replacement.replaces = vec!["old-a", "old-b"]
            .into_iter()
            .map(|name| pax_core::package::Dependency::parse(name).unwrap())
            .collect();
        pool.add_sync(replacement, 0);
        assert_eq!(compute_upgrades(&pool).len(), 1);
    }

    #[test]
    fn upgrade_uses_first_repository_even_if_later_is_newer() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("pkg", "2"));
        pool.add_sync(make_pkg("pkg", "3"), 1);
        pool.add_sync(make_pkg("pkg", "1"), 0);
        assert!(compute_upgrades(&pool).is_empty());
    }
    #[test]
    fn ignored_replacement_is_not_an_upgrade_target() {
        let mut pool = ConcretePool::new(HashSet::from(["new".to_string()]));
        pool.add_local(make_pkg("old", "1"));
        let mut replacement = make_pkg("new", "2");
        replacement.replaces = vec![pax_core::package::Dependency::parse("old").unwrap()];
        pool.add_sync(replacement, 0);
        assert!(compute_upgrades(&pool).is_empty());
    }
}
