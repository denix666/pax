use crate::pool::{PackagePool, PackageSource};
use crate::transaction::UpgradeAction;

pub fn compute_upgrades<P: PackagePool>(pool: &P) -> Vec<UpgradeAction> {
    let mut upgrades = Vec::new();

    for installed in pool.all_installed() {
        if pool.is_ignored(&installed.info.name) {
            continue;
        }

        let candidates = pool.candidates(&installed.info.name);
        let sync_candidate = candidates
            .iter()
            .find(|c| matches!(c.source, PackageSource::Sync { .. }));

        if let Some(sync) = sync_candidate {
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
}
