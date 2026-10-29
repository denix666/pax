use std::collections::{HashMap, HashSet, VecDeque};

use crate::pool::{PackagePool, package_satisfies};
use crate::resolve::ResolvedSet;

pub fn topological_sort<P: PackagePool>(pool: &P, resolved: &mut ResolvedSet) {
    let retained: Vec<_> = pool
        .all_installed()
        .into_iter()
        .filter(|candidate| {
            !resolved
                .to_install
                .iter()
                .any(|pkg| pkg.name == candidate.info.name)
                && !resolved
                    .to_remove
                    .iter()
                    .any(|(name, _)| name == &candidate.info.name)
        })
        .collect();

    let mut in_degree: HashMap<&str, usize> = HashMap::new();
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

    for pkg in &resolved.to_install {
        in_degree.entry(&pkg.name).or_insert(0);
        if let Some(candidate) = pool.get(pkg.id) {
            let mut prerequisites = HashSet::new();
            for dep in &candidate.info.depends {
                if package_satisfies(candidate.info, dep)
                    || retained
                        .iter()
                        .any(|installed| package_satisfies(installed.info, dep))
                {
                    continue;
                }
                if let Some(provider) = resolved.to_install.iter().find(|provider| {
                    pool.get(provider.id)
                        .is_some_and(|other| package_satisfies(other.info, dep))
                }) {
                    prerequisites.insert(provider.name.as_str());
                }
            }
            for prerequisite in prerequisites {
                *in_degree.entry(pkg.name.as_str()).or_insert(0) += 1;
                dependents
                    .entry(prerequisite)
                    .or_default()
                    .push(pkg.name.as_str());
            }
        }
    }

    let mut ready: Vec<_> = in_degree
        .iter()
        .filter(|&(_, deg)| *deg == 0)
        .map(|(&name, _)| name)
        .collect();
    ready.sort_unstable();
    let mut queue: VecDeque<&str> = ready.into();

    let mut order: Vec<&str> = Vec::new();

    while let Some(name) = queue.pop_front() {
        order.push(name);
        if let Some(deps) = dependents.get(name) {
            for &dep_name in deps {
                if let Some(deg) = in_degree.get_mut(dep_name) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(dep_name);
                    }
                }
            }
        }
    }

    let ordered_names: Vec<String> = order.iter().map(|&s| s.to_string()).collect();

    let mut final_order: Vec<String> = ordered_names;
    for pkg in &resolved.to_install {
        if !final_order.contains(&pkg.name) {
            final_order.push(pkg.name.clone());
        }
    }

    let index_map: HashMap<&str, usize> = final_order
        .iter()
        .enumerate()
        .map(|(i, n)| (n.as_str(), i))
        .collect();

    resolved.to_install.sort_by_key(|p| {
        index_map
            .get(p.name.as_str())
            .copied()
            .unwrap_or(usize::MAX)
    });
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
    fn deps_before_dependents() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("app", "1.0-1", &["lib-b"]), 0);
        pool.add_sync(make_pkg("lib-b", "1.0-1", &["lib-c"]), 0);
        pool.add_sync(make_pkg("lib-c", "1.0-1", &[]), 0);

        let mut resolved =
            resolve(&pool, &["app".to_string()], &ResolveOptions::default()).unwrap();
        topological_sort(&pool, &mut resolved);

        let names: Vec<_> = resolved
            .to_install
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        let pos_c = names.iter().position(|&n| n == "lib-c").unwrap();
        let pos_b = names.iter().position(|&n| n == "lib-b").unwrap();
        let pos_a = names.iter().position(|&n| n == "app").unwrap();
        assert!(pos_c < pos_b);
        assert!(pos_b < pos_a);
    }

    #[test]
    fn cycle_handled() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("a", "1.0-1", &["b"]), 0);
        pool.add_sync(make_pkg("b", "1.0-1", &["a"]), 0);

        let mut resolved = resolve(&pool, &["a".to_string()], &ResolveOptions::default()).unwrap();
        topological_sort(&pool, &mut resolved);
        assert_eq!(resolved.to_install.len(), 2);
    }
    #[test]
    fn virtual_provider_precedes_consumer() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("a-consumer", "1", &["virtual>=2", "other"]), 0);
        let mut provider = make_pkg("z-provider", "1", &[]);
        provider.provides = vec![
            Dependency::parse("virtual=2").unwrap(),
            Dependency::parse("other").unwrap(),
        ];
        pool.add_sync(provider, 0);
        let mut resolved =
            resolve(&pool, &["a-consumer".into()], &ResolveOptions::default()).unwrap();
        topological_sort(&pool, &mut resolved);
        assert_eq!(resolved.to_install[0].name, "z-provider");
        assert_eq!(resolved.to_install[1].name, "a-consumer");
    }
}
