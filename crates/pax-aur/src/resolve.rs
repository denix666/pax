use std::collections::{HashMap, HashSet, VecDeque};

use crate::error::{AurError, Result};
use crate::rpc::{self, AurPackage};

#[derive(Debug, Clone)]
pub struct AurTarget {
    pub package: AurPackage,
    pub repo_depends: Vec<String>,
    pub aur_depends: Vec<String>,
    pub make_depends: Vec<String>,
}

pub fn resolve_aur_targets(
    names: &[&str],
    installed: &HashSet<String>,
    sync_available: &HashSet<String>,
) -> Result<Vec<AurTarget>> {
    let mut resolved: HashMap<String, AurPackage> = HashMap::new();
    let mut queue: VecDeque<String> = names.iter().map(|n| n.to_string()).collect();
    let mut visited: HashSet<String> = HashSet::new();

    while let Some(name) = queue.pop_front() {
        if visited.contains(&name) || installed.contains(&name) {
            continue;
        }
        visited.insert(name.clone());

        if sync_available.contains(&name) {
            continue;
        }

        let results = rpc::info(&[name.as_str()])?;
        let Some(pkg) = results.into_iter().next() else {
            return Err(AurError::NotFound(name));
        };

        for dep in &pkg.depends {
            let dep_name = dep_name(dep);
            if !installed.contains(dep_name) && !sync_available.contains(dep_name) {
                queue.push_back(dep_name.to_string());
            }
        }

        for dep in &pkg.make_depends {
            let dep_name = dep_name(dep);
            if !installed.contains(dep_name) && !sync_available.contains(dep_name) {
                queue.push_back(dep_name.to_string());
            }
        }

        resolved.insert(name, pkg);
    }

    let mut targets: Vec<AurTarget> = Vec::new();

    // Topological order: deps first
    let mut order = Vec::new();
    let mut topo_visited = HashSet::new();
    for name in names {
        topo_sort(&name.to_string(), &resolved, &mut topo_visited, &mut order);
    }
    // Also include transitive AUR deps
    for name in resolved.keys() {
        topo_sort(name, &resolved, &mut topo_visited, &mut order);
    }

    for name in &order {
        let Some(pkg) = resolved.get(name) else {
            continue;
        };

        let mut repo_deps = Vec::new();
        let mut aur_deps = Vec::new();
        let mut make_deps = Vec::new();

        for dep in &pkg.depends {
            let dn = dep_name(dep).to_string();
            if installed.contains(&dn) {
                continue;
            }
            if sync_available.contains(&dn) {
                repo_deps.push(dn);
            } else if resolved.contains_key(&dn) {
                aur_deps.push(dn);
            } else {
                repo_deps.push(dn);
            }
        }

        for dep in &pkg.make_depends {
            let dn = dep_name(dep).to_string();
            if installed.contains(&dn) {
                continue;
            }
            if sync_available.contains(&dn) || !resolved.contains_key(&dn) {
                make_deps.push(dn);
            } else {
                aur_deps.push(dn);
            }
        }

        targets.push(AurTarget {
            package: pkg.clone(),
            repo_depends: repo_deps,
            aur_depends: aur_deps,
            make_depends: make_deps,
        });
    }

    Ok(targets)
}

fn dep_name(dep: &str) -> &str {
    for op in [">=", "<=", "=", ">", "<"] {
        if let Some(pos) = dep.find(op) {
            return &dep[..pos];
        }
    }
    // Strip description after ": "
    if let Some(pos) = dep.find(": ") {
        return &dep[..pos];
    }
    dep
}

fn topo_sort(
    name: &str,
    packages: &HashMap<String, AurPackage>,
    visited: &mut HashSet<String>,
    order: &mut Vec<String>,
) {
    if visited.contains(name) {
        return;
    }
    visited.insert(name.to_string());

    if let Some(pkg) = packages.get(name) {
        for dep in &pkg.depends {
            let dn = dep_name(dep);
            if packages.contains_key(dn) {
                topo_sort(dn, packages, visited, order);
            }
        }
        for dep in &pkg.make_depends {
            let dn = dep_name(dep);
            if packages.contains_key(dn) {
                topo_sort(dn, packages, visited, order);
            }
        }
    }

    order.push(name.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dep_name() {
        assert_eq!(dep_name("glibc>=2.27"), "glibc");
        assert_eq!(dep_name("openssl"), "openssl");
        assert_eq!(dep_name("pacman>6.1"), "pacman");
        assert_eq!(dep_name("sudo: privilege escalation"), "sudo");
    }
}
