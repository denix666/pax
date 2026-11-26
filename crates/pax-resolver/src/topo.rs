use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

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
                if let Some(provider) = resolved
                    .to_install
                    .iter()
                    .filter(|provider| {
                        pool.get(provider.id)
                            .is_some_and(|other| package_satisfies(other.info, dep))
                    })
                    .min_by(|a, b| a.name.cmp(&b.name))
                {
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

    // Resolver output is name-sorted; keep its usual FIFO Kahn order even when
    // callers shuffle the selection or sort it again.
    for deps in dependents.values_mut() {
        deps.sort_unstable();
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

    if order.len() < in_degree.len() {
        order.extend(order_remaining(&in_degree, &dependents));
    }
    let final_order: Vec<String> = order.iter().map(|&s| s.to_string()).collect();

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

// Kahn's remainder includes acyclic consumers blocked by cycles. Only members
// of the same SCC may use a fallback order; edges between SCCs must be respected.
fn order_remaining<'a>(
    in_degree: &HashMap<&'a str, usize>,
    dependents: &HashMap<&'a str, Vec<&'a str>>,
) -> Vec<&'a str> {
    let mut names: Vec<_> = in_degree
        .iter()
        .filter(|&(_, degree)| *degree > 0)
        .map(|(&name, _)| name)
        .collect();
    names.sort_unstable();
    let indices: HashMap<_, _> = names
        .iter()
        .enumerate()
        .map(|(index, &name)| (name, index))
        .collect();
    let mut edges = vec![Vec::new(); names.len()];
    let mut reverse = vec![Vec::new(); names.len()];
    for (node, name) in names.iter().enumerate() {
        if let Some(deps) = dependents.get(name) {
            for dep in deps {
                if let Some(&next) = indices.get(dep) {
                    edges[node].push(next);
                    reverse[next].push(node);
                }
            }
        }
    }

    // Both Kosaraju passes use explicit stacks: a long blocked chain or cycle
    // must not consume the process call stack.
    let mut visited = vec![false; names.len()];
    let mut finished = Vec::with_capacity(names.len());
    let mut stack = Vec::new();
    for start in 0..names.len() {
        if visited[start] {
            continue;
        }
        visited[start] = true;
        stack.push((start, 0));
        while let Some((node, edge)) = stack.last_mut() {
            if let Some(&next) = edges[*node].get(*edge) {
                *edge += 1;
                if !visited[next] {
                    visited[next] = true;
                    stack.push((next, 0));
                }
            } else {
                finished.push(*node);
                stack.pop();
            }
        }
    }

    let mut component_of = vec![usize::MAX; names.len()];
    let mut components = Vec::new();
    let mut stack = Vec::new();
    for start in finished.into_iter().rev() {
        if component_of[start] != usize::MAX {
            continue;
        }
        let component = components.len();
        let mut members = Vec::new();
        component_of[start] = component;
        stack.push(start);
        while let Some(node) = stack.pop() {
            members.push(node);
            for &next in &reverse[node] {
                if component_of[next] == usize::MAX {
                    component_of[next] = component;
                    stack.push(next);
                }
            }
        }
        members.sort_unstable();
        components.push(members);
    }

    let mut component_edges = vec![BTreeSet::new(); components.len()];
    let mut component_degree = vec![0; components.len()];
    for (node, next_nodes) in edges.iter().enumerate() {
        let from = component_of[node];
        for &next in next_nodes {
            let to = component_of[next];
            if from != to && component_edges[from].insert(to) {
                component_degree[to] += 1;
            }
        }
    }
    let mut ready = BTreeSet::new();
    for (component, &degree) in component_degree.iter().enumerate() {
        if degree == 0 {
            ready.insert((components[component][0], component));
        }
    }
    let mut order = Vec::with_capacity(names.len());
    while let Some((_, component)) = ready.pop_first() {
        order.extend(components[component].iter().map(|&node| names[node]));
        for &next in &component_edges[component] {
            component_degree[next] -= 1;
            if component_degree[next] == 0 {
                ready.insert((components[next][0], next));
            }
        }
    }
    order
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::planning::execution_plan;
    use crate::pool::ConcretePool;
    use crate::resolve::{ResolveOptions, resolve};
    use crate::transaction::build_transaction;
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

    fn names(resolved: &ResolvedSet) -> Vec<&str> {
        resolved
            .to_install
            .iter()
            .map(|pkg| pkg.name.as_str())
            .collect()
    }

    #[test]
    fn acyclic_fifo_order_is_preserved() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("m-root", "1", &[]), 0);
        pool.add_sync(make_pkg("a-leaf", "1", &["m-root"]), 0);
        pool.add_sync(make_pkg("b-leaf", "1", &["m-root"]), 0);
        pool.add_sync(make_pkg("z-ready", "1", &[]), 0);
        let mut resolved = resolve(
            &pool,
            &["a-leaf".into(), "b-leaf".into(), "z-ready".into()],
            &ResolveOptions::default(),
        )
        .unwrap();
        for _ in 0..2 {
            topological_sort(&pool, &mut resolved);
            // Newly ready a-leaf must not jump ahead of the initial z-ready.
            assert_eq!(names(&resolved), ["m-root", "z-ready", "a-leaf", "b-leaf"]);
            resolved.to_install.reverse();
        }
    }

    #[test]
    fn cycle_precedes_its_acyclic_downstream_after_kahn_prefix() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("appstream", "1", &["libvips"]), 0);
        pool.add_sync(make_pkg("libvips", "1", &["b"]), 0);
        pool.add_sync(make_pkg("b", "1", &["c", "z-ready"]), 0);
        pool.add_sync(make_pkg("c", "1", &["b"]), 0);
        pool.add_sync(make_pkg("z-ready", "1", &[]), 0);
        let mut resolved =
            resolve(&pool, &["appstream".into()], &ResolveOptions::default()).unwrap();
        topological_sort(&pool, &mut resolved);
        assert_eq!(
            names(&resolved),
            ["z-ready", "b", "c", "libvips", "appstream"]
        );
    }

    #[test]
    fn multiple_components_keep_dependency_order_and_stable_ties() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("a-app", "1", &["m-a", "y-a"]), 0);
        pool.add_sync(make_pkg("m-a", "1", &["m-b", "y-a", "y-b"]), 0);
        pool.add_sync(make_pkg("m-b", "1", &["m-a", "y-a"]), 0);
        pool.add_sync(make_pkg("y-a", "1", &["y-b"]), 0);
        pool.add_sync(make_pkg("y-b", "1", &["y-a"]), 0);
        pool.add_sync(make_pkg("z-a", "1", &["z-b"]), 0);
        pool.add_sync(make_pkg("z-b", "1", &["z-a"]), 0);
        let mut resolved = resolve(
            &pool,
            &["a-app".into(), "z-a".into()],
            &ResolveOptions::default(),
        )
        .unwrap();
        for _ in 0..2 {
            topological_sort(&pool, &mut resolved);
            assert_eq!(
                names(&resolved),
                ["y-a", "y-b", "m-a", "m-b", "a-app", "z-a", "z-b"]
            );
            resolved.to_install.reverse();
        }
    }

    fn linked_cycle_pool(bridge: bool) -> (ConcretePool, Vec<String>) {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_local(make_pkg("old", "1", &[]));
        if bridge {
            pool.add_local(make_pkg("b", "1", &["c>=1"]));
            pool.add_local(make_pkg("c", "1", &["b>=1"]));
        }
        pool.add_sync(make_pkg("b", "2", &["c>=1"]), 0);
        pool.add_sync(make_pkg("c", "2", &["b>=1"]), 0);
        pool.add_sync(make_pkg("libvips", "1", &["b>=2"]), 0);
        pool.add_sync(make_pkg("appstream", "1", &["libvips"]), 0);
        let mut new = make_pkg("new", "1", &["appstream"]);
        new.replaces = vec![Dependency::parse("old").unwrap()];
        pool.add_sync(new, 0);
        // Reserve both upgrades even when their installed versions already
        // satisfy the other's dependency.
        let targets = ["appstream", "b", "c", "new"]
            .into_iter()
            .map(str::to_string)
            .collect();
        (pool, targets)
    }

    #[test]
    fn linked_removal_with_installed_cycle_bridges_builds_a_plan() {
        let (pool, targets) = linked_cycle_pool(true);
        let mut resolved = resolve(&pool, &targets, &ResolveOptions::default()).unwrap();
        topological_sort(&pool, &mut resolved);
        let tx = build_transaction(&pool, &resolved, &targets, &|_| (0, 0), false).unwrap();
        assert_eq!(tx.package_order, ["b", "c", "libvips", "appstream", "new"]);
        assert_eq!(tx.upgrades.len(), 2);
        assert_eq!(tx.installs.len(), 3);
        assert_eq!(tx.removals.len(), 1);
        assert_eq!(tx.removals[0].name, "old");
        assert_eq!(tx.removals[0].links.len(), 1);
        assert_eq!(tx.removals[0].links[0].incoming, "new");

        let installed: Vec<_> = pool
            .all_installed()
            .into_iter()
            .map(|pkg| pkg.info.clone())
            .collect();
        let incoming: Vec<_> = resolved
            .to_install
            .iter()
            .map(|pkg| pool.get(pkg.id).unwrap().info.clone())
            .collect();
        let steps = execution_plan(&tx, &installed, &incoming).unwrap();
        assert_eq!(
            steps.iter().map(|step| &step.incoming).collect::<Vec<_>>(),
            tx.package_order.iter().collect::<Vec<_>>()
        );
        assert!(steps[..4].iter().all(|step| step.remove_before.is_empty()));
        assert_eq!(steps[4].remove_before, ["old"]);
    }

    #[test]
    fn fresh_cycle_does_not_move_an_unrelated_linked_removal() {
        let (pool, targets) = linked_cycle_pool(false);
        let mut resolved = resolve(&pool, &targets, &ResolveOptions::default()).unwrap();
        topological_sort(&pool, &mut resolved);
        let tx = build_transaction(&pool, &resolved, &targets, &|_| (0, 0), false).unwrap();
        assert_eq!(tx.package_order, ["b", "c", "libvips", "appstream", "new"]);
        assert_eq!(tx.removals.len(), 1);
        assert_eq!(tx.removals[0].name, "old");
        assert_eq!(tx.removals[0].links.len(), 1);
        assert_eq!(tx.removals[0].links[0].incoming, "new");
    }

    #[test]
    fn provider_witness_is_stable_for_shuffled_and_repeated_ordering() {
        let mut pool = ConcretePool::new(HashSet::new());
        pool.add_sync(make_pkg("consumer", "1", &["virtual>=2", "second>=2"]), 0);
        let mut selected_provider = None;
        for (name, provides, depends) in [
            ("0-unversioned", ["virtual", "second"], vec![]),
            ("1-too-old", ["virtual=1", "second=1"], vec![]),
            ("a-provider", ["virtual=2", "second=2"], vec!["consumer"]),
            ("z-provider", ["virtual=2", "second=2"], vec![]),
        ] {
            let mut pkg = make_pkg(name, "1", &depends);
            pkg.provides = provides
                .iter()
                .map(|provided| Dependency::parse(provided).unwrap())
                .collect();
            let id = pool.add_sync(pkg, 0);
            if name == "a-provider" {
                selected_provider = Some(id);
            }
        }
        // A later repository's candidate must not replace selected metadata.
        pool.add_sync(make_pkg("a-provider", "9", &[]), 1);
        let targets: Vec<_> = [
            "consumer",
            "0-unversioned",
            "1-too-old",
            "a-provider",
            "z-provider",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let mut resolved = resolve(&pool, &targets, &ResolveOptions::default()).unwrap();
        let selection = resolved.to_install.clone();
        for shift in 0..selection.len() {
            resolved.to_install = selection.clone();
            resolved.to_install.rotate_left(shift);
            if shift % 2 == 0 {
                resolved.to_install.reverse();
            }
            for _ in 0..2 {
                topological_sort(&pool, &mut resolved);
                // Choosing the earlier z-provider on a second sort would turn
                // the a-provider/consumer SCC into consumer -> a-provider.
                assert_eq!(
                    names(&resolved),
                    [
                        "0-unversioned",
                        "1-too-old",
                        "z-provider",
                        "a-provider",
                        "consumer"
                    ]
                );
                assert_eq!(resolved.to_install[3].id, selected_provider.unwrap());
            }
        }
    }

    #[test]
    fn long_residual_cycle_and_downstream_use_iterative_traversal() {
        let names: Vec<_> = (0..20_000)
            .map(|index| format!("node-{index:05}"))
            .collect();
        let in_degree: HashMap<_, _> = names.iter().map(|name| (name.as_str(), 1)).collect();
        let mut dependents: HashMap<_, _> = names
            .windows(2)
            .map(|pair| (pair[0].as_str(), vec![pair[1].as_str()]))
            .collect();
        dependents
            .get_mut(names[9_999].as_str())
            .unwrap()
            .push(names[0].as_str());
        assert_eq!(
            order_remaining(&in_degree, &dependents),
            names.iter().map(String::as_str).collect::<Vec<_>>()
        );
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
