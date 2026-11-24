use std::collections::{BTreeMap, BTreeSet};

use pax_core::package::PackageInfo;
use pax_core::version::Version;

use crate::error::{ResolveError, Result};
use crate::pool::package_satisfies;
use crate::transaction::Transaction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionStep {
    pub incoming: String,
    pub remove_before: Vec<String>,
}

type Packages<'a> = BTreeMap<&'a str, &'a PackageInfo>;

/// Plan linked removals without changing the incoming package order.
///
/// `installed` must be the complete installed snapshot; `incoming` must contain
/// exactly the metadata for the transaction's install/upgrade actions. Callers
/// applying a plan must hold the database lock and validate it again using the
/// actual archive metadata before hooks. This function performs no I/O.
///
/// Each removal stays immediately before its earliest linked incoming action.
/// Installed dependencies constrain removal order and may make those fixed slots
/// impossible. Incoming dependency-cycle fallback is preserved only for plans
/// without removals. This is not a filesystem ownership or boot-safety check, nor
/// a guarantee of continuously satisfied dependencies between individual steps.
pub fn execution_plan(
    tx: &Transaction,
    installed: &[PackageInfo],
    incoming: &[PackageInfo],
) -> Result<Vec<ExecutionStep>> {
    let installed = index_packages(installed, "installed")?;
    let incoming = index_packages(incoming, "incoming")?;
    validate_actions(tx, &installed, &incoming)?;

    let positions: BTreeMap<_, _> = tx
        .package_order
        .iter()
        .enumerate()
        .map(|(index, name)| (name.as_str(), index))
        .collect();
    let removal_nodes: BTreeMap<_, _> = tx
        .removals
        .iter()
        .enumerate()
        .map(|(index, action)| (action.name.as_str(), tx.package_order.len() + index))
        .collect();
    let retained: Packages<'_> = installed
        .iter()
        .filter(|(name, _)| !incoming.contains_key(*name) && !removal_nodes.contains_key(*name))
        .map(|(&name, &pkg)| (name, pkg))
        .collect();
    validate_final_dependencies(&installed, &incoming, &retained)?;

    let mut steps: Vec<_> = tx
        .package_order
        .iter()
        .map(|name| ExecutionStep {
            incoming: name.clone(),
            remove_before: Vec::new(),
        })
        .collect();
    if tx.removals.is_empty() {
        return Ok(steps);
    }

    let mut graph = PlanGraph::new(
        tx.package_order
            .iter()
            .map(|name| format!("apply {name}"))
            .chain(
                tx.removals
                    .iter()
                    .map(|action| format!("remove {}", action.name)),
            )
            .collect(),
    );
    for index in 1..tx.package_order.len() {
        graph.before(index - 1, index, "preserve package_order".into());
    }
    let mut anchors = BTreeMap::new();
    for action in &tx.removals {
        // Nonempty links and their endpoints were checked by validate_actions.
        let anchor = action
            .links
            .iter()
            .map(|link| positions[link.incoming.as_str()])
            .min()
            .unwrap();
        anchors.insert(action.name.as_str(), anchor);
        let node = removal_nodes[action.name.as_str()];
        if anchor > 0 {
            graph.before(
                anchor - 1,
                node,
                format!(
                    "keep removal in the slot before {}",
                    tx.package_order[anchor]
                ),
            );
        }
        for link in &action.links {
            graph.before(
                node,
                positions[link.incoming.as_str()],
                format!("{:?} link to {}", link.reason, link.incoming),
            );
        }
    }
    add_outgoing_dependencies(
        &mut graph,
        &installed,
        &incoming,
        &retained,
        &positions,
        &removal_nodes,
    );
    let order = graph.order()?;
    validate_incoming_order(tx, &installed, &incoming, &positions, &anchors)?;
    for node in order {
        if node >= tx.package_order.len() {
            let action = &tx.removals[node - tx.package_order.len()];
            steps[anchors[action.name.as_str()]]
                .remove_before
                .push(action.name.clone());
        }
    }
    Ok(steps)
}

fn invalid(message: impl Into<String>) -> ResolveError {
    ResolveError::InvalidExecutionPlan {
        message: message.into(),
    }
}

fn index_packages<'a>(packages: &'a [PackageInfo], kind: &str) -> Result<Packages<'a>> {
    let mut indexed = BTreeMap::new();
    for pkg in packages {
        if pkg.name.is_empty() || indexed.insert(pkg.name.as_str(), pkg).is_some() {
            return Err(invalid(format!(
                "empty or duplicate {kind} package name: {}",
                pkg.name
            )));
        }
    }
    Ok(indexed)
}

fn require_installed(
    installed: &Packages<'_>,
    name: &str,
    version: &Version,
    op: &str,
) -> Result<()> {
    let pkg = installed.get(name).ok_or_else(|| {
        invalid(format!(
            "{op} {name} {version}: package is no longer installed"
        ))
    })?;
    if pkg.version != *version {
        return Err(invalid(format!(
            "{op} {name}: stale installed version, expected {version}, found {}",
            pkg.version,
        )));
    }
    Ok(())
}

fn validate_actions(
    tx: &Transaction,
    installed: &Packages<'_>,
    incoming: &Packages<'_>,
) -> Result<()> {
    let mut expected = BTreeMap::new();
    for (name, version) in tx
        .installs
        .iter()
        .map(|action| (&action.name, &action.version))
        .chain(
            tx.upgrades
                .iter()
                .map(|action| (&action.name, &action.new_version)),
        )
    {
        if name.is_empty() || expected.insert(name.as_str(), version).is_some() {
            return Err(invalid(format!(
                "empty or duplicate incoming action: {name}"
            )));
        }
        let pkg = incoming
            .get(name.as_str())
            .ok_or_else(|| invalid(format!("missing incoming metadata for {name} {version}")))?;
        if pkg.version != *version {
            return Err(invalid(format!(
                "incoming {name}: expected version {version}, found {}",
                pkg.version,
            )));
        }
    }
    for name in incoming.keys() {
        if !expected.contains_key(name) {
            return Err(invalid(format!("unexpected incoming metadata: {name}")));
        }
    }
    let mut ordered = BTreeSet::new();
    for name in &tx.package_order {
        if !expected.contains_key(name.as_str()) || !ordered.insert(name.as_str()) {
            return Err(invalid(format!(
                "unknown or duplicate package_order entry: {name}"
            )));
        }
    }
    if ordered.len() != expected.len() {
        return Err(invalid(
            "package_order does not contain every incoming action",
        ));
    }
    for action in &tx.installs {
        if installed.contains_key(action.name.as_str()) {
            return Err(invalid(format!(
                "install {}: package is already installed",
                action.name
            )));
        }
    }
    for action in &tx.upgrades {
        require_installed(installed, &action.name, &action.old_version, "upgrade")?;
    }
    let mut removed = BTreeSet::new();
    for action in &tx.removals {
        if !removed.insert(action.name.as_str()) {
            return Err(invalid(format!(
                "duplicate removal action: {}",
                action.name
            )));
        }
        if expected.contains_key(action.name.as_str()) {
            return Err(invalid(format!(
                "{} has both removal and incoming actions",
                action.name
            )));
        }
        require_installed(installed, &action.name, &action.version, "remove")?;
        if action.links.is_empty() {
            return Err(invalid(format!(
                "removal {} has no incoming links",
                action.name
            )));
        }
        for link in &action.links {
            if !expected.contains_key(link.incoming.as_str()) {
                return Err(invalid(format!(
                    "remove {}: {:?} link refers to missing incoming action {} (possibly filtered as a no-op)",
                    action.name, link.reason, link.incoming,
                )));
            }
        }
    }
    Ok(())
}

fn validate_final_dependencies(
    installed: &Packages<'_>,
    incoming: &Packages<'_>,
    retained: &Packages<'_>,
) -> Result<()> {
    for pkg in incoming.values().chain(retained.values()) {
        for dep in &pkg.depends {
            if incoming
                .values()
                .chain(retained.values())
                .any(|provider| package_satisfies(provider, dep))
            {
                continue;
            }
            // Preserve the resolver's allowance for preexisting broken retained packages.
            if !incoming.contains_key(pkg.name.as_str())
                && !installed
                    .values()
                    .any(|provider| package_satisfies(provider, dep))
            {
                continue;
            }
            return Err(invalid(format!(
                "{} {}: dependency {dep} is unsatisfied in the final state",
                pkg.name, pkg.version,
            )));
        }
    }
    Ok(())
}

fn add_outgoing_dependencies(
    graph: &mut PlanGraph,
    installed: &Packages<'_>,
    incoming: &Packages<'_>,
    retained: &Packages<'_>,
    positions: &BTreeMap<&str, usize>,
    removals: &BTreeMap<&str, usize>,
) {
    for consumer in installed.values() {
        let removed_consumer = removals.get(consumer.name.as_str()).copied();
        let Some(consumer_node) =
            removed_consumer.or_else(|| positions.get(consumer.name.as_str()).copied())
        else {
            continue;
        };
        for dep in &consumer.depends {
            if package_satisfies(consumer, dep)
                || retained
                    .values()
                    .any(|provider| package_satisfies(provider, dep))
            {
                continue;
            }
            for provider in installed.values() {
                if provider.name == consumer.name || !package_satisfies(provider, dep) {
                    continue;
                }
                let provider_node = removals.get(provider.name.as_str()).copied().or_else(|| {
                    // Do not impose reverse upgrade ordering on ordinary upgrades.
                    // Only an explicitly removed consumer needs protection here.
                    if removed_consumer.is_some()
                        && incoming
                            .get(provider.name.as_str())
                            .is_some_and(|new| !package_satisfies(new, dep))
                    {
                        positions.get(provider.name.as_str()).copied()
                    } else {
                        None
                    }
                });
                if let Some(provider_node) = provider_node {
                    graph.before(
                        consumer_node,
                        provider_node,
                        format!(
                            "installed {} {} needs {dep} from {} {}",
                            consumer.name, consumer.version, provider.name, provider.version,
                        ),
                    );
                }
            }
        }
    }
}

fn validate_incoming_order(
    tx: &Transaction,
    installed: &Packages<'_>,
    incoming: &Packages<'_>,
    positions: &BTreeMap<&str, usize>,
    anchors: &BTreeMap<&str, usize>,
) -> Result<()> {
    for (index, name) in tx.package_order.iter().enumerate() {
        let pkg = incoming[name.as_str()];
        for dep in &pkg.depends {
            if package_satisfies(pkg, dep)
                || tx.package_order[..index]
                    .iter()
                    .any(|earlier| package_satisfies(incoming[earlier.as_str()], dep))
                || installed.values().any(|old| {
                    old.name != *name
                        && anchors
                            .get(old.name.as_str())
                            .is_none_or(|anchor| *anchor > index)
                        && positions
                            .get(old.name.as_str())
                            .is_none_or(|position| *position >= index)
                        && package_satisfies(old, dep)
                })
            {
                continue;
            }
            return Err(invalid(format!(
                "apply {} {}: dependency {dep} is unavailable after removals in this slot; linked plans cannot use incoming cycle/order fallback",
                pkg.name, pkg.version,
            )));
        }
    }
    Ok(())
}

struct PlanGraph {
    labels: Vec<String>,
    edges: Vec<BTreeMap<usize, String>>,
}

impl PlanGraph {
    fn new(labels: Vec<String>) -> Self {
        Self {
            edges: vec![BTreeMap::new(); labels.len()],
            labels,
        }
    }

    fn before(&mut self, before: usize, after: usize, reason: String) {
        self.edges[before].entry(after).or_insert(reason);
    }

    fn order(&self) -> Result<Vec<usize>> {
        let mut indegree = vec![0usize; self.labels.len()];
        for edges in &self.edges {
            for &next in edges.keys() {
                indegree[next] += 1;
            }
        }
        let mut ready = BTreeSet::new();
        for (node, &degree) in indegree.iter().enumerate() {
            if degree == 0 {
                ready.insert((self.labels[node].as_str(), node));
            }
        }
        let mut order = Vec::new();
        while let Some((_, node)) = ready.pop_first() {
            order.push(node);
            for &next in self.edges[node].keys() {
                indegree[next] -= 1;
                if indegree[next] == 0 {
                    ready.insert((self.labels[next].as_str(), next));
                }
            }
        }
        if order.len() != self.labels.len() {
            return Err(self.cycle_error(&indegree));
        }
        Ok(order)
    }

    fn cycle_error(&self, indegree: &[usize]) -> ResolveError {
        let mut node = (0..self.labels.len())
            .filter(|&node| indegree[node] > 0)
            .min_by_key(|&node| &self.labels[node])
            .unwrap();
        let mut seen = BTreeMap::new();
        let mut path = Vec::new();
        // Every remaining node has a remaining predecessor. Following those
        // backwards finds an actual cycle, not merely nodes blocked by one.
        loop {
            if let Some(&start) = seen.get(&node) {
                let mut cycle = path[start..].to_vec();
                cycle.push(node);
                cycle.reverse();
                let constraints = cycle
                    .windows(2)
                    .map(|pair| {
                        let (before, after) = (pair[0], pair[1]);
                        format!(
                            "{} -> {}: {}",
                            self.labels[before], self.labels[after], self.edges[before][&after]
                        )
                    })
                    .collect();
                return ResolveError::ExecutionPlanCycle { constraints };
            }
            seen.insert(node, path.len());
            path.push(node);
            node = (0..self.labels.len())
                .filter(|&previous| {
                    indegree[previous] > 0 && self.edges[previous].contains_key(&node)
                })
                .min_by_key(|&previous| &self.labels[previous])
                .unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{
        InstallAction, RemovalAction, RemovalLink, RemovalReason, UpgradeAction,
    };
    use pax_core::package::Dependency;

    fn package(name: &str, version: &str, depends: &[&str], provides: &[&str]) -> PackageInfo {
        PackageInfo {
            name: name.into(),
            version: Version::parse(version).unwrap(),
            base: None,
            description: String::new(),
            url: None,
            arch: "any".into(),
            build_date: 0,
            packager: String::new(),
            licenses: vec![],
            groups: vec![],
            depends: depends
                .iter()
                .map(|dep| Dependency::parse(dep).unwrap())
                .collect(),
            optdepends: vec![],
            provides: provides
                .iter()
                .map(|dep| Dependency::parse(dep).unwrap())
                .collect(),
            conflicts: vec![],
            replaces: vec![],
            xdata: vec![],
        }
    }

    fn transaction(
        installed: &[PackageInfo],
        incoming: &[PackageInfo],
        order: &[&str],
        removals: &[(&str, &[&str])],
    ) -> Transaction {
        let mut tx = Transaction {
            installs: vec![],
            upgrades: vec![],
            removals: vec![],
            package_order: order.iter().map(|name| (*name).into()).collect(),
            total_download_size: 0,
            total_installed_size: 0,
        };
        for pkg in incoming {
            if let Some(old) = installed.iter().find(|old| old.name == pkg.name) {
                tx.upgrades.push(UpgradeAction {
                    name: pkg.name.clone(),
                    old_version: old.version.clone(),
                    new_version: pkg.version.clone(),
                    repository: "test".into(),
                    download_size: 0,
                    installed_size: 0,
                });
            } else {
                tx.installs.push(InstallAction {
                    name: pkg.name.clone(),
                    version: pkg.version.clone(),
                    explicit: true,
                    repository: "test".into(),
                    download_size: 0,
                    installed_size: 0,
                });
            }
        }
        for (name, links) in removals {
            tx.removals.push(RemovalAction {
                name: (*name).into(),
                version: installed
                    .iter()
                    .find(|pkg| pkg.name == *name)
                    .unwrap()
                    .version
                    .clone(),
                links: links
                    .iter()
                    .map(|incoming| RemovalLink {
                        incoming: (*incoming).into(),
                        reason: RemovalReason::Replaced,
                    })
                    .collect(),
            });
        }
        tx
    }

    fn step(incoming: &str, removals: &[&str]) -> ExecutionStep {
        ExecutionStep {
            incoming: incoming.into(),
            remove_before: removals.iter().map(|name| (*name).into()).collect(),
        }
    }

    #[test]
    fn interleaved_actions_keep_order_and_unrelated_removals_stay_late() {
        let installed = [
            package("middle", "1", &[], &[]),
            package("old", "1", &[], &[]),
            package("old-later", "1", &[], &[]),
        ];
        let incoming = [
            package("dep", "1", &[], &[]),
            package("middle", "2", &["dep"], &[]),
            package("new", "1", &["middle>=2"], &[]),
            package("app", "1", &["new"], &[]),
            package("later", "1", &[], &[]),
        ];
        let tx = transaction(
            &installed,
            &incoming,
            &["dep", "middle", "new", "app", "later"],
            &[("old", &["new"]), ("old-later", &["later"])],
        );
        let plan = execution_plan(&tx, &installed, &incoming).unwrap();
        assert_eq!(
            plan,
            vec![
                step("dep", &[]),
                step("middle", &[]),
                step("new", &["old"]),
                step("app", &[]),
                step("later", &["old-later"]),
            ]
        );
        assert_eq!(
            plan.iter().map(|step| &step.incoming).collect::<Vec<_>>(),
            tx.package_order.iter().collect::<Vec<_>>()
        );
        assert_eq!(tx.installs.len(), 4);
        assert_eq!(tx.upgrades.len(), 1);
    }

    #[test]
    fn merged_package_removes_consumers_before_providers_in_the_same_slot() {
        let mut installed = vec![
            package("a-library", "1:2-3", &[], &["abi=2:1-4", "other-api"]),
            package("z-consumer", "1", &["abi>=2:1-3", "other-api"], &[]),
            package("independent", "1", &[], &[]),
        ];
        let incoming = [package("merged", "1", &[], &[])];
        let mut tx = transaction(
            &installed,
            &incoming,
            &["merged"],
            &[
                ("a-library", &["merged"]),
                ("z-consumer", &["merged"]),
                ("independent", &["merged"]),
            ],
        );
        let expected = vec![step("merged", &["independent", "z-consumer", "a-library"])];
        assert_eq!(
            execution_plan(&tx, &installed, &incoming).unwrap(),
            expected
        );
        installed.reverse();
        tx.removals.reverse();
        assert_eq!(
            execution_plan(&tx, &installed, &incoming).unwrap(),
            expected
        );
    }

    #[test]
    fn split_package_is_removed_once_before_earliest_of_all_links() {
        let installed = [package("old", "1", &[], &[])];
        let incoming = [
            package("part-a", "1", &[], &[]),
            package("part-b", "1", &["part-a"], &[]),
        ];
        let mut tx = transaction(
            &installed,
            &incoming,
            &["part-a", "part-b"],
            &[("old", &["part-b", "part-a", "part-a"])],
        );
        tx.removals[0].links.push(RemovalLink {
            incoming: "part-b".into(),
            reason: RemovalReason::Conflict,
        });
        assert_eq!(
            execution_plan(&tx, &installed, &incoming).unwrap(),
            vec![step("part-a", &["old"]), step("part-b", &[]),]
        );
        assert_eq!(tx.removals[0].links.len(), 4);
    }

    #[test]
    fn compatible_cross_slot_removal_order_is_allowed() {
        let installed = [
            package("old-lib", "1", &[], &[]),
            package("old-app", "1", &["old-lib"], &[]),
        ];
        let incoming = [
            package("new-app", "1", &[], &[]),
            package("new-lib", "1", &[], &[]),
        ];
        let tx = transaction(
            &installed,
            &incoming,
            &["new-app", "new-lib"],
            &[("old-lib", &["new-lib"]), ("old-app", &["new-app"])],
        );
        assert_eq!(
            execution_plan(&tx, &installed, &incoming).unwrap(),
            vec![step("new-app", &["old-app"]), step("new-lib", &["old-lib"]),]
        );
    }

    #[test]
    fn impossible_cross_anchor_order_reports_the_constraint_cycle() {
        let installed = [
            package("old-lib", "1", &[], &[]),
            package("old-app", "1", &["old-lib"], &[]),
        ];
        let incoming = [
            package("new-lib", "1", &[], &[]),
            package("new-app", "1", &["new-lib"], &[]),
        ];
        let tx = transaction(
            &installed,
            &incoming,
            &["new-lib", "new-app"],
            &[("old-lib", &["new-lib"]), ("old-app", &["new-app"])],
        );
        let error = execution_plan(&tx, &installed, &incoming).unwrap_err();
        assert!(matches!(error, ResolveError::ExecutionPlanCycle { .. }));
        let message = error.to_string();
        for text in [
            "remove old-app",
            "remove old-lib",
            "apply new-lib",
            "needs old-lib",
            "slot before new-app",
            "Replaced link",
        ] {
            assert!(message.contains(text), "{message}");
        }
        assert_eq!(tx.package_order, ["new-lib", "new-app"]);
    }

    #[test]
    fn removal_cycles_are_not_appended_as_a_fallback_order() {
        let installed = [
            package("old-a", "1", &["old-b"], &[]),
            package("old-b", "1", &["old-a"], &[]),
        ];
        let incoming = [package("new", "1", &[], &[])];
        let tx = transaction(
            &installed,
            &incoming,
            &["new"],
            &[("old-a", &["new"]), ("old-b", &["new"])],
        );
        assert!(matches!(
            execution_plan(&tx, &installed, &incoming),
            Err(ResolveError::ExecutionPlanCycle { .. })
        ));
    }

    #[test]
    fn consumer_upgrade_must_precede_explicit_provider_removal() {
        let installed = [
            package("old", "1", &[], &[]),
            package("consumer", "1", &["old"], &[]),
        ];
        let incoming = [
            package("new", "1", &[], &[]),
            package("consumer", "2", &[], &[]),
        ];
        let tx = transaction(
            &installed,
            &incoming,
            &["consumer", "new"],
            &[("old", &["new"])],
        );
        assert_eq!(
            execution_plan(&tx, &installed, &incoming).unwrap(),
            vec![step("consumer", &[]), step("new", &["old"])]
        );
        let mut late = tx.clone();
        late.package_order.reverse();
        assert!(matches!(
            execution_plan(&late, &installed, &incoming),
            Err(ResolveError::ExecutionPlanCycle { .. })
        ));
        let mut same_slot = tx;
        same_slot.removals[0].links[0].incoming = "consumer".into();
        assert!(matches!(
            execution_plan(&same_slot, &installed, &incoming),
            Err(ResolveError::ExecutionPlanCycle { .. })
        ));
    }

    #[test]
    fn removed_consumer_cannot_lose_an_incompatibly_upgraded_provider() {
        let installed = [
            package("library", "1", &[], &["abi=1"]),
            package("old-app", "1", &["abi=1"], &[]),
        ];
        for compatible in [false, true] {
            let incoming = [
                package(
                    "library",
                    "2",
                    &[],
                    if compatible { &["abi=1"] } else { &["abi=2"] },
                ),
                package("new-app", "1", &[], &[]),
            ];
            let tx = transaction(
                &installed,
                &incoming,
                &["library", "new-app"],
                &[("old-app", &["new-app"])],
            );
            let result = execution_plan(&tx, &installed, &incoming);
            if compatible {
                assert_eq!(
                    result.unwrap(),
                    vec![step("library", &[]), step("new-app", &["old-app"])]
                );
            } else {
                assert!(matches!(
                    result,
                    Err(ResolveError::ExecutionPlanCycle { .. })
                ));
                let mut early = tx;
                early.package_order.reverse();
                assert_eq!(
                    execution_plan(&early, &installed, &incoming).unwrap(),
                    vec![step("new-app", &["old-app"]), step("library", &[])]
                );
            }
        }
    }

    #[test]
    fn only_unchanged_version_satisfying_alternatives_relax_outgoing_constraints() {
        for provided in ["virtual", "virtual=1", "virtual=2:1-4"] {
            let installed = [
                package("provider", "1", &[], &["virtual=2:1-4"]),
                package("consumer", "1", &["virtual>=2:1-3"], &[]),
                package("alternative", "99", &[], &[provided]),
            ];
            let incoming = [
                package("new-provider", "1", &[], &[]),
                package("new-consumer", "1", &[], &[]),
            ];
            let tx = transaction(
                &installed,
                &incoming,
                &["new-provider", "new-consumer"],
                &[
                    ("provider", &["new-provider"]),
                    ("consumer", &["new-consumer"]),
                ],
            );
            assert_eq!(
                execution_plan(&tx, &installed, &incoming).is_ok(),
                provided == "virtual=2:1-4"
            );
        }
    }

    #[test]
    fn every_matching_outgoing_provider_is_constrained_not_an_arbitrary_one() {
        let installed = [
            package("first", "1", &[], &["virtual=2"]),
            package("second", "1", &[], &["virtual=2"]),
            package("consumer", "1", &["virtual>=2"], &[]),
        ];
        let incoming = [
            package("early", "1", &[], &[]),
            package("late", "1", &[], &[]),
        ];
        let tx = transaction(
            &installed,
            &incoming,
            &["early", "late"],
            &[
                ("first", &["late"]),
                ("second", &["early"]),
                ("consumer", &["late"]),
            ],
        );
        let error = execution_plan(&tx, &installed, &incoming).unwrap_err();
        assert!(matches!(error, ResolveError::ExecutionPlanCycle { .. }));
        assert!(error.to_string().contains("from second"));
    }

    #[test]
    fn incoming_cycle_compatibility_is_unchanged_without_removals() {
        let incoming = [
            package("a", "1", &["b"], &[]),
            package("b", "1", &["a"], &[]),
        ];
        for order in [["a", "b"], ["b", "a"]] {
            let tx = transaction(&[], &incoming, &order, &[]);
            assert_eq!(
                execution_plan(&tx, &[], &incoming).unwrap(),
                vec![step(order[0], &[]), step(order[1], &[])]
            );
        }
        let installed = [package("old", "1", &[], &[])];
        let tx = transaction(&installed, &incoming, &["a", "b"], &[("old", &["a"])]);
        let message = execution_plan(&tx, &installed, &incoming)
            .unwrap_err()
            .to_string();
        assert!(message.contains("dependency b is unavailable"), "{message}");
        // An installed future upgrade can satisfy the first dependency now.
        let installed = [package("old", "1", &[], &[]), package("b", "0", &[], &[])];
        let tx = transaction(&installed, &incoming, &["a", "b"], &[("old", &["a"])]);
        assert_eq!(
            execution_plan(&tx, &installed, &incoming).unwrap(),
            vec![step("a", &["old"]), step("b", &[])]
        );
    }

    #[test]
    fn incoming_cannot_use_a_provider_removed_in_its_own_slot() {
        let installed = [package("old", "1", &[], &["api=2"])];
        let incoming = [
            package("app", "1", &["api>=2"], &[]),
            package("provider", "1", &[], &["api=2"]),
        ];
        let tx = transaction(
            &installed,
            &incoming,
            &["app", "provider"],
            &[("old", &["app"])],
        );
        let message = execution_plan(&tx, &installed, &incoming)
            .unwrap_err()
            .to_string();
        assert!(
            message.contains("dependency api>=2 is unavailable"),
            "{message}"
        );
    }

    #[test]
    fn incoming_uses_actual_selected_versions_and_provides() {
        let installed = [package("old", "1", &[], &[])];
        let incoming = [
            package("provider", "1", &[], &["api=2:1-4"]),
            package("app", "1", &["api>=2:1-3"], &[]),
        ];
        let tx = transaction(
            &installed,
            &incoming,
            &["provider", "app"],
            &[("old", &["app"])],
        );
        assert_eq!(
            execution_plan(&tx, &installed, &incoming).unwrap(),
            vec![step("provider", &[]), step("app", &["old"])]
        );
        let mut unavailable = incoming.clone();
        unavailable[0].provides = vec![Dependency::parse("api").unwrap()];
        assert!(
            execution_plan(&tx, &installed, &unavailable)
                .unwrap_err()
                .to_string()
                .contains("final state")
        );
    }

    #[test]
    fn final_state_checks_allow_preexisting_broken_retained_packages_only() {
        let installed = [
            package("old", "1", &[], &[]),
            package("broken", "1", &["missing"], &[]),
        ];
        let incoming = [package("new", "1", &[], &[])];
        let tx = transaction(&installed, &incoming, &["new"], &[("old", &["new"])]);
        assert!(execution_plan(&tx, &installed, &incoming).is_ok());
        let installed = [installed[0].clone(), package("broken", "1", &["old"], &[])];
        assert!(
            execution_plan(&tx, &installed, &incoming)
                .unwrap_err()
                .to_string()
                .contains("dependency old is unsatisfied")
        );
    }

    #[test]
    fn missing_or_stale_installed_actions_are_rejected() {
        let installed = [
            package("old", "1", &[], &[]),
            package("upgraded", "1", &[], &[]),
        ];
        let incoming = [
            package("new", "1", &[], &[]),
            package("upgraded", "2", &[], &[]),
        ];
        let tx = transaction(
            &installed,
            &incoming,
            &["upgraded", "new"],
            &[("old", &["new"])],
        );
        for index in 0..installed.len() {
            let mut missing = installed.to_vec();
            let name = missing.remove(index).name;
            let message = execution_plan(&tx, &missing, &incoming)
                .unwrap_err()
                .to_string();
            assert!(
                message.contains(&name) && message.contains("no longer installed"),
                "{message}"
            );
            let mut stale = installed.clone();
            stale[index].version = Version::parse("3").unwrap();
            let message = execution_plan(&tx, &stale, &incoming)
                .unwrap_err()
                .to_string();
            assert!(
                message.contains(&name) && message.contains("stale installed version"),
                "{message}"
            );
        }
        let mut duplicate = installed.to_vec();
        duplicate.push(installed[0].clone());
        assert!(execution_plan(&tx, &duplicate, &incoming).is_err());
        let mut already_installed = installed.to_vec();
        already_installed.push(incoming[0].clone());
        assert!(
            execution_plan(&tx, &already_installed, &incoming)
                .unwrap_err()
                .to_string()
                .contains("already installed")
        );
    }

    #[test]
    fn incoming_metadata_must_cover_exactly_the_action_identities() {
        let installed = [package("old", "1", &[], &[])];
        let incoming = [package("new", "1", &[], &[])];
        let tx = transaction(&installed, &incoming, &["new"], &[("old", &["new"])]);
        assert!(execution_plan(&tx, &installed, &[]).is_err());
        assert!(
            execution_plan(&tx, &installed, &[incoming[0].clone(), incoming[0].clone()]).is_err()
        );
        assert!(
            execution_plan(
                &tx,
                &installed,
                &[incoming[0].clone(), package("extra", "1", &[], &[])]
            )
            .is_err()
        );
        let message = execution_plan(&tx, &installed, &[package("new", "2", &[], &[])])
            .unwrap_err()
            .to_string();
        assert!(message.contains("expected version 1, found 2"), "{message}");
    }

    #[test]
    fn malformed_orders_actions_and_links_fail_without_a_fallback() {
        let installed = [package("old", "1", &[], &[])];
        let incoming = [package("new", "1", &[], &[])];
        let tx = transaction(&installed, &incoming, &["new"], &[("old", &["new"])]);
        for order in [
            vec![],
            vec!["new".into(), "new".into()],
            vec!["unknown".into()],
        ] {
            let mut invalid = tx.clone();
            invalid.package_order = order;
            assert!(execution_plan(&invalid, &installed, &incoming).is_err());
        }
        let mut duplicate = tx.clone();
        duplicate.installs.push(duplicate.installs[0].clone());
        assert!(execution_plan(&duplicate, &installed, &incoming).is_err());
        let mut duplicate = tx.clone();
        duplicate.removals.push(duplicate.removals[0].clone());
        assert!(execution_plan(&duplicate, &installed, &incoming).is_err());
        let mut unlinked = tx.clone();
        unlinked.removals[0].links.clear();
        assert!(execution_plan(&unlinked, &installed, &incoming).is_err());
        let mut dangling = tx;
        dangling.removals[0].links[0].incoming = "filtered".into();
        let message = execution_plan(&dangling, &installed, &incoming)
            .unwrap_err()
            .to_string();
        assert!(
            message.contains("missing incoming action filtered"),
            "{message}"
        );
    }

    #[test]
    fn same_package_cannot_be_removed_and_upgraded() {
        let installed = [package("app", "1", &[], &[])];
        let incoming = [package("app", "2", &[], &[])];
        let tx = transaction(&installed, &incoming, &["app"], &[("app", &["app"])]);
        assert!(
            execution_plan(&tx, &installed, &incoming)
                .unwrap_err()
                .to_string()
                .contains("both removal and incoming")
        );
    }

    #[test]
    fn empty_transaction_has_no_steps() {
        let tx = transaction(&[], &[], &[], &[]);
        assert_eq!(
            execution_plan(&tx, &[], &[]).unwrap(),
            Vec::<ExecutionStep>::new()
        );
    }
}
