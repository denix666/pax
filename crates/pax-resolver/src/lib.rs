pub mod error;
pub mod planning;
pub mod pool;
pub mod resolve;
pub mod topo;
pub mod transaction;
pub mod upgrade;

pub use error::{ResolveError, Result};
pub use planning::{ExecutionStep, execution_plan};
pub use pool::{ConcretePool, PackageCandidate, PackageId, PackagePool, PackageSource};
pub use resolve::{ResolveOptions, ResolvedPackage, ResolvedSet, resolve};
pub use topo::topological_sort;
pub use transaction::{
    InstallAction, RemovalAction, RemovalLink, RemovalReason, Transaction, UpgradeAction,
    build_transaction,
};
pub use upgrade::compute_upgrades;
