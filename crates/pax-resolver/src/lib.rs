pub mod error;
pub mod pool;
pub mod resolve;
pub mod topo;
pub mod transaction;
pub mod upgrade;

pub use error::ResolveError;
pub use pool::{ConcretePool, PackageCandidate, PackageId, PackagePool, PackageSource};
pub use resolve::{resolve, ResolveOptions, ResolvedPackage, ResolvedSet};
pub use topo::topological_sort;
pub use transaction::{build_transaction, InstallAction, RemovalAction, RemovalReason, Transaction, UpgradeAction};
pub use upgrade::compute_upgrades;
