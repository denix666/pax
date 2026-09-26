pub mod build;
pub mod error;
pub mod resolve;
pub mod rpc;

pub use build::{clone_and_build, BuildResult};
pub use error::AurError;
pub use resolve::{resolve_aur_targets, AurTarget};
pub use rpc::{info as aur_info, search as aur_search, suggest as aur_suggest, AurPackage};
