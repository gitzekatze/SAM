//! sam-core: shared data model and policy logic for SAM.
//!
//! Everything that both the GUI and the CLI need to agree on lives here:
//! the permission model, risk scoring, warnings, configuration, storage
//! paths, host probing and the sandbox launch context.

pub mod backend;
pub mod config;
pub mod format;
pub mod host;
pub mod model;
pub mod paths;
pub mod permissions;
pub mod risk;
pub mod util;
pub mod warnings;

pub use backend::{BackendStatus, LaunchContext, SandboxCommand};
pub use config::Config;
pub use host::HostInfo;
pub use model::*;
pub use paths::Paths;
pub use permissions::*;
pub use risk::{RiskAssessment, RiskLevel};
pub use warnings::{Severity, Warning};

pub const SAM_VERSION: &str = env!("CARGO_PKG_VERSION");
