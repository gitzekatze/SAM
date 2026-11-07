//! appseal-core: shared data model and policy logic for Appseal.
//!
//! Everything that both the GUI and the CLI need to agree on lives here:
//! the permission model, risk scoring, warnings, configuration, storage
//! paths, host probing and the backend adapter trait.

pub mod backend;
pub mod config;
pub mod host;
pub mod model;
pub mod paths;
pub mod permissions;
pub mod risk;
pub mod util;
pub mod warnings;

pub use backend::{Backend, BackendKind, BackendStatus, LaunchContext, SandboxCommand};
pub use config::Config;
pub use host::HostInfo;
pub use model::*;
pub use paths::Paths;
pub use permissions::*;
pub use risk::{RiskAssessment, RiskLevel};
pub use warnings::{Severity, Warning};

pub const APPSEAL_VERSION: &str = env!("CARGO_PKG_VERSION");
