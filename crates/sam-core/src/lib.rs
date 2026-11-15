//! sam-core: shared data model and policy logic for SAM.
//!
//! Everything that both the GUI and the CLI need to agree on lives here:
//! the permission model, risk scoring, warnings, configuration, storage
//! paths, host probing and the sandbox launch context.

pub mod config;
pub mod error;
pub mod format;
pub mod host;
pub mod model;
pub mod paths;
pub mod permissions;
pub mod risk;
pub mod sandbox;
pub mod util;
pub mod warnings;

/// Level of the JSON interface (`sam-jail --json …`) that the window relies
/// on. Raise it whenever a command's JSON output or input changes in a way
/// an older or newer counterpart would misread. `sam-jail version` reports
/// it, and the window refuses to trust a command line tool with another one.
pub const JSON_INTERFACE: u32 = 1;

pub use config::Config;
pub use host::HostInfo;
pub use model::*;
pub use paths::Paths;
pub use permissions::*;
pub use risk::{RiskAssessment, RiskLevel};
pub use sandbox::{BubblewrapStatus, LaunchContext, SandboxCommand};
pub use warnings::{Severity, Warning};

pub const SAM_VERSION: &str = env!("CARGO_PKG_VERSION");
