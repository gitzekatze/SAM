//! sam-intake: the AppImage intake engine.
//!
//! * [`extract`]: static payload extraction with safety limits
//! * [`normalize`]: permission sanitization, symlink and file-type checks
//! * [`metadata`]: desktop entry and icon discovery
//! * [`desktop`]: launcher integration
//! * [`fingerprint`]: staleness detection
//! * [`id`]: human-readable, collision-free app ids
//! * `testkit`: builds synthetic AppImages for tests and demos (development
//!   builds and the `dev-tools` feature only, never release builds)

// The privacy check (crates/sam-jail-cli/tests/network_use.rs): every way
// this program could reach the network or start a program is an #[expect]
// listed there (clippy.toml: disallowed-methods, disallowed-types).
#![cfg_attr(not(test), deny(clippy::disallowed_methods, clippy::disallowed_types))]

pub mod desktop;
pub mod extract;
pub mod fingerprint;
pub mod id;
pub mod menu;
pub mod metadata;
pub mod normalize;
pub mod peek;
#[cfg(any(debug_assertions, feature = "dev-tools"))]
pub mod testkit;
