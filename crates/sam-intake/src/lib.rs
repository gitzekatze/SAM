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
