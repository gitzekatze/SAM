//! appseal-intake: the AppImage intake engine.
//!
//! * [`extract`]: static payload extraction with safety limits (§2.11.2-4)
//! * [`normalize`]: permission sanitization, symlink and file-type checks
//! * [`metadata`]: desktop entry and icon discovery (§2.11.6)
//! * [`desktop`]: launcher integration (§2.12)
//! * [`fingerprint`]: staleness detection (§2.11.7)
//! * [`id`]: human-readable, collision-free app ids
//! * [`testkit`]: builds synthetic AppImages for tests and demos

pub mod desktop;
pub mod extract;
pub mod fingerprint;
pub mod id;
pub mod metadata;
pub mod normalize;
pub mod testkit;
