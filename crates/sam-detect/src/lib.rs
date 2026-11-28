//! sam-detect: AppImage format detection and dependency
//! detection.

// The privacy check (crates/sam-jail-cli/tests/network_use.rs): every way
// this program could reach the network or start a program is an #[expect]
// listed there (clippy.toml: disallowed-methods, disallowed-types).
#![cfg_attr(not(test), deny(clippy::disallowed_methods, clippy::disallowed_types))]

pub mod appimage;
pub mod classify;
pub mod elf;
pub mod signature;
pub mod update_info;

pub use appimage::{inspect, looks_like_appimage, AppImageInfo, PayloadFormat};
pub use elf::{analyze_appdir, analyze_appdir_with, AnalyzeOptions};
