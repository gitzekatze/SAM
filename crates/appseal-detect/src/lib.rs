//! appseal-detect: AppImage format detection (§2.11.1) and dependency
//! detection (§2.16).

pub mod appimage;
pub mod classify;
pub mod elf;

pub use appimage::{inspect, looks_like_appimage, AppImageInfo, PayloadFormat};
pub use elf::{analyze_appdir, AnalyzeOptions};
