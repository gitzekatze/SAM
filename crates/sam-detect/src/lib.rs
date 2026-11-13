//! sam-detect: AppImage format detection and dependency
//! detection.

pub mod appimage;
pub mod classify;
pub mod elf;
pub mod signature;
pub mod update_info;

pub use appimage::{inspect, looks_like_appimage, AppImageInfo, PayloadFormat};
pub use elf::{analyze_appdir, analyze_appdir_with, AnalyzeOptions};
