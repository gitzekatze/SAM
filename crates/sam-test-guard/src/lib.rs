//! SAM's tests refuse to compile in a release build.
//!
//! A release build ignores SAM's developer variables: the folder variables
//! (`SAM_CONFIG_DIR`, `SAM_DATA_DIR`, `SAM_APPLICATIONS_DIR`,
//! `SAM_RUNTIME_DIR`) and the tool variables (`SAM_CLI`, `SAM_RUN`,
//! `SAM_LOCALE_DIR`, `SAM_DBUS_LOG`, `SAM_TRUST_TOOLS_IN`). SAM's tests keep
//! SAM away from the real folders and tools with exactly these variables, so
//! a test built in release mode would reach the real SAM folders of the
//! account running it, or real tools, and might still pass.
//!
//! Every other crate of SAM lists this crate under `[dev-dependencies]`,
//! which Cargo compiles only for test, bench and example targets, never for
//! a `cargo build` of the shipped programs. A test build without debug
//! assertions (a test run with `--release`, or with an optimisation level
//! above 0 in `RUSTFLAGS`) stops here with the message below. `crates/sam-jail-cli/tests/automation.rs` checks that every crate
//! lists it and that the guard stays in place.

#[cfg(not(debug_assertions))]
compile_error!(
    "SAM's tests rely on variables only a developer build reads (folders and tools): run them without --release and without an optimisation level above 0 in RUSTFLAGS (add -C opt-level=0 after the other flags)."
);
