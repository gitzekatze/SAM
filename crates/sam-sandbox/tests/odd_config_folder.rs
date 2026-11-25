//! A config or data folder (`XDG_CONFIG_HOME`, `XDG_DATA_HOME`) whose name
//! is not valid text stops the start: the start places below it could not
//! be named, so they would go unprotected. In its own file because it sets
//! these variables for the test process.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::os::unix::ffi::OsStrExt;

use sam_core::sandbox::sample_context;
use sam_sandbox::Bubblewrap;

#[test]
fn a_config_folder_whose_name_is_not_text_stops_the_start() {
    let ctx = sample_context();
    let odd = ctx.host.home.join(std::ffi::OsStr::from_bytes(b"cfg-\xff"));
    std::env::set_var("XDG_CONFIG_HOME", ctx.host.home.join(".config"));
    std::env::set_var("XDG_DATA_HOME", ctx.host.home.join(".local/share"));
    assert!(Bubblewrap.build(&ctx).is_ok());
    for var in ["XDG_CONFIG_HOME", "XDG_DATA_HOME"] {
        std::env::set_var(var, &odd);
        let e = Bubblewrap.build(&ctx).unwrap_err().to_string();
        assert!(
            e.contains("not valid text") && e.contains("cfg-"),
            "{var}: {e}"
        );
        std::env::remove_var(var);
    }
}
