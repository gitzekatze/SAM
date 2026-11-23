//! SAM unpacks an AppImage only inside a sandbox, also when a menu start
//! (`sam-jail-run`) unpacks it again after *Free Space* (threat model:
//! "SAM's own unpacker … run in a sandbox"). Without SAM's command line next
//! to `sam-jail-run`, the start refuses instead of unpacking unprotected.
//! Skipped when Bubblewrap cannot run here.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test
#![allow(clippy::disallowed_macros)] // a test's own notes, not SAM's output

use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn bwrap_works() -> bool {
    Command::new("bwrap")
        .args([
            "--ro-bind",
            "/",
            "/",
            "--unshare-user",
            "--unshare-pid",
            "true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn json(out: &Output) -> serde_json::Value {
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(text.lines().last().unwrap_or("null")).unwrap()
}

/// Runs one of SAM's programs from `bin` with its own folders under `root`.
///
/// The programs were just copied there. A process another test starts at
/// that moment inherits the copy's open file for an instant, and Linux
/// then refuses to run it ("Text file busy"); so a busy start is tried
/// again, for at most two seconds (seen in a full run on 2026-11-19).
fn sam(root: &Path, program: &str, args: &[&str]) -> Output {
    let start = std::time::Instant::now();
    loop {
        let out = Command::new(root.join("bin").join(program))
            .args(args)
            .env("SAM_CONFIG_DIR", root.join("config"))
            .env("SAM_DATA_DIR", root.join("data"))
            .env("SAM_APPLICATIONS_DIR", root.join("applications"))
            .env("XDG_RUNTIME_DIR", root.join("run"))
            .env("LC_ALL", "C")
            .env_remove("LANGUAGE")
            .env("PATH", "/usr/bin:/bin")
            .output();
        match out {
            Err(e)
                if e.kind() == std::io::ErrorKind::ExecutableFileBusy
                    && start.elapsed() < std::time::Duration::from_secs(2) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            out => return out.unwrap(),
        }
    }
}

/// A sandboxed fixture app whose unpacked copy was freed; returns its id.
fn freed_app(root: &Path) -> String {
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("run")).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_sam-jail"), root.join("bin/sam-jail")).unwrap();
    fs::copy(
        env!("CARGO_BIN_EXE_sam-jail-run"),
        root.join("bin/sam-jail-run"),
    )
    .unwrap();
    let img = root.join("Quick-1.0-x86_64.AppImage");
    let img_s = img.to_str().unwrap();
    assert!(sam(
        root,
        "sam-jail",
        &["dev", "make-fixture", "--name", "Quick", img_s]
    )
    .status
    .success());
    assert!(sam(root, "sam-jail", &["add", img_s, "--no-launcher"])
        .status
        .success());
    let id = json(&sam(root, "sam-jail", &["--json", "list"]))["data"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let freed = sam(root, "sam-jail", &["free-space", &id]);
    assert!(
        freed.status.success(),
        "{}",
        String::from_utf8_lossy(&freed.stderr)
    );
    id
}

fn unpacked_log(root: &Path, id: &str) -> Option<String> {
    fs::read_to_string(root.join("data/extracted").join(id).join("extraction.log")).ok()
}

#[test]
fn a_menu_start_after_free_space_unpacks_inside_a_sandbox() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = freed_app(root);
    assert!(
        unpacked_log(root, &id).is_none(),
        "Free Space removed the unpacked copy"
    );
    sam(root, "sam-jail-run", &["--app-id", &id]);
    let log = unpacked_log(root, &id).expect("the menu start unpacked the app again");
    assert!(
        log.contains("[extract] isolated"),
        "unpacking again ran inside the sandbox:\n{log}"
    );
}

#[test]
fn without_the_command_line_a_menu_start_refuses_to_unpack() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = freed_app(root);
    fs::remove_file(root.join("bin/sam-jail")).unwrap();
    let run = sam(root, "sam-jail-run", &["--app-id", &id]);
    let err = String::from_utf8_lossy(&run.stderr);
    assert!(!run.status.success(), "the start stops");
    assert!(err.contains("only inside a sandbox"), "and says why: {err}");
    assert!(
        unpacked_log(root, &id).is_none(),
        "nothing was unpacked: {err}"
    );
}

/// Every file below `dir`.
fn files_in(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(files_in(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

/// Unpacking limits hold inside the unpack sandbox too. Regression (audit
/// I-F3): when SAM's own reader hit the file or size limit inside the
/// sandbox, SAM saw only "failed", tried unsquashfs (which has only a time
/// limit) and then offered to let the AppImage unpack itself, so a crafted
/// image escaped the limits. The tests of the limits used to run without the
/// sandbox; this one goes through `sam-jail add`, which unpacks in it.
#[test]
fn an_unpacking_limit_inside_the_sandbox_stops_unpacking() {
    if !bwrap_works() {
        assert!(
            std::env::var("SAM_REQUIRE_SANDBOX").as_deref() != Ok("1"),
            "SAM_REQUIRE_SANDBOX=1, but Bubblewrap does not work here"
        );
        eprintln!("skipped: Bubblewrap does not work here");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("run")).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_sam-jail"), root.join("bin/sam-jail")).unwrap();
    let img = root.join("Tool-1.0-x86_64.AppImage");
    let img_s = img.to_str().unwrap();
    assert!(sam(
        root,
        "sam-jail",
        &["dev", "make-fixture", "--name", "Tool", img_s]
    )
    .status
    .success());
    assert!(sam(
        root,
        "sam-jail",
        &["config", "set", "extraction.max_files", "2"]
    )
    .status
    .success());
    let added = sam(
        root,
        "sam-jail",
        &["--json", "add", img_s, "--accept", "--no-launcher"],
    );
    let v = json(&added);
    assert_ne!(
        v["data"]["needs_fallback_consent"].as_bool(),
        Some(true),
        "no offer to let the AppImage unpack itself: {v}"
    );
    let logs: String = files_in(root)
        .iter()
        .filter_map(|f| fs::read_to_string(f).ok())
        .filter(|t| t.contains("[extract]"))
        .collect();
    assert!(
        logs.contains("[extract] isolated"),
        "unpacked in the sandbox:\n{logs}"
    );
    assert!(
        logs.contains("more than 2 files"),
        "the limit was hit:\n{logs}"
    );
    assert!(
        !logs.contains("trying unsquashfs"),
        "nothing else was tried:\n{logs}"
    );
    let app = &json(&sam(root, "sam-jail", &["--json", "list"]))["data"][0];
    assert_ne!(app["state"].as_str(), Some("ready"), "{app}");
    // The reason given is the limit's own message from inside the sandbox.
    let id = app["id"].as_str().unwrap();
    let info = json(&sam(root, "sam-jail", &["--json", "info", id]));
    assert!(
        info.to_string().contains("more than 2 files"),
        "the reason is shown: {info}"
    );
}

/// An update where SAM can build no sandbox stops at once with that reason,
/// before anything is downloaded or asked: the new version could be neither
/// unpacked nor its signature checked there. Before (review of PR 95), the
/// update was downloaded and, for a signed app, the question about its
/// signature said to install GnuPG, which was not the cause. Here the app
/// was added with Bubblewrap; the update runs where SAM finds none (curl
/// is still there), and its update source on this computer counts who
/// comes.
#[test]
fn an_update_without_a_sandbox_stops_before_downloading() {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for d in ["bin", "run", "tools"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    fs::copy(env!("CARGO_BIN_EXE_sam-jail"), root.join("bin/sam-jail")).unwrap();
    std::os::unix::fs::symlink("/usr/bin/curl", root.join("tools/curl")).unwrap();
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    server.set_nonblocking(true).unwrap();
    let port = server.local_addr().unwrap().port();
    let came = AtomicUsize::new(0);
    let done = AtomicBool::new(false);
    let img = root.join("Updating-1.0-x86_64.AppImage");
    let mut spec = sam_intake::testkit::FixtureSpec::hello("Updating");
    spec.update_info = Some(format!(
        "zsync|https://127.0.0.1:{port}/Updating-x86_64.AppImage.zsync"
    ));
    sam_intake::testkit::build(&img, &spec).unwrap();
    let added = sam(
        root,
        "sam-jail",
        &["add", img.to_str().unwrap(), "--no-launcher"],
    );
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    let id = json(&sam(root, "sam-jail", &["--json", "list"]))["data"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let updated = std::thread::scope(|s| {
        s.spawn(|| {
            while !done.load(Ordering::SeqCst) {
                match server.accept() {
                    Ok(_) => {
                        came.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
                }
            }
        });
        let out = Command::new(root.join("bin/sam-jail"))
            .args(["--json", "update", &id])
            .env("SAM_CONFIG_DIR", root.join("config"))
            .env("SAM_DATA_DIR", root.join("data"))
            .env("SAM_APPLICATIONS_DIR", root.join("applications"))
            .env("XDG_RUNTIME_DIR", root.join("run"))
            .env("LC_ALL", "C")
            .env_remove("LANGUAGE")
            // No Bubblewrap on the way; curl only, trusted from here.
            .env("PATH", root.join("tools"))
            .env("SAM_TRUST_TOOLS_IN", root.join("tools"))
            .output()
            .unwrap();
        done.store(true, Ordering::SeqCst);
        out
    });
    let reply = json(&updated);
    assert!(!updated.status.success(), "the update stops: {reply}");
    assert_eq!(reply["code"], "unpack-needs-sandbox", "{reply}");
    let message = reply["error"].as_str().unwrap_or_default();
    assert!(
        message.contains("Bubblewrap cannot run"),
        "and names the cause: {message}"
    );
    assert!(!message.contains("GnuPG"), "not GnuPG: {message}");
    assert_eq!(
        came.load(Ordering::SeqCst),
        0,
        "nothing was downloaded: {reply}"
    );
}


/// The host's unpacking tools unpack what SAM's own reader cannot, inside
/// the unpack sandbox, with the options SAM gives them (contract
/// unpack-tools; audit D-M10: its tests saw only SAM's own reader). A
/// SquashFS image compressed with lzo, which SAM's reader leaves to
/// `unsquashfs`, and an old type 1 AppImage (an ISO 9660 image), which only
/// `bsdtar` unpacks, both go through `sam-jail add` and come out whole.
#[test]
fn the_host_tools_unpack_what_sams_own_reader_cannot() {
    let tools = ["mksquashfs", "unsquashfs", "bsdtar"];
    if !bwrap_works() || tools.iter().any(|t| sam_core::util::which(t).is_none()) {
        sam_runner::contracts::skip("bubblewrap, mksquashfs, unsquashfs or bsdtar is missing here")
            .unwrap_or_else(|e| panic!("{e}"));
        return;
    }
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "unpack-tools"])
        .unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("run")).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_sam-jail"), root.join("bin/sam-jail")).unwrap();
    // An ordinary test AppImage, taken apart: its runtime and its files.
    let plain = root.join("Plain-1.0-x86_64.AppImage");
    let plain_s = plain.to_str().unwrap();
    assert!(sam(
        root,
        "sam-jail",
        &["dev", "make-fixture", "--name", "Plain", plain_s]
    )
    .status
    .success());
    let off = sam_detect::inspect(&plain).unwrap().payload_offset.unwrap() as usize;
    let tree = root.join("tree");
    let st = Command::new("unsquashfs")
        .args(["-quiet", "-no-progress", "-o", &off.to_string(), "-d"])
        .arg(&tree)
        .arg(&plain)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "the test AppImage's files");
    // The test image's top folder has no permissions of its own.
    fs::set_permissions(&tree, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let app_run = fs::read(tree.join("AppRun")).unwrap();
    let runtime = fs::read(&plain).unwrap()[..off].to_vec();

    // Type 2 with an lzo image: the runtime, then the image.
    let lzo = root.join("lzo.squashfs");
    let st = Command::new("mksquashfs")
        .arg(&tree)
        .arg(&lzo)
        .args([
            "-comp",
            "lzo",
            "-all-root",
            "-noappend",
            "-quiet",
            "-no-progress",
        ])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "mksquashfs made an lzo image");
    let type2 = root.join("Lzo-1.0-x86_64.AppImage");
    fs::write(&type2, [runtime.clone(), fs::read(&lzo).unwrap()].concat()).unwrap();

    // Type 1: an ISO 9660 image whose unused first sectors start with the
    // runtime's ELF header, marked as type 1 ("AI" and 1 at offset 8).
    let iso = root.join("old.iso");
    let st = Command::new("bsdtar")
        .args(["--format", "iso9660", "-cf"])
        .arg(&iso)
        .arg("-C")
        .arg(&tree)
        .arg(".")
        .status()
        .unwrap();
    assert!(st.success(), "bsdtar made an ISO 9660 image");
    let mut data = fs::read(&iso).unwrap();
    assert!(
        data[..64].iter().all(|b| *b == 0),
        "the system area is unused"
    );
    data[..64].copy_from_slice(&runtime[..64]);
    data[10] = 1;
    let type1 = root.join("Old-1.0-x86_64.AppImage");
    fs::write(&type1, data).unwrap();

    for (img, tool) in [(&type2, "unsquashfs"), (&type1, "bsdtar")] {
        let img_s = img.to_str().unwrap();
        let added = sam(
            root,
            "sam-jail",
            &["--json", "add", img_s, "--accept", "--no-launcher"],
        );
        let v = json(&added);
        assert!(added.status.success(), "{tool}: {v}");
        let entry = &v["data"]["entry"];
        let id = entry["id"]
            .as_str()
            .unwrap_or_else(|| panic!("{tool}: {v}"));
        let log = unpacked_log(root, id).unwrap_or_default();
        assert_eq!(
            entry["extraction"]["method"].as_str(),
            Some(tool),
            "unpacked by {tool}:\n{log}"
        );
        assert!(
            log.contains("[extract] isolated"),
            "{tool} ran in the sandbox:\n{log}"
        );
        let appdir = Path::new(entry["extraction"]["appdir"].as_str().unwrap());
        assert_eq!(fs::read(appdir.join("AppRun")).unwrap(), app_run, "{tool}");
        let mode = fs::metadata(appdir.join("AppRun")).unwrap().permissions();
        assert!(
            std::os::unix::fs::PermissionsExt::mode(&mode) & 0o111 != 0,
            "{tool}: AppRun stays a program"
        );
    }
}
