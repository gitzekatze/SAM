//! What a start hands the app, end to end through `sam-jail` and SAM's
//! real helper in a real sandbox: the app's own variables only after the
//! helper's layers (review SB-5), no descriptor SAM inherited (F6), no
//! folder it cannot see as `$OWD` (audit L-F16), a start whose option
//! values read like Bubblewrap's separator (F5), private folders and logs
//! for the user only (F4, audit A2) and a full log that never loses the
//! start's record (audit L-F5). Skipped where Bubblewrap cannot run.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
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

/// `sam-jail` for a test rooted at `root`, as the person runs it.
fn sam_cmd(root: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sam-jail"));
    c.args(args)
        .env("SAM_CONFIG_DIR", root.join("config"))
        .env("SAM_DATA_DIR", root.join("data"))
        .env("SAM_APPLICATIONS_DIR", root.join("applications"))
        .env("HOME", root.join("home"))
        .stdin(Stdio::null());
    sam_runner::testenv::isolate_command(&mut c, &root.join("sam"));
    c
}

fn sam(root: &Path, args: &[&str]) -> Output {
    sam_cmd(root, args).output().unwrap()
}

fn json(out: &Output) -> serde_json::Value {
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(
        text.lines()
            .rfind(|l| !l.trim().is_empty())
            .unwrap_or("null"),
    )
    .unwrap_or_else(|e| panic!("{e}: {text}"))
}

/// Makes and adds a terminal program with this start script from a file
/// called `file_name`; returns its id. Bubblewrap must work here.
fn add(root: &Path, file_name: &str, script: &str) -> String {
    for d in ["config", "home", "images"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    let s = root.join("apprun");
    fs::write(&s, script).unwrap();
    fs::set_permissions(&s, fs::Permissions::from_mode(0o755)).unwrap();
    let img = root.join("images").join(file_name);
    let (img_s, s_s) = (img.to_str().unwrap(), s.to_str().unwrap());
    let made = sam(
        root,
        &[
            "dev",
            "make-fixture",
            "--name",
            "Plain",
            "--terminal",
            "--apprun",
            s_s,
            img_s,
        ],
    );
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let o = sam(root, &["--json", "add", img_s, "--no-launcher", "--accept"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    json(&o)["data"]["app"]["id"].as_str().unwrap().to_string()
}

fn set(root: &Path, id: &str, key: &str, value: &str) {
    let o = sam(root, &["set", id, key, value, "--yes"]);
    assert!(
        o.status.success(),
        "{key}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

/// The test's setup, or a recorded skip where Bubblewrap cannot run.
fn usable() -> bool {
    if !bwrap_works() {
        sam_runner::contracts::skip("bubblewrap cannot run here").unwrap_or_else(|e| panic!("{e}"));
        return false;
    }
    true
}

fn out_and_err(o: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// Review SB-5: variables from the app's settings (`environment.set`,
/// rated Medium, or from an imported preset) reach the app, but never the
/// loader of SAM's helper, which starts before Landlock and the syscall
/// filter. `LD_DEBUG` makes every loader that sees it write down what it
/// loads: the helper's own loading must not be in that record, while the
/// app's is (`LD_PRELOAD` would have run the app's library there).
#[test]
fn the_apps_variables_reach_it_only_after_the_helpers_layers() {
    if !usable() {
        return;
    }
    let _contracts = sam_runner::contracts::guard(&["bwrap-core", "kernel-seccomp"])
        .unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = add(
        root,
        "Loader-1.0-x86_64.AppImage",
        "#!/bin/sh\necho \"debug=$LD_DEBUG\"\n\
         echo \"helper=$(cat /tmp/ld.* 2>/dev/null | grep -c 'needed by /run/sam/sam-jail-run')\"\n\
         echo \"app=$(cat /tmp/ld.* 2>/dev/null | grep -c 'needed by /bin/')\"\n",
    );
    set(
        root,
        &id,
        "environment.set",
        r#"{"LD_DEBUG": "files", "LD_DEBUG_OUTPUT": "/tmp/ld"}"#,
    );
    let run = sam(root, &["run", &id]);
    let all = out_and_err(&run);
    assert!(run.status.success(), "{all}");
    assert!(
        all.contains("debug=files"),
        "the app has its variable: {all}"
    );
    assert!(
        !all.contains("app=0"),
        "the app's own loader acted on it: {all}"
    );
    assert!(
        all.contains("helper=0"),
        "the helper's loader never saw it: {all}"
    );
    // The helper really started the app (the syscall filter is on).
    let info = json(&sam(root, &["--json", "info", &id]));
    let enforced = info["data"]["entry"]["last_launch"]["enforcement"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(enforced.contains("seccomp: baseline loaded"), "{info}");
}

/// Review F6 and the audit's open item: a descriptor SAM inherited (a
/// terminal's or launcher's leak; here a pipe at number 7 without its
/// close-on-exec mark) never reaches the app, which could otherwise write
/// to whatever it leads to.
#[test]
fn a_descriptor_sam_inherited_never_reaches_the_app() {
    if !usable() {
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = add(
        root,
        "Leak-1.0-x86_64.AppImage",
        "#!/bin/sh\n( echo leaked >&7 ) 2>/dev/null && echo fd7=open || echo fd7=closed\n",
    );
    let mut ends = [0; 2];
    // SAFETY: pipe2 writes two descriptors into the array.
    let made = unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(made, 0);
    // SAFETY: both descriptors were just made and belong to this test.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
    let w = write.as_raw_fd();
    let mut c = sam_cmd(root, &["run", &id]);
    // SAFETY: between fork and exec only dup2, which is async-signal-safe;
    // the copy at 7 has no close-on-exec mark, as a leaked one has not.
    unsafe {
        c.pre_exec(move || {
            if libc::dup2(w, 7) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let run = c.output().unwrap();
    drop(write);
    let all = out_and_err(&run);
    assert!(run.status.success(), "{all}");
    assert!(
        all.contains("fd7=closed"),
        "the app got SAM's descriptor: {all}"
    );
    // What is in the pipe now, without waiting for its end.
    // SAFETY: fcntl only sets a flag on this test's own descriptor.
    unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
    let mut got = [0u8; 64];
    let n = std::io::Read::read(&mut fs::File::from(read), &mut got).unwrap_or(0);
    assert_eq!(n, 0, "the app wrote into it: {:?}", &got[..n]);
}

/// Audit L-F16: started from a folder the app cannot see, the app is not
/// told that folder's name as `$OWD`: it gets the folder it really starts
/// in, its home.
#[test]
fn an_app_is_never_told_a_folder_it_cannot_see() {
    if !usable() {
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = add(
        root,
        "Where-1.0-x86_64.AppImage",
        "#!/bin/sh\necho \"owd=$OWD\"\necho \"pwd=$(pwd)\"\n",
    );
    let private = root.join("home/private/clientX");
    fs::create_dir_all(&private).unwrap();
    let run = sam_cmd(root, &["run", &id])
        .current_dir(&private)
        .output()
        .unwrap();
    let all = out_and_err(&run);
    assert!(run.status.success(), "{all}");
    assert!(
        !all.contains("clientX"),
        "the folder's name stayed outside: {all}"
    );
    let home = root.join("home");
    let home = home.display();
    assert!(
        all.contains(&format!("owd={home}\n")) && all.contains(&format!("pwd={home}\n")),
        "OWD is where the app starts: {all}"
    );
}

/// Review F5: an option value that reads `--` (an AppImage file called
/// `--`, a terminal type set to it) is never taken for Bubblewrap's
/// separator when SAM adds its helper's status channel: the app starts.
#[test]
fn values_that_read_like_the_separator_break_no_start() {
    if !usable() {
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = add(
        root,
        "--",
        "#!/bin/sh\necho \"started as $ARGV0 on $TERM\"\n",
    );
    let run = sam_cmd(root, &["run", &id])
        .env("TERM", "--")
        .output()
        .unwrap();
    let all = out_and_err(&run);
    assert!(
        run.status.success() && all.contains("started as -- on --"),
        "{all}"
    );
}

/// Review F4 and audit A2: an app's private home and its own layer of the
/// app folder, and the start's log, are for the user only, also with the
/// usual umask (022) and when an older SAM made their folders readable for
/// everyone.
#[test]
fn private_folders_and_logs_are_for_the_user_only() {
    if !usable() {
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = add(
        root,
        "Private-1.0-x86_64.AppImage",
        "#!/bin/sh\necho secret > \"$HOME/profile\"\n",
    );
    set(root, &id, "advanced.persistent_home", "true");
    set(root, &id, "advanced.writable_appdir", "true");
    // As an older SAM left them.
    for d in ["data/homes", "data/overlays", "config/logs"] {
        fs::create_dir_all(root.join(d)).unwrap();
        fs::set_permissions(root.join(d), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut c = sam_cmd(root, &["run", &id]);
    // SAFETY: umask is async-signal-safe.
    unsafe {
        c.pre_exec(|| {
            libc::umask(0o022);
            Ok(())
        });
    }
    let run = c.output().unwrap();
    assert!(run.status.success(), "{}", out_and_err(&run));
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let home = root.join("data/homes").join(&id);
    assert!(home.join("profile").is_file(), "the app wrote its home");
    for d in [root.join("data/homes"), home] {
        assert_eq!(mode(&d), 0o700, "{}", d.display());
    }
    let overlay = root.join("data/overlays").join(&id);
    if overlay.exists() {
        for d in [root.join("data/overlays"), overlay] {
            assert_eq!(mode(&d), 0o700, "{}", d.display());
        }
    } else {
        assert_eq!(mode(&root.join("data/overlays")), 0o700, "tightened");
        sam_runner::contracts::not_here("no writable app folder here (Bubblewrap before 0.10)");
    }
    let info = json(&sam(root, &["--json", "info", &id]));
    let log = info["data"]["entry"]["last_launch"]["log_file"]
        .as_str()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| panic!("no log: {info}"));
    assert_eq!(mode(&log), 0o600, "{}", log.display());
    for d in [root.join("config/logs"), root.join("config/logs").join(&id)] {
        assert_eq!(mode(&d), 0o700, "{}", d.display());
    }
}

/// Audit L-F5: when the app's output fills the start's log to the limit
/// the system allows (a full disk the app may cause on purpose), the start
/// still ends normally and its record is saved, with its result. Here a
/// file-size limit of 256 KiB stands in for the full disk.
#[test]
fn a_full_log_never_loses_the_starts_record() {
    if !usable() {
        return;
    }
    let _contracts =
        sam_runner::contracts::guard(&["bwrap-core"]).unwrap_or_else(|e| panic!("{e}"));
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let id = add(
        root,
        "Chatty-1.0-x86_64.AppImage",
        "#!/bin/sh\nhead -c 1048576 /dev/zero | tr '\\0' x | fold -w 100\necho done-talking\n",
    );
    let mut c = sam_cmd(root, &["--json", "run", &id]);
    // SAFETY: between fork and exec only signal and setrlimit, plain
    // system calls on this process.
    unsafe {
        c.pre_exec(|| {
            // Writing past the limit fails (EFBIG) instead of ending SAM.
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            let limit = libc::rlimit {
                rlim_cur: 256 * 1024,
                rlim_max: 256 * 1024,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let run = c.output().unwrap();
    let err = String::from_utf8_lossy(&run.stderr);
    assert!(run.status.success(), "{err}");
    let info = json(&sam(root, &["--json", "info", &id]));
    let last = &info["data"]["entry"]["last_launch"];
    let log = std::path::PathBuf::from(last["log_file"].as_str().unwrap());
    assert!(
        fs::metadata(&log).unwrap().len() >= 256 * 1024,
        "the log reached the limit"
    );
    assert_eq!(last["success"], true, "{last}");
    assert_eq!(last["summary"], "exited normally", "{last}");
}
