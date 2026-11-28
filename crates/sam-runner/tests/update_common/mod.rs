//! For update tests against a local HTTPS server that need a process of
//! their own: the server with a throwaway certificate, test AppImages whose
//! update information points at it, and publishing a version there. A copy
//! of the helpers in `update_server.rs`, a protected test file that may only
//! gain lines; using this module there too needs the owner's approval.
//!
//! `start_server` sets process-wide variables (CURL_CA_BUNDLE, CURL_HOME,
//! NO_PROXY): a file with several tests runs them one at a time.
#![allow(clippy::unwrap_used, clippy::panic, dead_code)] // a test helper: a panic is a failed test

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use sam_core::Paths;
use sam_intake::testkit::{build, FixtureFile, FixtureSpec};
use sam_runner::ops::{AddOptions, Sam};

const SERVER: &str = r#"
import http.server, json, ssl, sys, os, threading, time
root, cert, key, log = sys.argv[1:5]
class Handler(http.server.SimpleHTTPRequestHandler):
    tag = ""
    def __init__(self, *a, **k):
        super().__init__(*a, directory=root, **k)
    # Every request whole, whatever its method, one JSON line each, for the
    # privacy test (update_privacy.rs): the request line and every header
    # the client sent, in its order. Read here, before the method decides
    # what the server answers, so no request is left out.
    def parse_request(self):
        ok = super().parse_request()
        if getattr(self, "headers", None) is not None:
            with open(log + ".headers", "a") as f:
                f.write(json.dumps({"tag": self.tag, "line": self.requestline,
                                    "headers": list(self.headers.items())}) + "\n")
        return ok
    def do_GET(self):
        rng = self.headers.get("Range")
        with open(log, "a") as f:
            f.write(f"{self.tag}{self.path} {rng}\n")
        # A test's hook: a file "swap-on-request" next to the served folder
        # holds two paths; the first request moves the first file over the
        # second (a file replaced while SAM is working).
        hook = os.path.join(os.path.dirname(root), "swap-on-request")
        if os.path.exists(hook):
            src, dst = open(hook).read().split("\n")[:2]
            os.replace(src, dst)
            os.remove(hook)
        # /redirect-https/NAME sends the client to NAME on this HTTPS server.
        if self.path.startswith("/redirect-https/"):
            self.send_response(302)
            self.send_header("Location", f"https://127.0.0.1:{srv.server_address[1]}/{self.path[16:]}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # /redirect/NAME sends the client to NAME on the plain HTTP server.
        if self.path.startswith("/redirect/"):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{plain.server_address[1]}/{self.path[10:]}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # /endless/NAME streams zeros without naming a length (64 MiB) and
        # logs how many pieces of 64 KiB the client took.
        if self.path.startswith("/endless/"):
            self.send_response(200)
            self.end_headers()
            sent = 0
            try:
                for _ in range(1024):
                    self.wfile.write(b"\0" * 65536)
                    sent += 1
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass
            with open(log, "a") as f:
                f.write(f"endless {sent}\n")
            return
        # /norange/NAME sends NAME whole, whatever range was asked for, as a
        # server that ignores Range does. /slow/NAME sends NAME (or the part
        # asked for) in pieces of 4 KiB, one every half second.
        mode = ""
        for m in ("norange", "slow"):
            if self.path.startswith(f"/{m}/"):
                mode, self.path = m, self.path[len(m) + 1:]
        path = self.translate_path(self.path)
        if not os.path.isfile(path):
            self.send_error(404)
            return
        data = open(path, "rb").read()
        if mode == "norange":
            rng = None
        if mode == "slow":
            part = data
            if rng and rng.startswith("bytes="):
                a, b = rng[6:].split("-")
                part = data[int(a):int(b) + 1]
                self.send_response(206)
            else:
                self.send_response(200)
            self.send_header("Content-Length", str(len(part)))
            self.end_headers()
            try:
                for i in range(0, len(part), 4096):
                    self.wfile.write(part[i:i + 4096])
                    self.wfile.flush()
                    time.sleep(0.5)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass
            return
        if rng and rng.startswith("bytes="):
            a, b = rng[6:].split("-")
            a = int(a)
            b = int(b) if b else len(data) - 1
            part = data[a:b + 1]
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {a}-{a + len(part) - 1}/{len(data)}")
            self.send_header("Content-Length", str(len(part)))
            self.end_headers()
            self.wfile.write(part)
        else:
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass
    def log_message(self, *a):
        pass
class Plain(Handler):
    tag = "plain "
# The same files over plain HTTP, which SAM must never use.
plain = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Plain)
threading.Thread(target=plain.serve_forever, daemon=True).start()
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print(srv.server_address[1], plain.server_address[1], flush=True)
srv.serve_forever()
"#;

pub struct Server {
    pub child: Child,
    pub port: u16,
    /// The same files over plain HTTP.
    pub plain_port: u16,
    pub root: PathBuf,
    pub log: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Whether SAM finds `tool` on the command search path (and may run it).
pub fn have(tool: &str) -> bool {
    sam_core::util::which(tool).is_some()
}

/// A local HTTPS server for `dir`, trusted by curl through CURL_CA_BUNDLE.
pub fn start_server(tmp: &Path) -> Server {
    let root = tmp.join("www");
    fs::create_dir_all(&root).unwrap();
    let (cert, key) = (tmp.join("cert.pem"), tmp.join("key.pem"));
    let st = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
        ])
        .args(["-addext", "subjectAltName=IP:127.0.0.1"])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "openssl could not make a certificate");
    let log = tmp.join("requests.log");
    let mut child = Command::new("python3")
        .args(["-c", SERVER])
        .arg(&root)
        .arg(&cert)
        .arg(&key)
        .arg(&log)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let mut ports = line
        .split_whitespace()
        .map(|p| p.parse().expect("the server prints its ports"));
    let (port, plain_port) = (ports.next().unwrap(), ports.next().unwrap());
    // curl (which SAM uses for downloads) trusts the test certificate.
    std::env::set_var("CURL_CA_BUNDLE", &cert);
    // The same result behind any proxy of the person running it.
    std::env::set_var("NO_PROXY", "127.0.0.1,localhost");
    std::env::set_var("no_proxy", "127.0.0.1,localhost");
    // SAM's curl never reads a ~/.curlrc: one that sends every request to a
    // dead proxy changes nothing (curl looks in CURL_HOME first).
    let curl_home = tmp.join("curl-home");
    fs::create_dir_all(&curl_home).unwrap();
    fs::write(
        curl_home.join(".curlrc"),
        "proxy = \"http://127.0.0.1:9\"\nnoproxy = \"\"\n",
    )
    .unwrap();
    std::env::set_var("CURL_HOME", &curl_home);
    Server {
        child,
        port,
        plain_port,
        root,
        log,
    }
}

/// A test AppImage whose update information points at `url`; `version`
/// changes its contents.
pub fn appimage(path: &Path, url: &str, version: &str) {
    let mut spec = FixtureSpec::hello("Tool");
    spec.comment = format!("Tool, version {version}");
    spec.files.push(FixtureFile {
        path: "usr/share/tool/data.bin".into(),
        data: vec![7u8; 300_000],
        mode: 0o644,
    });
    spec.files.push(FixtureFile {
        path: "usr/share/tool/version".into(),
        data: version.as_bytes().to_vec(),
        mode: 0o644,
    });
    spec.update_info = Some(format!("zsync|{url}"));
    build(path, &spec).unwrap();
}

/// Publishes `file` as `name` with its .zsync update description.
pub fn publish(server: &Server, file: &Path, name: &str) {
    fs::copy(file, server.root.join(name)).unwrap();
    let zsync =
        sam_runner::zsync::make(file, name, name, "Tue, 10 Nov 2026 10:00:00 +0000").unwrap();
    fs::write(server.root.join("Tool-x86_64.AppImage.zsync"), zsync).unwrap();
}

/// Starts the server and returns it with the update URL, or `None` where
/// the tools are missing (a skip that fails under SAM_REQUIRE_SANDBOX).
pub fn server_or_skip(tmp: &Path) -> Option<(Server, String)> {
    if !["python3", "openssl", "objcopy", "curl"]
        .iter()
        .all(|t| have(t))
    {
        sam_runner::contracts::skip("needs python3, openssl, objcopy and curl")
            .unwrap_or_else(|e| panic!("{e}"));
        return None;
    }
    let server = start_server(tmp);
    let url = format!(
        "https://127.0.0.1:{}/Tool-x86_64.AppImage.zsync",
        server.port
    );
    Some((server, url))
}

/// Adds `file` to a fresh SAM in `tmp/sam`, with its settings confirmed.
pub fn add_reviewed(tmp: &Path, file: &Path) -> (Sam, String) {
    let sam = Sam::with_paths(Paths::rooted(&tmp.join("sam"))).unwrap();
    let id = sam
        .add(
            file,
            &AddOptions {
                accept: true,
                launcher: Some(false),
                ..Default::default()
            },
        )
        .unwrap()
        .entry
        .id;
    (sam, id)
}

/// The version file inside the app's unpacked folder (what runs).
pub fn unpacked_version(sam: &Sam, id: &str) -> String {
    let x = sam.resolve(id).unwrap().extraction.unwrap();
    fs::read_to_string(x.appdir.join("usr/share/tool/version")).unwrap_or_default()
}
