# Architecture (developer documentation)

```
sam-jail-gui (GTK 4/libadwaita)  sam-jail / sam-jail-run (CLI)
        │  `sam-jail --json …`              │
        └──────────────┬───────────────────┘
                 sam-runner  (ops facade, launch, bwrap, doctor, diagnose, kernel)
     ┌────────┬────────┼─────────┬──────────────┐
  intake   detect   profile   storage     sam-sandbox
     └────────┴────────┴─────────┴──────────────┘
                   sam-core (model, permissions, risk, warnings, config, host, LaunchContext)
```

## GUI ↔ core

The GUI (`crates/sam-gtk`) is a GTK 4 / libadwaita window. Each operation runs
`sam-jail --json <args>` asynchronously. When a command needs a full profile,
preset or config, the GUI sends it as JSON on stdin (`profile set`,
`preset put`, `config put`, `evaluate`). Every response is a single envelope:

```json
{"ok": true, "data": …}
{"ok": false, "error": "human readable message"}
```

Apps are launched detached with `sam-jail-run --app-id <id>`, the same command
the desktop launchers use, so apps keep running when SAM closes. The GUI
links no SAM crate except `sam-core` (for the dangerous D-Bus name list):
the CLI is the API.

`sam-jail-gui --screenshot out.png [--size WxH] [--page …]` renders the
window once it has loaded (with `GDK_BACKEND=broadway` it works without a
desktop), and saves the scrollable content of the right column as
`out-content.png`.

## Sandbox command builder

SAM has one sandbox: Bubblewrap. `sam_sandbox::Bubblewrap` has two
functions:

```rust
impl Bubblewrap {
    pub fn status(&self, host: &HostInfo) -> BubblewrapStatus;         // installed / usable / notes
    pub fn build(&self, ctx: &LaunchContext) -> Result<SandboxCommand>;
}
```

`LaunchContext` holds everything needed to build a sandbox: the AppDir, the
entry point, the permission set, the host probe, the private home, the runtime
dir, the AppImage environment (`APPDIR`, `APPIMAGE`, `OWD`, …), the D-Bus
proxy socket, the Landlock helper, the seccomp fd, the tracer and extra binds.

## Launch pipeline

1. **Preflight:** the extraction exists; warn if the source is stale or missing.
2. **Sandbox check:** `bwrap.rs` verifies Bubblewrap can run here (installed,
   user namespaces allowed) or stops with a hint.
3. **Runtime dir:** generated `passwd` and `group`, an `xdg-dbus-proxy` for a
   filtered bus, and the Landlock spec.
4. **Build and spawn:** `Bubblewrap::build` produces the command, and stdout and
   stderr are teed into `~/.config/sam/logs/<id>/launch-*.log`.
5. **Record:** exit code or signal, plus a sandbox-failure classification (a
   `bwrap:` error, exit 126 or 127). The result goes into
   `AppEntry.last_launch` and the badge.

## Data model

See `crates/sam-core/src/model.rs`: `AppEntry`, `AppImageMetadata`,
`ExtractionInfo`, `DependencyReport`, `SandboxProfile`, `Preset`,
`LaunchRecord` and `DiagnosticReport`. The app registry stores one JSON file
per app; presets and the config are stored as TOML.

## Tests

- `cargo test --workspace`: unit tests in every crate.
- `crates/sam-runner/tests/sandbox.rs`: the end-to-end test. It builds a
  probe AppImage, adds it, launches it under several profiles, and checks from
  inside the sandbox what is visible and writable. It skips itself when bwrap
  cannot run.
- `sam-jail dev make-fixture <path> [--name] [--categories] [--apprun file]`
  builds synthetic AppImages for manual testing.
- `sam-jail-gui --screenshot out.png --page <page>` (with
  `QT_QPA_PLATFORM=offscreen`) renders the GUI headlessly.
