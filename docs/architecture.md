# Architecture (developer documentation)

```
appseal-gui (Qt/QML/Kirigami)   appseal / appseal-run (CLI)
        │  `appseal --json …`              │
        └──────────────┬───────────────────┘
                 appseal-runner  (ops facade, launch, select, doctor, diagnose, kernel)
     ┌────────┬────────┼─────────┬──────────────┐
  intake   detect   profile   storage     backends (bubblewrap | bubblejail | firejail)
     └────────┴────────┴─────────┴──────────────┘
                   appseal-core (model, permissions, risk, warnings, config, host, Backend trait)
```

## GUI ↔ core

The GUI is a thin C++ shell (`gui/src/backend.cpp`). Each operation runs
`appseal --json <args>` asynchronously. When a command needs a full profile,
preset or config, the GUI sends it as JSON on stdin (`profile set`,
`preset put`, `config put`, `evaluate`). Every response is a single envelope:

```json
{"ok": true, "data": …}
{"ok": false, "error": "human readable message"}
```

Apps are launched detached with `appseal-run --app-id <id>`, the same command
the desktop launchers use. This keeps the GUI free of Rust↔C++ bindings (the
"thin C++ Qt shell" fallback from §2.9). The CLI is the API.

## Backend adapter API

```rust
pub trait Backend: Send + Sync {
    fn kind(&self) -> BackendKind;
    fn status(&self, host: &HostInfo) -> BackendStatus;       // installed / usable / risks
    fn build(&self, ctx: &LaunchContext) -> Result<SandboxCommand>;
}
```

`LaunchContext` holds everything needed to build a sandbox: the AppDir, the
entry point, the permission set, the host probe, the private home, the runtime
dir, the AppImage environment (`APPDIR`, `APPIMAGE`, `OWD`, …), the D-Bus
proxy socket, the Landlock helper, the seccomp fd, the tracer and extra binds.

To add a backend:

1. Implement the trait.
2. Register it in `appseal_runner::backend_for`.
3. Add selection rules in `appseal_runner::select`.

## Launch pipeline

1. **Preflight:** the extraction exists; warn if the source is stale or missing.
2. **Backend selection:** `select.rs`, following §2.13.3.
3. **Runtime dir:** generated `passwd` and `group`, an `xdg-dbus-proxy` for a
   filtered bus, and the Landlock spec.
4. **Build and spawn:** `Backend::build` produces the command, and stdout and
   stderr are teed into `~/.config/appseal/logs/<id>/launch-*.log`.
5. **Record:** exit code or signal, plus a sandbox-failure classification (a
   `bwrap:` error, exit 126 or 127). The result goes into
   `AppEntry.last_launch` and the badge.

## Data model

See `crates/appseal-core/src/model.rs`: `AppEntry`, `AppImageMetadata`,
`ExtractionInfo`, `DependencyReport`, `SandboxProfile`, `Preset`,
`LaunchRecord` and `DiagnosticReport`. The app registry stores one JSON file
per app; presets and the config are stored as TOML.

## Tests

- `cargo test --workspace`: unit tests in every crate.
- `crates/appseal-runner/tests/sandbox.rs`: the end-to-end test. It builds a
  probe AppImage, adds it, launches it under several profiles, and checks from
  inside the sandbox what is visible and writable. It skips itself when bwrap
  cannot run.
- `appseal dev make-fixture <path> [--name] [--categories] [--apprun file]`
  builds synthetic AppImages for manual testing.
- `appseal-gui --screenshot out.png --page <page>` (with
  `QT_QPA_PLATFORM=offscreen`) renders the GUI headlessly.
