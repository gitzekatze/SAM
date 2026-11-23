# Architecture (developer documentation)

This page describes SAM after the [C4 model](https://c4model.com/) in three
levels: SAM in its surroundings (context), the programs and stores SAM
consists of (containers), and the parts inside them (components). The code
itself is the fourth level. The sections after the overview explain the
interfaces in detail. Every part named here has its tests listed in
[the test library](test-library.md), and [SAM's functions](functions.md#components-and-their-functions)
shows which functions each component carries.

## Level 1: Context

```mermaid
flowchart LR
    user(["Person using the desktop"])
    sam["SAM: creates sandboxes for AppImages and starts apps in them"]
    appimage[("AppImage files: untrusted programs from the internet")]
    desktop["Desktop session: Wayland compositor, session D-Bus with portals, PipeWire"]
    kernel["Linux kernel: namespaces, seccomp, Landlock"]
    tools["System tools: Bubblewrap, xdg-dbus-proxy, pasta"]
    updates["Update servers named by the AppImage, only when the user checks"]
    user -->|"chooses permissions, starts apps"| sam
    sam -->|"reads, unpacks, never runs outside a sandbox"| appimage
    sam -->|"starts the app inside"| tools
    tools -->|"builds the sandbox with"| kernel
    sam -->|"passes only the allowed parts of"| desktop
    sam -.->|"optional update check over HTTPS"| updates
```

A person uses SAM to turn an AppImage into an app that runs in a sandbox
with only the access that person allows. SAM treats every AppImage as
untrusted: it reads and unpacks the file itself and never runs it outside a
sandbox. The sandbox is built by Bubblewrap from the kernel's namespaces,
with a syscall filter and Landlock on top. Desktop services reach the app
only through filters: xdg-dbus-proxy for the session bus, a Wayland security
context for the compositor, and pasta for "this computer only". SAM contacts
the internet only when the user checks for updates, and only the addresses
the AppImage names.

## Level 2: Containers

```mermaid
flowchart TB
    gui["sam-jail-gui: the window, GTK 4 and libadwaita"]
    cli["sam-jail: the command line; every operation, JSON interface"]
    run["sam-jail-run: starts an app from its menu entry; applies Landlock inside the sandbox"]
    cfg[("~/.config/sam: settings, the user's presets, logs")]
    data[("~/.local/share/sam: app records, unpacked apps, private homes, icons")]
    menu[("~/.local/share/applications: SAM's menu entries")]
    box["The sandbox at run time: Bubblewrap with the app, plus xdg-dbus-proxy, pasta and a terminal relay"]
    gui -->|"sam-jail --json …, one call per action"| cli
    cli --> cfg
    cli --> data
    cli --> menu
    menu -->|"Exec=sam-jail-run --app-id …"| run
    run --> box
    cli -->|"Launch button"| box
```

The window never changes SAM's files itself: every action is one call of
`sam-jail --json`, so the command line and the window always behave the same
and every action can be scripted and tested without a display. `sam-jail-run`
is what menu entries start; it reads the app record, builds the sandbox and
starts the app. Settings and the user's presets live in `~/.config/sam`; app
records, unpacked apps and the apps' private home folders live in
`~/.local/share/sam`. Sandboxed apps cannot see either folder.

## Level 3: Components

```mermaid
flowchart TB
    subgraph clients["Programs"]
        gtk["sam-gtk: window pages, permission editor, Permissions page"]
        clic["sam-jail-cli: commands, JSON output, sam-jail-run"]
    end
    runner["sam-runner: operations facade (add, launch, verify, repair, update, group changes), D-Bus proxy, network namespace, terminal relay, Wayland context, diagnostics"]
    intake["sam-intake: safe unpacking, metadata, icons, menu entries, IDs"]
    detect["sam-detect: AppImage format, ELF analysis, toolkits, signatures, update info"]
    profile["sam-profile: recommendations, the user's presets, change checks, permission tags"]
    sandbox["sam-sandbox: Bubblewrap command from the permissions"]
    storage["sam-storage: app records, presets, logs"]
    core["sam-core: permission model, risk, warnings, configuration, file formats, host facts, translations, error codes"]
    gtk -->|JSON| clic
    gtk --> core
    clic --> runner
    clic --> intake
    clic --> detect
    clic --> profile
    clic --> storage
    clic --> core
    runner --> intake
    runner --> detect
    runner --> profile
    runner --> sandbox
    runner --> storage
    runner --> core
    intake --> detect
    intake --> core
    detect --> core
    profile --> storage
    profile --> core
    sandbox --> core
    storage --> core
```

Every arrow is a real dependency; the test
`the_component_diagram_shows_the_real_dependencies` fails when the diagram
and the code disagree. The window uses sam-core only for shared names (the
permission catalog); everything it does goes through `sam-jail --json`.

| Component | Responsibility | Untrusted input it handles |
|---|---|---|
| sam-core | What a permission is, how risky it is, which warnings apply, the configuration and the versions of SAM's files; translations (gettext) and error codes | none (pure model) |
| sam-detect | Recognizes the AppImage format and what the program inside needs (libraries, toolkit, X11 or Wayland) | the AppImage file, ELF headers, start scripts |
| sam-intake | Unpacks an AppImage without running it, with limits on size, file count and time; reads name, icon and desktop file; writes menu entries | the squashfs or DwarFS image, desktop files, icons |
| sam-profile | Recommends permissions from what the app declares and contains; checks a change for what an app would lose; turns permissions into tags | metadata from the AppImage |
| sam-sandbox | Builds the Bubblewrap command line from a set of permissions | none (permissions are SAM's) |
| sam-runner | Carries out every operation and runs the helpers of a sandbox | the app's output (terminal relay), logs |
| sam-storage | Reads and writes app records, presets and logs; moves damaged files aside | SAM's own files, possibly changed by others |
| sam-jail-cli | Turns commands into operations and results into text or JSON | command-line arguments, JSON on stdin |
| sam-gtk | Shows the results and asks the user; contains no sandbox logic | none (talks only to sam-jail) |

The trust boundary runs at sam-detect and sam-intake: everything taken from
an AppImage is treated as data, never as code or as trusted text (markup is
neutralized before it is shown). The parsers there are fuzzed
(`crates/sam-runner/tests/fuzz.rs`, see the [threat model](threat-model.md)).

## Texts and languages

Every text a person reads is translated where it is made, with
`sam_core::i18n` (gettext, text domain `sam`); the window shows the
messages of the command line as they come. Because the texts are
translated, no code may decide anything by comparing a message: an error that
code must recognize carries a code (`sam_core::error::CodedError`), which the
JSON envelope passes on as `"code"`. Logs, codes and the JSON keys stay
English. [Translating SAM](translating.md) has the details.

## GUI ↔ core

The GUI (`crates/sam-gtk`) is a GTK 4 / libadwaita window. Each operation runs
`sam-jail --json <args>` asynchronously. When a command needs a full profile,
preset or config, the GUI sends it as JSON on stdin (`profile set`,
`preset put`, `config put`, `evaluate`). Every response is a single envelope:

```json
{"ok": true, "data": …}
{"ok": false, "error": "a message in the user's language", "code": "signing-key-changed"}
```

`code` is present only for errors the window must recognize.

Apps are launched detached with `sam-jail-run --app-id <id>`, the same command
the desktop launchers use, so apps keep running when SAM closes. The GUI
links no SAM crate except `sam-core` (for the permission catalog and the
translations): the CLI is the API.

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
2. **Bubblewrap check:** `bwrap.rs` verifies Bubblewrap can run here (installed,
   user namespaces allowed) or stops with a hint.
3. **Runtime dir:** generated `passwd` and `group`, an `xdg-dbus-proxy` for a
   filtered bus, the Landlock spec, and Room service's socket and stand-in
   (`room_service.rs`).
4. **Build and spawn:** `Bubblewrap::build` produces the command, and stdout and
   stderr are teed into `~/.config/sam/logs/<id>/launch-*.log`. The command
   is also the app's *floor plan* for Room service (`room_rules.rs`), which
   then serves the app's requests for rooms until the start ends.
5. **Record:** exit code or signal, plus a sandbox-failure classification (a
   `bwrap:` error, exit 126 or 127), and a line per room built or refused.
   Every room ends before SAM waits for the app's output. The result goes
   into `AppEntry.last_launch` and the badge.

## Data model

See `crates/sam-core/src/model.rs`: `AppEntry`, `AppImageMetadata`,
`ExtractionInfo`, `DependencyReport`, `SandboxProfile`, `Preset`,
`LaunchRecord` and `DiagnosticReport`. The app registry stores one JSON file
per app; presets and the config are stored as TOML.

## Tests

The complete list, with what each test proves, is the
[test library](test-library.md) (`scripts/test-library.py`).

- `cargo test --workspace`: unit tests in every crate.
- `crates/sam-runner/tests/sandbox.rs`: the end-to-end test. It builds a
  probe AppImage, adds it, launches it under several profiles, and checks from
  inside the sandbox what is visible and writable. Where Bubblewrap cannot
  run it skips itself, except in CI, where `SAM_REQUIRE_SANDBOX=1` turns
  that skip into a failure.
- `sam-jail dev make-fixture <path> [--name] [--categories] [--apprun file]`
  builds synthetic AppImages for manual testing.
- `sam-jail-gui --screenshot out.png --page <page>` (with
  `GDK_BACKEND=broadway`) renders the window without a desktop.
- `scripts/function-map.py` checks that every function has its tests and
  writes [functions.md](functions.md); `scripts/i18n.py check` keeps the
  three translations complete. [Testing](testing.md) explains the rest.
