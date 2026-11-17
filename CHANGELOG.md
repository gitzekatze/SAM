# Changelog

All notable changes to SAM. Versions follow [Semantic Versioning](https://semver.org/):
before 1.0, a minor version (0.x) may change the command line or the JSON
output; patch versions (0.x.y) only fix bugs.

`scripts/release.sh` takes the *Unreleased* section as the notes of the next
version.

## Unreleased

### Three promises kept again (found by an independent review)

- **An app can no longer write to the clipboard through leading zeros.**
  SAM's terminal filter read at most 10 digits of a control code, so
  `00000000052` was cut to 5 and passed on, while terminals read it as 52
  (clipboard). Codes are now compared by value, and a number longer than
  any real code is removed whole; `CSI 021 t` (a title report) is caught too.
- **A bug report no longer contains the values of variables you gave an
  app** (API keys, tokens): the launch log's command line hides them, and a
  short run's log tail, which the report quotes, is that line.
- **An AppImage whose start file links to `/dev/zero` (or is huge) can no
  longer fill SAM's memory while it is added:** files inside an unpacked
  AppImage are read only when regular, and only up to a limit.
- **A folder set to read & write stays writable when the whole home is
  read-only.** Before, Documents (or another folder) set to read & write was
  silently read-only in that case.

### One building block fewer

- SAM no longer uses the `chrono` library, which was declared unmaintained
  (RUSTSEC-2026-0543): the current time comes from the standard library,
  local and UTC dates from the C library SAM already uses. 175 lines fewer
  in `Cargo.lock`, and the dependency check is green again.

### The window is checked in every state an app can be in

- The window smoke test opens an app's page in each state that shows
  differently (needs review, compatibility mode, last start failed, repair
  step on, changed outside SAM) and checks first that each state is really
  there; a page that breaks in one state only is no longer missed.
- It runs the same on every computer: its own home folder and no desktop
  settings, so neither the Downloads folder nor the theme and fonts of the
  person running it change the result.
- A window screenshot that saves nothing says why (nothing shown yet, nothing
  drawn, no renderer) instead of staying silent.

### Rules for automation

- The handbook starts with **How SAM looks after itself**: the whole
  maintenance machine on one page, what runs without the maintainer, where
  they are needed, and a weekly routine of about 15 minutes.
- A sandbox test that cannot run fails in CI instead of skipping
  (`SAM_REQUIRE_SANDBOX=1`), so a green run always tested the sandbox.
- Protected tests may only gain lines; any removed or changed line needs
  the owner's label. The approval is its own check, "Needs your approval",
  and setting the label reruns only that check.
- The permission matrix and the breakout test run in named sections: a
  failure names the part (`CHECK FAIL breakout/landlock`), and the other
  sections still run.
- The automation's repository-specific lists live in `keeper.toml`; the
  scripts are general (preparation for a reusable maintenance tool).
  Removing anything from its lists needs the owner's label.
- **AUTOMATION.md** sets the rules for automated upkeep: what automation
  may do, what it may never do, risk classes, and a kill switch
  (`SAM_AUTOMATION`).
- Every pull request gets a risk class (low to critical) from the files it
  touches.
- **A contract verifier** blocks every weakening of a security promise
  (contracts, functions, syscall review, threat model, protected tests,
  safety lists) and every new dependency unless the owner sets the label
  `owner-approved`.
- A workflow check refuses the known ways a GitHub workflow can hand the
  repository to an attacker.

### Contracts with the outside world

- **A contract map** (`docs/contracts.toml`, page `docs/contracts.md`): every
  assumption SAM makes about programs, the kernel, the file system,
  sockets, variables, desktop services and file formats, with what SAM
  does when it breaks (always to the safe side), its tests and a playbook.
  CI fails when the code uses something outside SAM that no contract
  covers.
- `sam-jail doctor --contracts` checks the contracts on any computer and
  names the versions of the components; bug reports include it.
- Sandbox tests check their contracts first: a failure says "CONTRACT
  BROKEN: …" (the outside world changed) or "SAM ERROR" (SAM's own code).
- CI records each run's outside world; a failed run lists what changed
  since the last green one.
- Every night SAM is built and tested on Fedora Rawhide, Debian testing,
  Ubuntu's development release, Arch and Tumbleweed, and every week the
  release notes of the projects it builds on are read; both open issues
  when something SAM relies on changes.
- The first early-warning runs found that openSUSE keeps vendor settings in
  `/usr/etc` (the sandbox now shares those few files from there too) and
  that GitHub's machines block pasta through AppArmor (lifted on the
  throwaway runner). Every contract now says whether its tests cover it
  fully or partly and what is not tested; sound, D-Bus and X11 report
  their versions; paths built at runtime are checked; ten sandbox tests
  check their contracts first.
- Every syscall of the kernel is reviewed for the baseline filter, and a
  test names any new one. The first, `fchroot` (Linux 7.3), was found on
  Arch and is allowed like `chroot`.

### Two promises of the threat model kept everywhere

- **Unpacking always runs inside a sandbox.** A start from the menu that
  unpacks an app again after *Free Space* used SAM's reader without a
  sandbox, because only the program named `sam-jail` set one up. Now every
  SAM program uses the `sam-jail` next to it, and when no sandbox can be
  built, SAM refuses to unpack and says why instead of unpacking
  unprotected.
- **An update that cannot be checked needs your consent.** When the
  installed version was signed and checked, but the update's signature
  cannot be checked (GnuPG missing), SAM stops and asks, as it does for a
  changed signing key. Before, such an update was installed without asking.

### Risk ratings that match what a permission can do

- **The full session bus is rated Dangerous**, like allowing systemd by
  name: on the full bus an app can ask systemd to start programs outside
  its sandbox. Its explanation and compatibility mode's warning now say so.
- **The file that says where your user folders are**
  (`~/.config/user-dirs.dirs`) stays read-only even with a writable home,
  so an app cannot point other apps' Documents or Downloads grant at
  another folder.
- **A diagnostic run cannot be talked into a wider grant.** Its trace lies
  in a folder the app can write, so paths with `..` are ignored and a
  low-risk grant is always a real folder of shared system data, never a
  parent such as `/usr`.

### Every error names the part of SAM it happened in

- An error from the command line, the window or a start from the menu
  names the SAM function it happened in (`(SAM function 3)` on the
  terminal, `"function": 3` in `--json`): the promise, its code and its
  tests in docs/functions.md. Recognizing a file is function 2, unpacking
  it 3, starting 19. A check makes sure every number exists.

### Smaller things that behave the same everywhere

- **`sam-jail run` checks the sandbox before a start** when *Check the
  sandbox before each start* is on, like a start from the menu. All starts
  now share one check.
- **Launch logs stop at 16 MiB** with a note, and an app's output is read
  in pieces, so an app that prints without end can fill neither the disk
  nor SAM's memory; the app never stalls on a full pipe.
- **The command line names risk like the window**: Harmless, Think twice
  or Dangerous. `sam-jail list --risk` accepts these words and the old
  names.
- **A download that broke off is recognized**: SAM says the file is
  incomplete and should be downloaded again, instead of creating a sandbox
  that cannot start.
- **A missing library is named first** when an app cannot start because
  of it, instead of a general "entry point not found".

### Tests that cannot run are never silent

- Tests find SAM's helper `sam-jail-run` of their own build, so the
  breakout test, the sandbox check and the stop test no longer skip
  themselves when `PATH` was not set by hand.
- `make test` ends with the list of tests that did not run here and why
  (`$SAM_SKIP_LOG`); in CI a test that cannot run still fails.
- The hostile-AppImage test also finds the helper of its own build. Before,
  it failed for every change in a mutation run, so every change counted as
  caught ([report](docs/reports/mutants-2026-11-16.md), addendum).
- `scripts/mutants.sh` runs mutation testing with the settings that make
  its result true: whole workspace, skips refused, the whole suite first on
  the unchanged code, a short runtime folder of its own, two changes at a
  time. `scripts/mutants-report.py` names the SAM function of every change
  the tests miss, and refuses a run in which a test never passed.

### Real AppImages compared by group

- `tests/real-apps/compare.py` compares two real-app runs (or a run with
  the last published report) by group of apps, and groups the apps a group
  lost by their reason, so a regression points at one part of SAM instead
  of a list of names.

### Security and reliability (from an outside code audit)

- **A sandbox with "This computer only" could outlive SAM.** When SAM's
  launcher was killed, pasta (which sits between SAM and the sandbox in this
  mode) kept running, and the app with it. The process SAM starts now dies
  with the launcher in every mode; a test kills the launcher hard and checks
  that nothing of the sandbox survives.
- A test now proves that with "This computer only" a listed port on your
  computer is reachable and an unlisted one is not.
- Desktop services are shared with a sandbox only when they are real
  sockets, so a wrong session variable can never put an ordinary file into
  the sandbox.
- A malformed internal pasta command is refused with an error instead of a
  crash.
- No `.unwrap()` outside tests anymore (a lint enforces it): every possible
  failure is handled, or its `expect` says why it cannot happen.
- SHA-1 and MD4, which the zsync update format prescribes, are confined to
  the update code by a test; the threat model states what updates of
  unsigned apps can and cannot promise.
- **No silent loss of protection.** When a start lacks a layer its settings
  ask for (Landlock or the syscall filter, for example because SAM's helper
  is missing), the command line warns, the app's page says which layer was
  missing, and the overview marks the app *Protection missing* until a start
  has every layer again.
- `panic!`, `todo!` and `unimplemented!` are not allowed outside tests (a
  lint enforces it).
- Every release comes with an SBOM (SPDX): every component built into SAM,
  with version and license, signed like the other release files.
- The security page names where an outside review should start.
- Mutation testing of the audited files found four gaps, now closed with
  tests: SAM never runs an AppImage's own unpacker without consent, a
  sensitive file named at the start stays out, the machine ID reaches only
  apps with D-Bus, and a delta update must really be assembled from the
  changed parts.

### First start

- The app page shows the settings first; saving a preset comes last.
- The "Bubblewrap" tag appears only when the sandbox cannot run.
- The filter says "Not sandboxed", like the list.

### Website

- The website shows the repository's documents and writes nothing of its
  own: README.md is the front page, the Use and Trust overviews are
  documents (docs/use.md, docs/trust.md), and the dashboard is built from
  scripts/dashboard.py with every change. A document's shape decides the
  design: three bold steps become a flow, longer lists become rows, short
  ones cards, and bars become real bars.
- Numbers are never typed by hand: scripts/facts.py fills them into the
  documents from the repository (tests, functions, the newest real-AppImage
  and mutation reports), and CI fails when a document quotes an old one.
- A full mutation run (docs/reports/mutants-2026-11-16.md) records every
  change on its own: 3,011 changes, 84.8 % of the buildable ones caught,
  and the weakest files named (the sandbox check, the terminal relay, the
  kernel layers). The report of 2026-11-15 had figures that did not match
  its run's records.
- The results of the 120 real AppImages are published as a report
  (docs/reports/real-apps-2026-11-15.md), made by
  `tests/real-apps/table.py --markdown`.
- The README is rewritten as the front page's text: why AppImages need a
  sandbox, what SAM does differently, how it works, and the evidence.
- The dashboard shows what the tests prove area by area and the evidence
  behind SAM's promises, as tiles, bars and a chart on the website.
- Every page and every point has its own icon, and a page keeps its icon
  wherever it is linked. The website build stops if two of them share one.
- CONTRIBUTING.md names SAM's five columns (Reliability, Security,
  Simplicity, Compatibility, Privacy); they guide the work and are no
  longer shown on the website.
- Every page has a breadcrumb trail, Previous and Next links that go round
  in a loop, and a link back to its section; the side menu and the
  overviews use small icons.
- Wide tables use the full width and scroll on their own on phones; long
  code names wrap instead of squeezing the columns.
- *Use SAM* has an overview page and a *What's new* page (the changelog);
  *How SAM is tested* and *Architecture* moved to *Trust SAM*.
- The window tests also run under GNOME (a headless Mutter), not only under
  KDE's KWin.
- CI skips the build, test, window and sandbox jobs for pull requests that
  change only documents or the website, so they can be merged in about a
  minute; every change to code still runs all of them.
- The maintainer handbook (*Maintain SAM*) is about processes: changing,
  updating and releasing SAM, and looking after its repository.

### Signed releases

- SAM has a release key (fingerprint
  `AFE940EDA5A0C5C4B94B0A3FB1764CFD72A238E6`), and SAM updates itself only to
  an AppImage signed with it.
- The AppImages are signed on the maintainer's computer after GitHub has
  built and tested them (`scripts/sign-release.sh`), so the key never goes to
  GitHub; every release file also gets a detached `.asc` signature.
- `scripts/new-version.sh X.Y.Z` makes a release in one go: it checks that
  everything is ready, asks once for the key's passphrase, tags on a branch
  `release-X.Y.Z`, opens a pull request (`main` is protected), waits for
  GitHub's build, seals the AppImages, merges the pull request with a merge
  commit once its checks pass, and ends at the draft release, which a
  person publishes.

### German, Spanish and French

- The main menu has **Language**: follow the system, or choose English,
  Deutsch, Español or Français, each named in its own language. SAM's window
  restarts in the new language; apps keep the language of the system.
- *Permissions of All Apps* is now called **Permission Manager**.
- SAM speaks to you informally in every language: du in German, tú in
  Spanish, tu in French. The translation check refuses the formal forms.
- SAM speaks German, Spanish and French: every text in the window, every
  message from SAM's core (permissions, warnings, repair advice, check
  results, update and error messages) and the command line's sentences.
  Logs, the technical tables of `info`, `preview` and `report`, and the JSON
  interface stay English.
- Every text was reworded into whole sentences first, so each language can
  order its words freely; code that needed to know which error happened now
  reads an error code instead of the message.
- CI fails when a text lacks a translation in one of the three languages or
  a translation drops a placeholder.

### Reliability beyond the first start

- An app that connected to the filtered session bus right after the start
  could be refused: SAM waited for the proxy's socket file, which appears a
  moment before the proxy listens. SAM now waits until a connection works.
- "Allow diagnostic runs" in Preferences now works: when it is off, SAM runs
  no app under strace. Two switches that did nothing ("Remove unpacked
  copies of apps that are gone", "Verbose logging") are gone.
- docs/profiles.md is now docs/permissions.md: the permission keys, preset
  files and group changes, without the outdated table of category defaults.
- A new SAM icon now reaches the taskbar: SAM marks the icon folders as
  changed, so the desktop's icon cache stops showing the old icon.
- When SAM's own SquashFS reader stopped at the size limit, the window
  did not recognize it as a limit (the error lost its code), so it did not
  explain how to raise the limit. Mutation testing found it.
- The check whether the unpacking folder supports overlays no longer
  leaves a locked `.overlay-check-…` folder behind in SAM's data each time
  it runs, and removes the ones earlier versions left.
- Unpacking checks the free space first and refuses with what to do
  instead of filling the disk; if the disk still fills up, SAM removes
  what was unpacked and says so.
- Clearer messages for the unpack limits (why they exist, how to raise
  them), a missing xdg-dbus-proxy or curl, and an app that is not
  unpacked.
- The real-app harness checks more than the first start: unanswered D-Bus
  calls, error dialogs, recommendation stability, leftovers, and with
  CHECKS a start without network and sound, a second start and a start in
  German; tests/real-apps/checks.py summarizes a run in one line per app.
- The header bar no longer uses strict centering, which made libadwaita
  1.5 (Ubuntu 24.04) need 409 px in a 360 px window.

### Security tests that prove every promise

- The evil-AppImage suite: 18 hostile AppImages, each trying one escape,
  go through the normal path (added, started with the recommended
  settings); every attempt fails, writes are judged on the host, and
  desktop-service attempts run against stand-ins on a private test bus.
- SAM notices app records changed outside SAM (a checksum in every record
  SAM saves) and does not start such an app until you confirm its
  settings ("Confirm Settings", or `sam-jail review APP`).
- Mutation fuzzing of the parsers for untrusted input (AppImage images,
  desktop files, zsync files, update information, ELF programs). It found
  a crash: a damaged SquashFS image made the reader panic, and because SAM
  reads names and icons in its own process, one such file in a searched
  folder emptied the whole list. Fixed; a regression test keeps the file.
- The threat model (docs/threat-model.md): what SAM protects, whom it
  trusts, each threat with what stops it and the test that proves it, and
  plainly what it cannot protect against, including programs that run
  outside any sandbox.
- **Test** also checks that typing into the terminal is blocked and, with
  full home access, that autostart and menu entries cannot be created.
- CI runs the sandbox tests on Fedora too.

### Clear decisions on the app page

- **Test** replaces Check and Test start: the settings check, then a short
  real start; the header always shows the test state (not tested yet,
  tested with the date, out of date, failed). The update check's button is
  now *Check for Updates*.
- One place for advice: what went wrong, repair steps, hints and a warning
  about unsandboxed menu entries (with *Hide It*) in one group. Repair
  steps are switches that say what they change and what protection that
  costs; each can be switched off on its own (`sam-jail repair APP
  --undo-step ID`). Compatibility mode names the switches it turns on.
- "Local network only" is now called "This computer only", which is what
  it means: no internet and no local network, only the listed services on
  this computer.
- The syscall filters and Landlock are a group of their own, "Extra
  Protection Layers", with an explanation of when turning one off is right.
- "Files This App Saved" is a visible row with the folder's path.
- The remove dialog offers three named choices (only the unpacked copy;
  the sandbox but keep the settings; everything); none is preselected and
  the button names the action.
- Downloads is an ordinary location; *Add Downloads* replaces the switch,
  and a switch that was on becomes a location once.
- The CUDA and ROCm notes say what a missing part means for local AI
  models: they run on the processor, which is much slower.
- "Recognized as" appears only when the category explains the
  recommendation.

### A calmer main window

- Sandboxed apps show their own icon and name in the taskbar. The app ID
  SAM gives the compositor is now the name of SAM's menu entry; KWin names
  sandboxed windows after it, and before found no matching entry.
- The reload button sits at "AppImages found", next to the busy indicator;
  the header bar holds only the logo, the title and the menu, with the
  title exactly between them and the logo as tall as the title.
- On an app's page, a round trash button left of Check replaces the
  "Remove Sandbox" text button (the confirmation stays); icon, title and
  buttons line up at the top, and every button explains itself on hover.
- While an app runs, its page says that changed settings apply at the next
  start and offers "Restart".
- Diagnostics: `SAM_DBUS_LOG=FILE` makes SAM's D-Bus proxy log every call;
  `scripts/dbus-log-summary.py FILE` lists unanswered and blocked calls.

### Permissions of All Apps

- A new page, opened with *Permissions of All Apps* above the list of
  AppImages, shows every sandboxed app with tags for what it may access
  (Network, Files, Devices, Desktop; the color shows the risk, an outline
  means read-only). Tags above the list filter by permission (has / has
  not / off) and by state (running, needs review, may not start).
- Several apps can be selected (check boxes, Shift-click for a range,
  *Select all* for the filtered apps) and changed together. Where the apps
  differ, each value gets its own row with the apps below it, and each app
  has a small switch of its own. Changes apply at once with one Undo for
  the whole change; SAM asks first only when an app would stop working.
- `sam-jail group list/set/restore` do the same on the command line.

### Tests and documentation

- A review of every document against SAM as it is: wrong command names in
  the README and testing guide (`sam-jail sandbox`, `sam-jail show`), an
  install section that described packages not yet published, the risk
  levels, outdated button and mode names, a `tests/README.md` that named a
  folder that does not exist, and an overstated claim ("every security
  promise names its test": the threat model does; the security page is
  checked by the breakout test). CI now fails when the threat model names a
  test that does not exist. The testing guide starts with an overview of
  every kind of test.
- The website's front page explains why SAM is good (the gap it closes,
  what it does differently, its five promises); line icons replace emoji;
  the dashboard explains what the tests prove, area by area, and how SAM is
  tested; it works on phones without sideways scrolling.
- docs/install.md is an install guide for users, honest that the first
  release is still being prepared, with building from source as a section
  for testers. The README's install section points to it.
- SAM has a website (GitHub Pages), built from the repository on every
  change: Use SAM (install, guide), Trust SAM (security, threat model,
  dashboard, functions, tests, mutation testing) and Maintain SAM.
- A maintainer handbook (docs/handbook/) for beginners: where everything
  is, how GitHub works for SAM, everyday work, every tool, and what to look
  at weekly, monthly and yearly.
- The window is clicked through on every push: a new test follows the main
  flow (Create Sandbox, Launch) and the window in German and English, and
  the app page, Permission Manager and accessibility tests now run in CI too.
- `make mutants-diff` checks that the tests of a change would catch a
  mistake in it, and CONTRIBUTING describes when to write the test first.
- An upgrade test builds the last released SAM, creates apps, settings and a
  preset with it, and checks that the new version keeps them and still
  starts the apps; `scripts/new-version.sh` runs it before every release.
- Updates are tested end to end against a local HTTPS server: finding the
  newer version, downloading only the changed parts, swapping the file while
  keeping the old one, refusing a damaged download, and refusing plain HTTP.
- Mutation testing before the release ([report](docs/reports/mutants-2026-11-15.md)):
  314 of 2,835 deliberate code changes (11.1 %) went unnoticed; the gaps it showed in
  the unpacking limits, the sandbox command, the terminal filter and the
  update checksums now have tests.
- The test library (docs/test-library.md, made by `scripts/test-library.py`)
  lists every automated test with the promise it keeps; CI fails when it is
  out of date. Every change now comes with a test, every fixed bug with a
  regression test (CONTRIBUTING.md).
- New regression suites: group changes and Undo, the user's presets, the
  JSON interface of `group` and `preset`, the change check, one name per
  permission across tags and the risk list, colors and the startup order of
  the window, valid values of the group switches.
- The Permissions page is checked through the accessibility interface
  (`tests/gui/permissions-atspi.sh`, in an invisible KWin session made by
  `tests/gui/session.sh`).
- The version report (`make report`, docs/reports/): for each part of SAM
  the passing and failing tests, its line coverage, how long its steps take
  (`sam-jail dev bench`: unpacking, analysis, the sandbox command, creating
  a sandbox, a real start, the Permissions page with 120 apps) and its
  dependencies, compared with the previous report.
- A test checks the relations between the parts against the C4 rules: the
  window depends only on sam-core, lower parts never on higher ones, and
  the component diagram shows exactly the real dependencies.
- docs/architecture.md describes SAM after the C4 model: context, programs
  and stores, components with the untrusted input each one handles.

### Removed

- The six built-in presets (Strict Browser, Media Player Safe, Game
  Performance, Untrusted Utility, Office Documents Only, Image Editor) and
  the preset picker on the app page. SAM's recommendation for each app fits
  better than a set made for a whole category. Your own presets stay, under
  ☰ → *My Presets*; `sam-jail preset check` is gone with the picker.

### Security

- App records changed outside SAM can no longer make SAM delete folders
  outside its own: a record whose id is not a safe name (or differs from its
  file name) is ignored, and removing a sandbox deletes the unpacked app only
  after resolving its real path inside SAM's unpack folder. Before, an id
  like `../../.ssh` or an unpack folder like `extracted/../../Documents`
  in a tampered or damaged record would have been deleted on removal.
- SAM's own menu entry keeps only clean categories and file types: a
  changed record could otherwise have added a line such as a second
  `Exec=`, which would start the app without a sandbox.
- "Go back to the earlier version" moves only files in SAM's backup folder;
  a changed record could otherwise have made SAM move any of the user's
  files.

- Apps started from a terminal never get the user's terminal: SAM puts them
  on a pseudo-terminal of its own and passes the bytes on. As before, they
  cannot type commands into the shell (`TIOCSTI`); now escape codes for the
  clipboard, desktop notifications, tmux passthrough and window-title
  reports are removed from their output too, and terminal replies still
  queued when they end are discarded. (Before, Bubblewrap's new session
  stopped typed-in commands, but passed every escape code on and cut
  terminal programs off from resizing.) The app page and each start say
  what a terminal program can and cannot reach.
- Nested namespaces are off by default; only apps whose engine builds its own
  sandbox (Electron, CEF, Qt WebEngine, WebKitGTK) get them.
- Full home read/write: more persistence paths stay read-only (`~/.local/bin`,
  D-Bus service files, `mimeapps.list`, KWin/Plasma scripts, service menus,
  git and editor configs), also when they do not exist yet.
- A granted folder that contains the home gets the same protection as full
  home access.
- SAM's own folders are hidden whenever a grant would show them.
- *Local network only* runs the app with the user's ids (it ran as root, so
  Electron apps did not start and the D-Bus proxy rejected every app).
- `systemd-run` inside the sandbox runs the command inside it;
  `flatpak-spawn` refuses.
- Blocked D-Bus names win over wildcard allow entries.
- The syscall filter also covers the x32 ABI, and blocks `io_uring`.
- Wayland security context: each app gets its own Wayland socket, and the
  desktop hides privileged functions (background clipboard access, screen
  capture, fake input) from it. *Privileged Wayland protocols* turns this
  off for tools that need them.
- *Audio* gives only the PulseAudio socket. The raw PipeWire socket, which
  also reaches cameras and other apps' screen-cast streams, is a separate
  advanced permission (*Direct PipeWire access*); the sandbox check confirms
  it is absent.
- `cargo deny` checks advisories, licences and sources in CI; Dependabot
  proposes updates; `scripts/release.sh` signs releases by default.
- New breakout test suite; security review report
  (`docs/reports/security-review-2026-11-10.md`).

### Added

- `sam-jail uninstall` removes every trace of SAM (lists first; `--yes`).
- `sam-jail stop`, `sam-jail remove --stop`, and *Close and Remove* in the
  window for apps still running (also in the system tray).
- *Check the setup* and *Test start* per app; the sandbox check also works
  before a sandbox exists.
- The extraction folder can be chosen in Preferences.
- Terminal programs: no display or GPU, and *Launch* opens a terminal.
- `sam-jail preset check`; the window asks before a conflicting preset also
  when no sandbox exists yet.
- Single SAM window per data set.
- Man pages for `sam-jail`, `sam-jail-run` and `sam-jail-gui`.
- Translations (gettext): the window's own text can be translated; German
  is the first language (`docs/translating.md`).
- The list of AppImages updates by itself when files appear in or
  disappear from a location (a finished download, a deleted file).
- Screen readers announce every icon-only button by name; the blue label
  keeps enough contrast in light and dark style.
- 64-bit ARM (aarch64): an AppImage of SAM is built for it, and CI tests
  it once the repository is public; the breakout test uses each
  architecture's syscall numbers.
- Update check: SAM reads where an AppImage's updates are published (its
  update information: zsync or GitHub releases) and tells whether a newer
  version exists, with a link to download it. Only on request (*Check* on
  an app's page, `sam-jail updates`), or once a day at start when turned on
  in Preferences.
- *Update Now* (`sam-jail update APP`) downloads the newest version, checks
  it against the published checksum and the signing key, and puts it in
  place; settings stay. The replaced version is kept, and *Go back to the
  previous version* (`--undo`) restores it.
- Updates download only the changed parts when the AppImage publishes a
  zsync description (e.g. 5.5 of 11.5 MB for Neovim 0.12.5 → 0.12.6), and
  fall back to the whole file otherwise.
- SAM's own AppImage updates itself: *Check for SAM Updates* in the main
  menu, or `sam-jail self-update [--check]`. Release builds carry SAM's
  update information and a `.zsync` file.
- `SECURITY.md` (private vulnerability reports), `CONTRIBUTING.md` and issue
  forms.
- Disk space per app (details, Diagnostics, `sam-jail space`) and *Free
  Space*: deletes the unpacked copy, which is unpacked again before the next
  start (`sam-jail free-space`).
- AppImage signatures are checked and shown; an update signed with another
  key, or no longer signed, gets a warning.
- AppImages with lz4-compressed SquashFS are unpacked by SAM's own reader.
- AppImages with a DwarFS image (uruntime) are recognised and unpacked with
  `dwarfsextract` when the dwarfs tools are installed.
- The JSON interface is documented (`docs/json-interface.md`).
- `sam-jail version` reports the JSON interface level; the window says so
  clearly when its command line tool is from another version.

### Changed

- While Downloads is not searched, its switch says how many AppImages are
  there (browsers save new AppImages to Downloads).
- Asking to let an AppImage unpack itself is worded plainly, and for DwarFS
  AppImages names the dwarfs package that avoids the question; the command
  line says which command to use.
- When an app stops right after starting, the notification has a *Show the
  fix* button that opens SAM at that app; its page shows *What went wrong
  last time* first, with the fix one click away.
- SAM's files carry a format number: old ones are migrated (original kept),
  newer ones are never changed, damaged ones are moved aside and reported.
- Risk is shown with the permission that sets it (*High risk · Network +1*)
  instead of a score.
- *Compatibility mode* and *May not start* are separate labels; *May not
  start* clears after the first successful start.
- Log analysis reads stdout as well as stderr.
- `advanced.extra_backend_args` is now `advanced.extra_bwrap_args` (old
  profiles still load). Internally, the crate `sam-backend-bubblewrap` is
  now `sam-sandbox`.
- Detection skips bundled musl (Alpine) variants.
- The app is called *SAM - Sandboxed AppImage Manager* everywhere it
  introduces itself: window title, About, menu entry, metainfo, man pages,
  packages.
- The AppImage locations no longer scroll in a small box: the list grows
  with every location and the whole left column scrolls.
- README and security page rewritten.

### Fixed

- Compatibility, from a test of 71 real AppImages (59 started before these
  fixes, 69 after; the other 2 are terminal tools):
  - Apps with an older bundled libxcb (many Qt and Java apps) could not
    connect to X11 even with X11 allowed: Landlock refused the abstract
    socket and old libxcb gives up instead of using the socket file. The
    sandbox now uses its own display number (:99) with a matching cookie.
  - Apps whose AppImage bundles only Qt's X11 plugin, and apps whose start
    script forces X11 (linuxdeploy's GTK hook, Tauri apps), get X11 in
    their recommendation.
  - X11 apps share the IPC namespace (as Flatpak's `--share=ipc`); GTK and
    Electron apps died with BadAccess from MIT-SHM.
  - With both Wayland and X11 allowed, Qt picks the platform itself; the
    list `wayland;xcb` stopped Qt before 5.12.
  - GTK's image loaders (glycin, gdk-pixbuf 2.44+) are visible; apps using
    the system's GTK aborted at the first icon.
  - Apps may own the D-Bus name of their own reverse-DNS ID (as with
    Flatpak); a refused name in the log is offered as a repair step.
  - Programs that load OpenGL or Vulkan only at run time (WezTerm, Rust
    apps) get the GPU; their EGL setup failed and no window appeared.
  - Qt apps that switch Qt to X11 in their own code (MuseScore and
    Audacity 4, which name their own `MU_`/`AU_QT_QPA_PLATFORM`) and Qt
    apps whose Wayland plugin lacks its bundled Qt Wayland library
    (OpenShot) get X11 from the start instead of after a repair step.
  - Terminal programs (Helix, Neovim, command-line tools) work in the
    terminal: they get a terminal of SAM's own, see the files and folders
    named when they start (`hx notes.txt`, `hx .`, relative to the folder
    they start in) and adapt to window resizing. A test start gives them a
    terminal too, and a tool that ends with an error code of its own (wrong
    arguments) no longer counts as a failed start, so repair steps no
    longer weaken their sandbox for nothing. From the menu, the window stays
    open after an error until Enter is pressed.
  - Second test set of 26 AppImages from groups the first lacked
    (Flutter, Tauri, Wails, sharun/anylinux, Wine, .NET/Avalonia, Java
    launcher, GTK4, Python): 20 started at once. Group-wide fixes:
    - Apps may own the D-Bus name of their window class (GTK and Flutter
      apps register their application ID there: Hiddify could not start)
      and KDE apps their org.kde.<app> name with its numbered variants
      (Kdenlive could not start). Names a service on this computer starts
      on demand are refused at every start.
    - The EGL driver configuration is shown without GPU access too, so
      apps that draw with OpenGL fall back to software instead of
      aborting (LocalSend); Flutter apps get the GPU recommended.
    - A library missing for what the main program loads at start, also
      through its bundled libraries (a Flutter plugin), counts as a start
      problem (AppFlowy was rated fine).
    - Without sound access, SDL gets its silent driver, so games and
      emulators start instead of quitting.
    - sharun's .env file counts when checking whether an app forces X11.
  - "May not start" only for real reasons. It showed for 44 of the 71
    test AppImages, of which 69 start: for using the system's GTK or
    OpenSSL (now an information note), for libraries only bundled
    libraries or Node add-ons need (now a notice naming the feature), and
    for add-ons built for another CPU (now ignored). A missing library
    counts as a start problem only when the app's main program needs it;
    for another program inside the app the label says so. On the test set,
    70 of 71 are now rated fine before their first start.
  - Bundled parts built for a CUDA or ROCm version this computer lacks
    get a short note naming the part (e.g. "foundry-local-sdk, bundled in
    this app, is built for CUDA 12. This computer has CUDA 13, which it
    cannot load ..."), saying that other ways the app uses the graphics
    card are not affected. Missing tray-menu or OpenCL libraries get their
    own short notes.
  - The sandbox shows the library folders the system's loader uses
    outside /usr (CUDA in /opt/cuda/lib64, /usr/local/lib), read-only:
    the analysis already counted libraries there as present.
  - Creating a sandbox shows its progress: step, a progress bar and what
    happens ("1.2 GB unpacked", "40 of 115 program files read"), and the
    settings are locked meanwhile (`sam-jail add --progress` for scripts).
    It is also much faster for large AppImages: AnythingLLM took over two
    minutes (in development builds), now 13 s.
  - First starts are faster: the sandbox includes the system's font cache
    (`/var/cache/fontconfig`, read-only), so an app no longer builds its
    own for every installed font (WezTerm's window took 35 s to appear,
    now under 5 s).
  - Apps whose start script launches the real program in the background
    and exits (Pulsar) stay alive: SAM's helper waits for the app's last
    process, not its first.
  - The AppImage's own extractor (after consent) works from files without
    the executable bit and with uruntime's AppDir layout (DwarFS
    "anylinux" AppImages).
- *Local network only* on systems whose `pasta` has no `--splice-only`
  (Ubuntu 24.04): every start failed with a misleading Bubblewrap error. Such
  a pasta is no longer used; the app starts with no network at all, and
  `doctor` says why.
- The writable app folder on Bubblewrap before 0.10 (Ubuntu 24.04, Debian 12):
  the app failed to start. The folder now stays read-only there, with a
  warning.
- The filter buttons above the AppImage list fit the narrowest window.
- On libadwaita 1.5 (Ubuntu 24.04) a narrow window now folds into one
  column instead of overflowing.
- The labels under an app's name are no longer cut off when they wrap onto
  a second line.
- Unpacking tools installed outside `/usr` (e.g. `~/.local/bin`) now work
  inside the unpacking sandbox.
- Icons that some themes lack (a tick, a tool) replaced by ones every
  theme has.
- Keyboard: Tab no longer gets stuck at the "⋮" button of an app page (a
  label under the app's name could take the focus); greyed-out settings are
  skipped by Tab; the Downloads switch
  and the search field have names for screen readers.

### Removed

- The never-enforced "filtered" network mode, `network.allowed_hosts`, the
  system-bus name lists and three unused config keys (old files still load).
- The placeholder for eBPF network filtering (Preferences, `doctor`), a
  feature that was never built.
- Outdated design and handover documents from before the GTK window.

## 0.1.0 - 2026-11-10

First release.

- Sandboxes AppImages with Bubblewrap, Landlock and a syscall filter; private
  home per app; filtered D-Bus and desktop portal; *Local network only*.
- Unpacks AppImages without running them; dependency analysis and
  recommended settings by category; presets.
- GTK 4 / libadwaita window in the style of Flatseal; `sam-jail` command line
  with JSON output.
- Sandbox check, repair steps, log analysis, diagnostics, user guide.
- Packages: Arch (AUR), Fedora (RPM spec), AppImage.
