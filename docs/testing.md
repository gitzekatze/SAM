# Testing SAM

How SAM is tested: every kind of test, how to run it, when it runs, and the
checks a person still does by hand.

## The kinds of tests

| Kind | What it does | Run it | When it runs |
|---|---|---|---|
| Logic tests | every rule with known inputs and the exact expected result | `make test` | every change on GitHub, twice |
| Real sandbox tests | start real Bubblewrap sandboxes and check from inside what an app can see, reach and change (`matrix`, `sandbox`, `verify`) | `make test` | every change, on Ubuntu and Fedora |
| Attack tests | breakout attempts, hostile AppImages and fuzzing (`breakout`, `evil`, `adversarial`, `fuzz`, `fuzz_targets`, `terminal_fuzz`) | `make test` | every change, on Ubuntu and Fedora |
| Update tests | real updates from a local HTTPS server (`update_server`) | `make test` | every change |
| Window tests | open every page, and click through the window like a person (`tests/gui/`) | `tests/gui/smoke.sh OUTDIR`, `tests/gui/flow-atspi.sh OUTDIR` | every change |
| Desktop sandbox tests | the sandbox tests (permission matrix, sandbox check, breakout, hostile AppImages) inside a hidden KWin with PipeWire, where they must find Wayland and sound (`tests/gui/desktop-sandbox.sh`) | `SAM_SESSION=kwin SAM_TEST_AUDIO=1 tests/gui/desktop-sandbox.sh OUTDIR` | every change |
| Upgrade test | data from the previous version still works (`tests/upgrade/run.sh`) | `tests/upgrade/run.sh vX.Y.Z WORKDIR` | before every release |
| Real AppImages | 120 real AppImages through SAM's whole flow (`tests/real-apps/`) | see below | before every release |
| Mutation testing | deliberate mistakes in the code that the tests must notice | `make mutants-diff`; `scripts/mutants.sh FILE…` for whole parts (never plain `cargo mutants`: its settings miss the sandbox tests); each test program in its own memory compartment where systemd allows it (`tests/mutants/memory-compartments.sh` checks that) | per change for security code; whole parts before every release |
| Install tests | the finished AppImage on fresh distributions | `make test-shipped APPIMAGE=…` | every release build |
| Contract checks | SAM's assumptions about the outside world hold here (`sam-jail doctor --contracts`), and the code uses nothing no contract covers (`scripts/contract-map.py`) | see [contracts](contracts.md) | every change |
| Early warning | the contracts and sandbox tests on tomorrow's distributions (`tests/canary/`) | Actions → Early warning | every night |
| Weekly upkeep | mutation testing of last week's code, and a long fuzz run with a random seed drawn at the start and named in the report (`.github/workflows/upkeep.yml`) | Actions → Weekly upkeep | every week, in the issue **Weekly summary** |
| Manual checks | what needs a real desktop or a person (this page, below) | by hand | before a release |

The complete list of automated tests, each with the promise it keeps, is the
[test library](test-library.md). Which of SAM's functions each test proves is
the [function map](functions.md). How each part of SAM does from version to
version (tests, line coverage, timings, dependencies) is in the
[version reports](reports/), made with `make report`.

**No silent skips in CI:** a sandbox test that cannot run (no working
Bubblewrap, no kernel headers) skips with a note when you start `cargo test`
yourself, but CI, `make test` and the scripts that run the suite set
`SAM_REQUIRE_SANDBOX=1`, which turns such a skip into a failure: a green
run always tested the sandbox.

**"Not here" is listed, never hidden:** a test that does not apply to a
machine at all (another processor; a component SAM itself would not use,
such as Ubuntu 24.04's pasta without `--splice-only`) passes there without
checking anything. CI writes each one into the job's summary ("Tests that
did not run here") and fails when one is not on the agreed list for that
job, `tests/expected-not-here.toml`, which needs the owner to change. The
Fedora job runs what Ubuntu cannot ("This computer only", PipeWire refusing
to load modules), so every listed test is proven in another job.

**Not proven on CI machines:** granting real devices (the graphics card,
a webcam, game controllers, input devices, raw sound devices). The runners have none,
so the permission matrix proves that each stays out when off, but "on" is
only a manual check (section 9).

**Stand-in tools:** SAM runs a helper program only where the user cannot
change it, so a test's own stand-ins (a broken `bwrap`, a hostile unpack
tool) in a temporary folder would be skipped. Such a test names that folder
in `SAM_TRUST_TOOLS_IN`.

**The same result on every computer:** a test never uses anything of the
person running it. Tests that start sandboxes get their own runtime folder
(`Paths::rooted`, `SAM_RUNTIME_DIR`) and see the computer without its
desktop session (`testenv::test_host`): no display, session bus, sound or
SSH agent of yours. Where a test needs a session bus or an agent, it starts
its own (`testenv::PrivateServices`). The window tests run in a session
of their own (`tests/gui/session.sh`: own home, settings, runtime folder,
bus without services, one language). Inside that session, tests may use its
display and bus: they are the test's own (`SAM_TEST_SESSION=1`). A test that
does not apply to a computer at all (another processor, a pasta version SAM
refuses) says so in the skip list (`contracts::not_here`) and never fails.

**How CI judges the tests:** it runs the whole suite twice
(`scripts/flaky-check.py`). A test whose result differs between the two runs
is *flaky*: its answer depends on timing or on other tests, not only on the
code, so it fails the job like a test that fails. After the tests, the run
page shows which of SAM's functions the change touches and how their tests
did (`scripts/push-summary.py`, from the function map).

**Real AppImages beyond the first start:** `WORK=… tests/real-apps/run.sh
APP…` also records, for every app, the D-Bus calls of the first start that
got no answer (an app waiting on them feels slow), the windows after 20
seconds and whether a title reads like an error dialog, whether the
recommendation is the same twice, and leftovers after closing. With
`CHECKS="netoff second lang"` it also starts each app without network and
sound, a second time while the first runs, in German, with display
scaling 2, and (`missing`, needs strace) under strace to list files the app
looked for in vain. Every run also notes the time until the first window,
the memory after 20 seconds, whether a tray icon
was registered, and which portals the app called.

**Whether an app really uses what SAM allowed:** during the first start
(every 2 seconds for its 25 seconds) the test looks from outside whether
the app uses the graphics card (contexts NVIDIA's driver lists for its
processes; *n/a* with other drivers, which show this to root only), plays
through the session's own silent sound server, and has connections that
leave this computer. For the network each app runs in a control group of its
own, so `ss` tells its connections apart from everything else on the
computer; start the run in a scope with `Delegate=yes`
(`systemd-run --user --scope -p Delegate=yes …`), otherwise network use is
*n/a*. Per permission the result is *works* (allowed and used), *unused*
(allowed, not used during the start: no failure), *-* (not allowed) or
*local* (this computer only). `table.py --markdown` adds a summary and a
column to the report. A process still in the app's control group after SAM
closed it is listed as `left-running`.

**Whether an app works, not just starts:** every app that started is
started once more like a person would use it: with a small sample file of a
type its menu entry says it opens (`tests/real-apps/samples.py` makes them:
images, text, PDF, video, sound and more), then closed with its windows'
close buttons (a KWin script). Linux reports from outside whether the app
read the file (inotify sees reads through the sandbox; SAM itself never
reads it, checked). The report says per app: the file read or not, closed
cleanly, closed with an error, did not close within 10 seconds (with the
window's title), ended by itself, or had no window. Without extra start
time, `checks.py` also looks at the screenshot inside the app's largest
window (empty: one or two colours; changed between 12 and 20 seconds),
reads its text for error words (tesseract, when installed), and sorts the
app's own messages from the first start into crashes, missing libraries
and refused access (lines about what SAM never gives, like the system bus,
are left out). `table.py --markdown` adds a "Used like a person would"
summary and a column.
`python3 tests/real-apps/checks.py WORK [BASELINE]` prints one line per app,
or with a baseline only what changed. The smoke subset (one app per family,
16 apps) passed every check on 2026-11-15.

These checks need a real desktop session: real AppImages, PipeWire, a GPU, an
unfiltered session bus, and packages that may not be installed. They
complement `cargo test --workspace` (unit tests plus the end-to-end sandbox
test).

To keep your real configuration untouched while testing, run:

```sh
export SAM_CONFIG_DIR=/tmp/sam-test/config \
       SAM_DATA_DIR=/tmp/sam-test/data \
       SAM_APPLICATIONS_DIR=/tmp/sam-test/applications
```

Leave `SAM_APPLICATIONS_DIR` unset if you want launchers to show up in your menu.
`SAM_RUNTIME_DIR` moves the per-launch runtime folders (default
`$XDG_RUNTIME_DIR/sam`); SAM's tests set it, so they never use the real one.

Five more variables work only in developer builds (`cargo build` without
`--release`); a release build ignores them, so a forgotten setting in
your desktop's environment cannot change what an installed SAM runs, shows
or records:
`SAM_CLI` and `SAM_RUN` make the window use another `sam-jail` or
`sam-jail-run`, `SAM_LOCALE_DIR` another folder of compiled translations,
`SAM_DBUS_LOG=FILE` makes the D-Bus proxy log every call
(`scripts/dbus-log-summary.py FILE` sums it up), and `SAM_TRUST_TOOLS_IN`
names a folder of stand-in tools that SAM's tests may run although the user
owns them. SAM's scripts and tests that set them (`tests/real-apps/`,
`tests/gui/desktop-sandbox.sh`, the integration tests) use developer builds.

## Manual checks and details

## 0. Automated permission matrix

`cargo test -p sam-runner --test matrix` starts a probe AppImage once per
permission and checks from inside the sandbox what it can see. Build
SAM's helper first (`cargo build -p sam-jail-cli`, or `cargo test --workspace`
builds it), so Landlock and seccomp are applied too: tests find the helper of
their own build without `PATH`. `SAM_MATRIX_DEBUG=1` with `-- --nocapture`
prints every launch log. With `SAM_REQUIRE_SANDBOX=1` (as in CI) a test that
cannot run fails instead of skipping.

`cargo test -p sam-runner --test verify` covers the sandbox check
(`sam-jail verify`): it passes for a correct sandbox, reports a folder leaked
through a raw Bubblewrap argument, and follows the settings (syscall filter
off is expected off). It needs the helper, as above.

By hand: `sam-jail verify <app>` on a few real apps should report every check
as passed; `sam-jail config set security.check_before_launch true`, then a
raw `--ro-bind` of a hidden folder in `advanced.extra_bwrap_args`, must make
`sam-jail run` refuse to start with "sandbox check failed". The same is
tested automatically by `sam_jail_run_refuses_a_sandbox_whose_settings_do_not_apply`.

## 0a. Robustness and removal

`cargo test -p sam-jail-cli --test robustness` runs the real `sam-jail` on
old, newer, damaged and deliberately mangled files (truncated at many
lengths, single bytes changed): old ones are migrated with a backup, newer
ones are never changed, damaged ones are moved aside and reported, and
nothing panics. `cargo test -p sam-runner --test uninstall` checks that
`sam-jail uninstall` removes every trace, restores hidden menu entries,
keeps the AppImage and refuses folders that are not SAM's.

Scale (2026-11-10, release build): 200 AppImages among 3,200 files are
found in 0.8 s cold and 30 ms warm; with 40 sandboxes `list`, `doctor` and
`info` answer in under 40 ms, and the window shows all 240 entries.

## 0b. Real AppImages

`WORK=… tests/real-apps/run.sh App.AppImage …` runs the whole flow
(recommendation, Create Sandbox, sandbox check, test start, hints, repair
steps) on real AppImages in an invisible KWin session with a fake home;
`python3 tests/real-apps/analyze.py "$WORK"` summarises it. The
[version reports](reports/) record the results of each full run.

The test desktop is a real one in what apps look for at start: a sound
server with a silent output (a "null sink": it takes sound and drops it,
so nothing plays out loud) and a session manager that watches no real
device, and a stand-in notification service that writes each notification
to `notifications.log`. Without them, apps that open sound or send a
notification first waited for ever and looked broken (the night run of
2026-11-18: six games and players, Chatterino, Plover). Tests on a desktop
stay hints: every fix SAM makes for an app gets a unit or sandbox test.

To see what a change to SAM did, compare the run with the last one by
group of apps (toolkit, packager), not app by app:

```sh
python3 -I tests/real-apps/table.py "$WORK" kinds.txt > after.txt
python3 -I tests/real-apps/compare.py docs/reports/real-apps-2026-11-20.md after.txt kinds.txt
```

It prints each group whose results changed, for example
`electron: 39 → 37 of 39 start`, and for the apps a group lost the reason,
grouped: two apps lost for the same reason point at one part of SAM. The
exit status is 1 when any group lost an app.

## 0c. What an app does, checked by hand

Sandboxed apps cannot be driven through the accessibility interface: SAM
blocks it inside the sandbox, because an app could read other windows
through it. So the harness measures what can be seen from outside (a
tray icon, the portals an app calls, D-Bus calls it waits
on) and these checks stay manual. For each app tested, note one letter per
column (✓ works, ✗ fails, – does not apply) in this form:

| App | Open a file | Save into a granted folder | Saving elsewhere is refused | Internet when on | No internet when off | Sound | Link opens in the browser | File dialog | Tray menu | Notification | Clipboard |
|---|---|---|---|---|---|---|---|---|---|---|---|
| (name) | | | | | | | | | | | |

## 1. Environment

- [ ] `sam-jail doctor`: everything is `ok`. The sandbox test passes, and
      Wayland, PipeWire and D-Bus are detected.
- [ ] `sam-jail info <id>` prints `sandbox: Bubblewrap`.

## 2. Real AppImages

For each category (browser, media player, image editor, game, text editor,
Electron app, Qt app, GTK app):

- [ ] `sam-jail add <file>` succeeds, and the category and recommendation make sense.
- [ ] `sam-jail run <id>` opens a window on Wayland.
- [ ] Rendering is GPU-accelerated when GPU is on (e.g. `chrome://gpu`,
      `glxinfo` inside a terminal app).
- [ ] Audio plays through PipeWire when sound is on, and is silent when off.
- [ ] Network works with `full` and fails with `none`.
- [ ] File dialogs only show granted folders. Opening a file from Dolphin
      ("Open with" via the launcher) works even when its folder isn't granted.
- [ ] Electron apps start (nested namespaces allowed).

## 3. D-Bus filtering

- [ ] With the session bus set to *filtered*, `busctl --user list` inside a
      sandboxed terminal app lists only the portals, notifications and tray.
- [ ] Notifications from the app appear.
- [ ] With the session bus set to *none*, `DBUS_SESSION_BUS_ADDRESS` is unset inside the sandbox.

## 4. Kernel features

- [ ] Logs show `landlock: true` (`sam-jail logs <id>`).
- [ ] With `sam-jail set <id> advanced.seccomp_strict true`, a non-Electron app
      still starts.

## 5. Desktop integration

- [ ] A launcher appears in the KDE menu with the app's icon.
- [ ] Starting it from the menu runs the app sandboxed (`ps` shows `bwrap`).
- [ ] A failed launch from the menu shows a notification.
- [ ] Removing the app removes the launcher.

## 6. Updates and staleness

- [ ] Replace an AppImage with a newer version. `sam-jail refresh` reports it
      as changed and the GUI shows the *Changed* badge.
- [ ] Unpack Again. Your own settings are kept, and new needs are listed under
      "Update needs new permissions".
- [ ] Move the AppImage. The overview shows it as a moved copy;
      *Locate…* fixes the path.

## 7. Diagnostics

- [ ] With user namespaces disabled, starting an app stops with a clear
      hint and nothing runs unsandboxed.
- [ ] **Diagnostic run** (needs `strace`): `sam-jail diagnose <id> --apply`
      lists findings, and low-risk fixes are applied.

## 8. Type 1 AppImages

- [ ] An old Type 1 AppImage (ISO 9660) is extracted via `bsdtar`.

## 9. GUI

- [ ] The overview lists AppImages from the scan folders under *Not sandboxed*,
      with names and icons, before anything is unpacked.
- [ ] Downloads is only listed after **Add Downloads** on the main page, which adds it as an ordinary location.
- [ ] *Create sandbox* on an app with an AppImageLauncher/Gear Lever menu entry
      asks to hide it. *Hide it* removes it from the KDE menu; *Remove sandbox*
      brings it back unchanged.
- [ ] No SAM menu entry exists for apps that are not sandboxed.
- [ ] Adding a folder or a single file in "AppImage locations" lists its
      AppImages; removing it drops them from the list (sandboxed apps stay).
- [ ] Selecting an app without a sandbox shows the recommended settings;
      changes made there are used by *Create sandbox*.
- [ ] Drag an AppImage into the window: it is added to the list and selected.
- [ ] Every setting is visible at all times; settings that do not apply
      (e.g. ~/.ssh without full home) are greyed out, never hidden.
- [ ] Preferences → Style (Follow system, Light, Dark) applies instantly.
- [ ] Turning on full home, the system bus or raw devices asks for confirmation.
- [ ] With a game controller and a webcam plugged in: an app gets the controller only with **Game controllers** (or **All input devices**), the webcam only with **Webcam**, and the graphics card only with **GPU acceleration** (CI machines have no devices, so only "off" is proven there).
- [ ] Applying a preset without network access to a browser warns that it removes network access.
- [ ] **Test** runs the settings check and a short start; the header shows *Tested* with the date, *Test out of date* after a change.
- [ ] After a failed start, repair steps appear as switches under **Advice**; switching one off undoes only that step.
- [ ] The remove dialog has three choices, none preselected; the button names the chosen action (*Free Space*, *Remove Sandbox*, *Delete Everything*).
- [ ] With the old "Also search the Downloads folder" switch on, Downloads appears once as an ordinary location; otherwise *Add Downloads* adds it.
- [ ] While a sandboxed app runs, its page shows "… is running. Changed settings apply the next time it starts."; **Restart** closes it and starts it again; the bar disappears a few seconds after the app is closed.
- [ ] The round trash button left of **Test** asks before removing a sandbox; every header button explains itself on hover.
- [ ] A sandboxed Wayland app shows its own icon and name in the taskbar (KDE Plasma).
- [ ] *Permission Manager*: a tag filter cycles has / has not / off; Shift-click selects a range; turning the internet off for several apps shows one toast with Undo, and Undo restores every app.
- [ ] *Copy bug report* produces a report without your username or home path.

## 10. Compatibility helpers

- [ ] A link clicked in a sandboxed app opens in the normal browser.
- [ ] *This computer only*: the app reaches a host server on 127.0.0.1, the
      host browser reaches the app's own port, websites do not load.
- [ ] *Writable app folder*: a portable app keeps its settings; the extracted
      copy under `extracted/` is unchanged.
- [ ] An app that fails at start shows a notification with the likely cause,
      and its **Fix It** button leads to the app's *Advice*, where the fix and the repair steps (switches) make it start.
- [ ] `sam-jail selftest` lists every sandboxed app as ✓ or ✗.
- [ ] *This computer only*: the log shows `# enforced: landlock …`.
- [ ] After using SAM, nothing named `io.github.gitzekatze.SAM` exists under
      `/run/user/<uid>/.flatpak` or `~/.local/share/flatpak`.
- [ ] Removing or re-extracting an app while it runs is refused with
      "… is running. Close it first".
- [ ] Closing SAM leaves apps started with *Launch* running.
- [ ] *Launching*: adding and removing a launch argument shows in the
      sandbox command; compatibility mode on asks first, off restores the
      settings from before.
- [ ] *Menu Entries*: with an AppImageLauncher/Gear Lever entry, the hide
      switch hides and restores it; without one it is greyed out.
- [ ] *Environment variables*: `NAME=value` is set in the sandbox; an
      invalid name is refused with a message.
- [ ] *Logs*: the picker lists start, unpacking, detection and diagnostic
      logs; each one opens.
- [ ] A new app shows *Needs review*; *Mark as Reviewed* clears it.

## 11. Packaging

- [ ] `cd packaging/arch && makepkg -si` builds and installs both packages.
- [ ] SAM starts from the application menu.

## Keyboard

`sam-jail-gui --screenshot OUT.png --page app --focus-walk` (in the invisible
session of `tests/real-apps/run.sh`) moves the focus with Tab like a person,
1.5 s per step, and prints every stop with its name. On 2026-11-11 it found
two unnamed controls and a keyboard trap: Tab stopped for good at the app
page's "⋮" button, because one of the labels under the app's name could take
the focus (confirmed with a real keyboard; arrow keys still worked). Fixed:
the walk now passes all 130 controls of an app page and wraps around.

`tests/gui/flow-atspi.sh OUTDIR` clicks through SAM's main flow like a
person: an AppImage without a sandbox → Create Sandbox → its page → Launch,
and checks in SAM's records that the app started; then it starts the window
with the language set to German and to the system's, and reads the labels.
GTK 4 check boxes and radio buttons offer the accessibility interface no
action, so ticking a choice (the language, the remove dialog) is checked by
hand:

- [ ] Main menu → Language → Deutsch → *Restart Now*: the window comes back
      in German; *Follow the system* brings back the system's language.

The large sandbox tests (the permission matrix and the breakout test) run
in named sections (`sam_runner::contracts::Checks`): every section reports
`CHECK ok matrix/network` or `CHECK FAIL matrix/network: …`, a failing
section does not stop the next ones, and the test lists every failed
section at the end. (They stay one test each: their steps change the test
process's environment and must not run in parallel.)

Sandbox tests check the contracts they rely on first
(`sam_runner::contracts::guard`): a broken one that SAM cannot work without
stops the test with its name and playbook, so a failure says whether the
outside world or SAM changed ([contracts](contracts.md)). A broken contract
SAM falls back from is only noted, and the test checks the fallback.

CI runs all click-through tests on every push, under KDE's KWin (job *window-flows*) and under GNOME's Mutter (job *window-flows-gnome*); `SAM_SESSION=mutter` runs them under Mutter locally.

`tests/gui/a11y-atspi.sh OUTDIR` opens every page of the window in the
invisible session and reads it through the accessibility interface: every
visible, enabled control must have a name a screen reader can say and must
take keyboard focus (itself, through an inner part, or through its row). On
2026-11-15 all nine pages passed with 443 controls. It checks what screen
readers are told, not how one sounds: the item below with Orca stays a
manual check.

- [ ] With the Orca screen reader on, every control on the overview, an app
      page and the Permissions page is read with a name that says what it
      does, and the risk explanations are read out.
- [ ] On an app page, Tab from the AppImage list reaches *Check*, *Launch*
      and every setting, and Shift+Tab goes back.

