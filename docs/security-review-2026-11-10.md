# Security review 2026-11-10

Scope: every promise in [security.md](security.md) checked against a test
that proves it, a breakout test suite for the promises without one, and a
code review of the security-critical parts: the Bubblewrap command, Landlock
and seccomp (`sam-runner/src/kernel.rs`), the D-Bus proxy and portal filter,
pasta (*Local network only*), extraction, host-side reads and writes of
AppImage data, the stop logic and the launchers.

## Method

- **Promise map.** Each statement in `security.md` was matched to a test.
  Already covered: private home, hidden `~/.ssh`, folder grants, read-only
  payload and system, no network, PID namespace, generated `passwd`, system
  bus, devices, display, extra folders, setuid stripping, symlink escapes at
  extraction, app output that cannot buy grants, markup and MIME hijacking,
  the sandbox check, Local network only.
- **Breakout suite** (`crates/sam-runner/tests/breakout.rs`): a probe app
  inside a real sandbox calls the kernel directly (Python `ctypes`) and
  tries the documented attacks. Calls are chosen so that an ordinary user
  succeeds or gets a different error without the filter (`keyctl`,
  `userfaultfd` in user mode, `unshare(0)`, `TIOCSTI` on a non-tty), so
  `EPERM` proves the filter. x32 calls prove the filter covers them because
  seccomp answers before the kernel says `ENOSYS`.
- **Real apps** after each change: 18 AppImages
  ([real-apps-2026-11-10.md](real-apps-2026-11-10.md)), re-run with the
  hardened defaults.

## Findings

| # | Severity | Finding | Fix |
|---|---|---|---|
| S1 | High | **Nested namespaces were allowed for every app** (default `allow_userns: true`), so `unshare` and mounts were never blocked and every app had the kernel attack surface of user namespaces. | Off by default. Detection marks engines that build their own sandbox (Electron, CEF, Qt WebEngine, WebKitGTK); only those get it. 11 non-Electron real apps verified to run without. |
| S2 | High | **Full home read/write: persistence paths were protected only if they existed**, and several were missing from the list: `~/.local/bin`, `~/bin`, D-Bus service files (started outside the sandbox), `mimeapps.list`, KWin/Plasma scripts, service menus, git/editor configs. An app could create `~/.config/autostart/x.desktop` and run outside the sandbox at the next login. | List extended; missing folders (and files where empty equals missing) created empty and mounted read-only. Remaining exceptions documented. |
| S3 | Medium | **A granted folder containing the home** (e.g. `/home`, `/`) showed `~/.ssh`, keyrings and SAM's data unguarded; guards applied only to *Full home access*. | The same guards apply whenever a grant contains the home. |
| S4 | Medium | **SAM's own folders could become visible** through a grant when placed elsewhere (configurable extraction folder since today, `SAM_CONFIG_DIR`/`SAM_DATA_DIR`): an app could change its own registry entry (permissions) or another app's files. | Every SAM folder is replaced by an empty tmpfs whenever a grant would show it. |
| S5 | Medium | ***Local network only* ran the app as root** inside pasta's namespace: the D-Bus proxy rejected it (no portals) and Electron refused to start. (Found by the real-app test.) | `--uid`/`--gid` always; integration test. |
| S6 | Medium | **`systemd-run`** inside the sandbox: with full D-Bus it could start a program outside the sandbox. (Found by the real-app test, KeePassXC.) | Replaced by a stand-in that runs the command inside; `flatpak-spawn` refuses. |
| S7 | Low | **"Always blocked" D-Bus names did not hold against wildcard allow entries** (`org.kde.*` vs `org.kde.KWin`): `xdg-dbus-proxy` has no deny rules. | Fail closed: such wildcards are dropped, with a warning. |
| S8 | Low | **x32 ABI**: blocked calls were matched by their x86-64 numbers only; on kernels with x32 enabled the x32 numbers would pass. Not exploitable here (x32 off). | x32 numbers blocked as well; tested. |
| S9 | Info | 32-bit AppImages are stopped by the filter's architecture check. | The recommendation turns the filter off for them and says why. |
| S10 | Doc | `security.md` said Landlock blocks writes behind any wrongly writable mount. Inside the (writable) home it cannot; there the read-only mount protects. | Documentation corrected; Landlock tested outside the home. |

## Verified, no change needed

- Seccomp architecture check: a mismatched architecture ends the process
  (`seccompiler` emits `KILL_PROCESS`).
- `TIOCSTI`/`TIOCLINUX`, keyrings, `userfaultfd`, BPF, perf, modules,
  handle-based opens and `syslog` are refused; `NoNewPrivs` 1, no
  capabilities, seccomp mode 2.
- Landlock blocks writes to a read-only grant mounted writable by a raw
  Bubblewrap argument; host abstract sockets are unreachable with full
  network (Landlock ABI 6).
- `/` read-only, private `/dev/shm`, host environment not passed in.
- Extraction: `..` paths refused, escaping symlinks removed, setuid/setgid
  and world-writable bits stripped, FIFOs and sockets removed, limits
  enforced; host-side reads never leave the payload; icon names cannot
  escape; the cache file name comes from SAM's id.
- D-Bus proxy: portal access method by method on fixed object paths;
  dangerous names and wildcards covering them are rated Dangerous and ask.
- pasta: ports are numbers, DNS is never forwarded, `--splice-only`.
- `sam-jail stop` only signals processes that hold their launch's lock.
- Launchers: `Exec` quoted, id from a slug, MIME types filtered.

## Accepted risks

- Icons (PNG, SVG, XPM, ≤10 MB) are drawn by the host's image libraries,
  as with every AppImage integration tool.
- With *Full home access* read/write, files whose presence changes
  behaviour (`.bash_profile`, `.zshrc`, `.xinitrc`, `.xprofile`, `.vimrc`)
  can be created when missing. Full home read/write is rated Dangerous and
  asks first.
- X11, the keyring, the full session bus and full home remain as dangerous
  as `security.md` says; SAM warns and asks.
- Portals see SAM apps as ordinary programs; the method filter is what
  limits them, and SAM relies on the portal's own checks (for example for
  opening files).

## Recommendation

An outside review before a public release: one or two people from the
Bubblewrap/Flatpak community reading `security.md`, this report,
`crates/sam-backend-bubblewrap/src/lib.rs` and `crates/sam-runner/src/kernel.rs`.
