# Privacy check: SAM goes online only when asked (2026-11-28)

> **What this is:** a check, done once before the beta, of when SAM's own
> programs (`sam-jail`, `sam-jail-run`, `sam-jail-gui`, the AppImage's
> `AppRun`, and every program they start outside an app) reach the network
> and what they send. An app's own network is its permission
> (`network.mode`) and is not counted here; nor is the browser after a
> click on a link SAM shows. Code read at commit 57946533 of the branch
> that adds this report. The tests ran in SAM's test container (Ubuntu
> 24.04) with developer builds; CI's test job runs the same tests on its
> Ubuntu runner (strace is in its package list).

## Result

The claim, copied from the security page, where it is kept up to date
([Network use by SAM itself](../security.md#network-use-by-sam-itself)):

> **SAM goes online only when you ask.** That means an update check, an
> update of an app, or an update of SAM itself. It also means once a day
> when the window opens, if you switched on *Check for updates when SAM
> opens*, which is off by default.
>
> Each time, SAM runs `curl`. For an app whose update information names an
> update description (a `.zsync` address), curl asks for that description,
> then for the file it names. For an app published on GitHub, curl first
> asks `api.github.com` for the description of the newest release (or of
> the release the app names), then for up to four update descriptions that
> answer names, then for the file a description names. That file can be on
> any HTTPS server. curl also follows a server's redirect to another HTTPS
> address, at most five times per request.
>
> Every request is a plain `GET`. It carries only the address, the
> server's name, SAM's fixed user agent (`SAM-AppImage-update-check`), what
> SAM accepts and, for part of a file, which part. It carries nothing else
> about you, this computer or your other apps. SAM refuses an update
> address that holds a login.

Nothing was found that goes online unasked. One finding is named as a
limit below: `curl --version`, which the contract check and the bug report
run, looks up the user's account and this computer's name through the
system's name service.

## Checked once by reading (at 57946533)

This is the evidence of one reading, not a promise the tests keep; the
tests are in the next section.

| What | Where | Read |
|---|---|---|
| The only program that goes off this computer is curl, built in one place | `crates/sam-runner/src/updates.rs:87` (`curl_args`), `:159` (`curl`), `:69` (`github_api_url`) | every request: `--disable`, HTTPS only also after redirects, at most 5 redirects, `--globoff`, `--fail`, time limits, SAM's user agent; no cookies, no login, no body; at most four update descriptions from a GitHub answer (`updates.rs:427`) |
| Who reaches curl | `sam-jail updates`, `update`, `self-update` (`crates/sam-jail-cli/src/main.rs:704, 774, 806`); the window's update actions through `Backend::call_online` (`crates/sam-gtk/src/backend.rs:111`), which its other methods refuse (`backend.rs:395, 403`) | each runs after the person's action; at the window's start only with the daily check on (`crates/sam-runner/src/ops/maintain.rs:837`) |
| The daily check's switch | `crates/sam-gtk/src/pages.rs:329` | switching it on runs `config set updates.check_on_start true` through the window's ordinary method; that is the person's standing choice, so later checks at start count as asked |
| curl inherits SAM's environment | `updates.rs:159` | a proxy set in `https_proxy`, `ALL_PROXY` or `NO_PROXY` applies |
| GnuPG | `crates/sam-detect/src/signature.rs:203`, `:247` | import and verify with `--batch --no-options` and a throwaway home, no key-server option; run directly (outside the unpack sandbox) for doctor's check on SAM's test keys, SAM's own update when no unpack sandbox can be built, developer builds, and the `sign-appimage` developer tool, which uses the developer's own GnuPG configuration |
| SAM's own D-Bus client | `crates/sam-runner/src/dbus_check.rs:49, 79, 107` | sends `Hello`, `GetNameOwner` and, for tests' private buses only, `RequestName` |
| Links | `crates/sam-gtk/src/window.rs:1269, 1274` (About: website and the GPL licence link), `window.rs:1556` (SAM's release page, after *Yes*), `crates/sam-gtk/src/app_page/render.rs:393` (*Open Download Page*), the guide's links | each opens in the browser only on a click |
| Local only | `pasta` (`crates/sam-runner/src/netns.rs:31`); the sandbox check's TCP connects to `127.0.0.1` (`crates/sam-runner/src/probe.rs:393`); Unix sockets for D-Bus, Wayland, Room service and the sound relay; `update-desktop-database` (`crates/sam-intake/src/desktop.rs:318`); `notify-send`, `kdialog`, `zenity` (`crates/sam-jail-cli/src/bin/sam-jail-run.rs:47, 133, 176`) | nothing leaves this computer |
| Libraries | `Cargo.lock` | no HTTP, TLS or name-lookup library; GTK, libadwaita and GLib have network functions, which SAM's code does not call |

## Kept true by tests

Each test's own description says exactly what it proves; together:

1. **The static gate** (`each_listed_call_in_program_code_is_a_listed_place`,
   `the_way_out_parser_reads_what_the_compiler_reads`, in
   `crates/sam-jail-cli/tests/network_use.rs`). A new direct call in SAM's
   program code of one of the functions listed in clippy.toml fails CI's
   clippy step until it is listed with its exact line. This covers the
   code CI's clippy compiles: the debug build for x86_64, all features.
   Today 93 places are listed, each with what it runs, when and what it
   sends. **Does not prove:** functions clippy.toml does not list; macros,
   function pointers and generic helpers (which program a generic place
   runs, or what new callers of a generic helper ask it to run); `extern`
   blocks, `asm!`, `include!` and `#[path]` only as far as the parser
   refuses them; release-only and aarch64-only code; the arguments of a
   listed program in later statements (except curl's); messages over an
   already listed socket; links inside label markup; `build.rs` and the
   room helper `crates/sam-runner/room-exec/main.rs` (with its own
   `execve`), which the build compiles without clippy; shell code
   (`AppRun` is pinned instead); libraries' own behaviour.
2. **What every update request is built from**
   (`every_update_request_has_exactly_these_curl_arguments`,
   `the_github_address_is_exactly_the_release_address`,
   `an_update_address_with_a_login_is_refused`, and
   `the_update_module_the_window_start_and_apprun_are_as_reviewed`, which
   pins the update module's program part, the window's start functions and
   `AppRun` by hash, kept in `network_use_pins.toml`). **Does not prove:**
   that a reviewer judged a change correctly; changes inside functions the
   start functions call; what curl does on the wire with these arguments
   (layer 6).
3. **The window's network commands**
   (`the_window_runs_update_commands_only_through_call_online`): the
   window's ordinary command methods refuse `updates`, `update` and
   `self-update`, so they run only through the listed method. **Does not
   prove:** that each listed place runs only after the person's action; the
   list says when each runs, and review judges it.
4. **The libraries** (`only_listed_libraries_are_part_of_sam`,
   `the_library_check_sees_a_new_name_or_source`): the name and source of
   every package in `Cargo.lock`. A new library or another source fails; a
   new version of a listed library does not. **Does not prove:** that a
   listed library never goes online; a new direct use of a library already
   in `Cargo.lock`.
5. **The traced run** (`everyday_commands_make_no_internet_connection`,
   `the_trace_sees_an_update_check`, `the_trace_sees_inside_an_apps_sandbox`,
   `every_command_is_traced_or_named_untraced`,
   `the_trace_check_reads_strace_lines`). The window's start commands
   (twice, before and after an app is added) and the everyday commands run
   under strace, which follows every process SAM starts. Each must end with
   its expected exit status; exit status 3 ("not passed") counts as ran for
   `verify` and the doctor commands. Only `add`, `run`, `verify`, `doctor`
   and `doctor --contracts` must also show a program that proves they did
   their work (an unpack tool or SAM's own extractor, Bubblewrap, GnuPG).
   No process may make an internet connection: none may open an internet
   socket, set up io_uring or connect to a name-service socket. The two
   exceptions are pasta's probe socket, which is opened and connects
   nowhere on the internet, and `curl --version`'s connect to nscd (see
   Limits). Two controls show the tracer sees an update check (curl, and
   an internet connect only to the address the app names) and follows into
   an app's sandbox (getent's own socket). Every command of `sam-jail` is
   either traced or named as untraced. **Does not prove:** the untraced
   commands and forms (among them `desktop <id> <action>`, `update --undo`
   and the key-change answers); release builds; whether the unpack sandbox
   was used in the traced run; the window's own process (GTK, portals);
   `AppRun` itself; other settings (an app with network access uses it by
   its permission); work done by services SAM asks over D-Bus or a socket;
   name lookups through network account directories, which the container
   lacks; reads from network file systems; a socket another program hands
   over; a 32-bit helper using `socketcall` (none is started).
6. **On the wire** (`update_requests_carry_nothing_about_the_person_or_their_apps`,
   `a_version_is_found_only_as_a_whole_word`,
   `the_recording_server_records_every_method`, in
   `crates/sam-runner/tests/`). A stand-in HTTPS server records every
   request, whatever its method. For an app with a `.zsync` source reached
   through a redirect on the same server, the update check and the update
   (a part, then the whole file) send exactly a `GET` with `Host`,
   `User-Agent` and `Accept` once each and at most one `Range`, with exact
   values. No request names the user, the login, this computer's name, the
   home, the test's folder, the app's record, the installed file's name or
   SAM's version; the address itself names the app, as every update check
   must. **Does not prove:** the GitHub request on the wire (it is built
   from unit-tested arguments and address); a redirect to another host, or
   a redirect address that holds a login; HTTP/2 framing, and HTTP/1.1 to
   this stand-in (it answers in HTTP/1.0, and curl then speaks 1.0 to it
   after the redirect); the TLS handshake; a proxy's view; SAM's own update
   on the wire (it uses the same functions).

`update_checks_stay_off_unless_switched_on` keeps the daily check off by
default.

## Observed in the traced run

The test prints this for every command; the run of 2026-11-28 in the test
container:

| Command | Exit | Programs it ran | Unix sockets it connected to | Internet socket |
|---|---|---|---|---|
| W1-W7, W9-W11 (window start: language, version, permissions, menu entries, settings, lists, Downloads scan, `updates --if-due`) | 0 | sam-jail | none | none |
| W8 `discover` | 0 | sam-jail, bwrap | none | none |
| E1 `add` | 0 | sam-jail, bwrap (the unpack sandbox, SAM's own extractor) | none | none |
| E2 `preview`, E3 `info`, E5 `command` | 0 | sam-jail, bwrap | none | none |
| E4 `get`, E6 `menu list`, E7 `evaluate`, E8 `logs --list`, E9 `space`, E11 `logs`, E18-E22 | 0 | sam-jail | none | none |
| E10 `run` | 0 | sam-jail, bwrap, sam-jail-run, the app's AppRun | none | none |
| E12 `verify` | 0 | sam-jail, bwrap, sam-jail-run | none | none |
| E13 `doctor` | 0 | sam-jail, bwrap, true, pasta, pipewire, strace, unsquashfs, bsdtar, xdg-dbus-proxy (version options) | `/dev/log` (pasta's log, absent) | pasta's probe only, connected nowhere on the internet |
| E14 `doctor <id>` | 0 | as E13 without pasta and the test sandbox (true) | none | none |
| E15 `doctor --contracts`, E16 `report`, E17 `report <id>` | 3, 0, 0 | as E13, plus curl, gpg, gpgv, gpg-agent, dbus-daemon (version options and the GnuPG check) | `/dev/log`, the throwaway GnuPG home's agent, nscd's socket (curl, absent) | pasta's probe only, connected nowhere on the internet |

Exit 3 of `doctor --contracts` means a contract does not hold in the
container; the GnuPG programs in its trace show it ran.

## Limits

- Everything each layer above names under **Does not prove**.
- **What the servers learn:** each server sees the IP address, the time
  and which app is checked; partial downloads show roughly which version
  was installed; GitHub sees every GitHub-hosted app a check of all apps
  asks about; the DNS server, a proxy and the network path see the
  servers' names.
- **`curl --version`'s name lookups.** The contract check and the bug
  report run `curl --version`. In the traced run it connects to nscd's
  socket. A separate trace of its file openings, made while preparing this
  check, showed it then reads `/etc/passwd` and `/etc/hosts`: its libraries
  look up the user's account and this computer's name (**likely**, from
  that trace, not from the tests). Where the name service asks a server
  (accounts from a network directory, or a computer name not found
  locally), this lookup may leave the computer. Without `--disable`, this
  curl also reads a `~/.curlrc` (**likely**); SAM's update requests do not.
- **pasta's probe socket.** `pasta --help` and `--version`, which doctor
  runs, open one TCP socket to read the kernel's buffer sizes; the test
  allows this only for that program and checks that it connects nowhere
  on the internet and sends nothing on it.
- **Libraries' own behaviour** outside the traced commands, including the
  window's process: GLib or GTK may look up the user's own account through
  the name service, which can leave the computer where accounts come from a
  network directory.
- **Network file systems:** when a scanned folder, Downloads or an
  AppImage lies on NFS, SMB, sshfs or a GVfs mount, SAM's reads go over
  that network; the kernel or the file system's helper does that, out of
  the tracer's sight.
- **The `sign-appimage` developer tool** uses the developer's own GnuPG
  configuration.
