# Threat model

This page says what SAM protects, against whom, how, and where that
protection ends. Each protection names the test that proves it; the
[test library](test-library.md) lists every test, and
[architecture.md](architecture.md) shows where the trust boundary runs.

## What SAM protects

- **Your files:** documents, photos, keys and passwords in your home folder,
  and the files of your other apps.
- **Your session:** what you type, what is on your screen, your desktop
  services (the keyring, the notification service, the file manager), and
  the programs you start yourself.
- **Your computer's startup:** autostart entries, shell startup files,
  menu entries and services that would run code later, outside a sandbox.
- **SAM itself:** its settings, its app records, and the decision which
  app gets which access.

## Who is trusted

| Party | Trusted? | Why |
|---|---|---|
| You, at your desktop | Yes | You decide what each app may access. |
| SAM's own programs | Yes | They build the sandbox. |
| The Linux kernel, Bubblewrap, xdg-dbus-proxy, pasta | Yes | SAM relies on them to enforce the sandbox; a bug in them weakens every sandbox. |
| An AppImage and everything inside it | **No** | It may be hostile, or a good app may be compromised. |
| What a running app prints or sends | **No** | The app controls it, so it can lie. |
| Other programs running as you, outside a sandbox | **No, but SAM cannot stop them** (see below) | They have all of your rights. |

## Where untrusted input comes in

1. **The AppImage file:** its format headers, the SquashFS or DwarFS image,
   the programs inside, the desktop file, the icon, the update information.
   SAM reads and unpacks it without ever running it outside a sandbox.
2. **The running app:** its output on the terminal and in logs, its D-Bus
   calls, its network traffic, the files it writes in its private folder.
3. **SAM's own files,** when something other than SAM changed them.

## Threats and what stops them

| Threat | What stops it | Proven by |
|---|---|---|
| An app reads your files, keys or passwords | A private home; only the folders you grant are visible; with full home access, keys and credential stores stay hidden, and the file that says where your user folders are stays read-only, so other apps' folder grants cannot be redirected | `every_hostile_appimage_fails_to_escape` (ReadKey, ReadOtherApp), `every_breakout_attempt_from_a_real_sandbox_fails`, `user_folder_locations_stay_read_only_with_a_writable_home`, `the_home_protections_hold_whatever_else_is_granted` |
| An app makes itself start later outside the sandbox (autostart, `.bashrc`, menu entries, services) | These paths are never writable, and the folders above them cannot be renamed, whatever else is granted. With full home access, startup files that did not exist and replaced links are moved aside as soon as they appear (renamed in place or deleted when SAM's folder cannot take them; never silently); Landlock does not guard them then, because the whole home is writable; settings of programs not on the list are not covered (security.md, *Full home access*): an app gets it only with a warning, for apps you trust | the evil suite (WriteAutostart, WriteBashrc), the breakout test, `full_home_access_cannot_leave_anything_that_runs_later`, `the_home_protections_hold_whatever_else_is_granted`, `a_new_start_file_never_stays_silently` |
| An app replaces SAM's own program, which every menu entry runs outside the sandbox (SAM's AppImage kept in a folder the app may write, such as `~/Downloads`) | SAM's AppImage and its programs are read-only wherever the sandbox shows them writable, and the folders above them cannot be renamed | `an_app_can_never_replace_the_programs_that_menu_entries_run`, `sams_own_programs_are_read_only_wherever_an_app_could_write_them` |
| An app types commands into your terminal | The syscall filter refuses `TIOCSTI`; terminal programs run on SAM's own pseudo-terminal, which drops clipboard and report escape codes | the evil suite (TypeIntoTerminal), `the_app_cannot_reach_the_outer_terminal` |
| An app starts a program outside the sandbox through a desktop service (systemd, the Flatpak spawn portal, a launcher) | The filtered D-Bus proxy allows only a short list of services; host tools like `systemd-run` are replaced by stand-ins | the evil suite (Systemd, FlatpakSpawn, Launcher), the breakout test |
| An app poses as a desktop service (takes over a portal's or the notification service's name) | SAM refuses dangerous names and names of services that start on demand | the evil suite (ImpersonatePortal), `own_names_that_are_refused` |
| An app reads your passwords from the keyring | The keyring is blocked unless you allow it, and the switch says that the keyring does not separate apps | the evil suite (Keyring) |
| An app uses the network when it should not | No network: its own empty network; "This computer only": pasta with only the ports you list, every other service on your computer stays unreachable | the evil suite (NetworkWhenOff), `each_permission_grants_exactly_its_access_in_a_real_sandbox` (a listed and an unlisted port) |
| An app keeps running unsupervised after SAM's launcher crashes or is killed | The sandbox dies with its launcher: Bubblewrap's `--die-with-parent`, and a parent-death signal on the process SAM starts (pasta with "This computer only") | `without_network_the_sandbox_dies_with_its_launcher`, `with_this_computer_only_the_sandbox_dies_with_its_launcher` |
| SAM claims protection it did not apply (Landlock or the syscall filter missing at a start) | The start is recorded with its missing layers; the command line warns, the app's page and the overview show it; a syscall filter that fails to load stops the start | `a_start_without_the_helper_reports_its_missing_layers`, `a_wanted_layer_that_was_not_applied_is_reported_missing`, `a_start_without_a_wanted_protection_layer_is_marked`, `a_syscall_filter_that_fails_to_load_stops_the_start` |
| An app watches your other windows or keystrokes | Wayland with a security context; X11 only when you allow it (and the X11 switch says what it costs) | `wayland_security_context_socket_is_used` |
| A hostile AppImage escapes while being unpacked (paths with `..`, symlinks out of the image, setuid bits, huge images) | SAM's own unpacker with limits on size, files and time, run in a sandbox; setuid bits removed; paths checked | `paths_climbing_out_of_the_image_are_refused`, `an_entry_named_dot_dot_writes_nothing_outside_the_app`, `unpacking_removes_setuid_bits`, `a_menu_start_after_free_space_unpacks_inside_a_sandbox`, `without_the_command_line_a_menu_start_refuses_to_unpack`, the evil suite (SymlinkToKey, SetuidInImage) |
| A damaged or hostile AppImage crashes SAM | The parsers are fuzzed; a reader crash becomes an error; one bad file does not stop the list | `changed_appimages_never_crash_or_escape_the_unpacker`, `one_damaged_appimage_does_not_stop_the_list` |
| An app's output talks SAM into granting access | Suggestions based on what an app printed always ask first and are labelled as the app's request; a diagnostic trace (which the app can write) never grants more than a real folder of shared system data | `app_output_cannot_buy_dangerous_grants`, `a_forged_trace_line_cannot_widen_a_low_risk_grant` |
| Text from an app tricks you in SAM's window | Markup and control characters are removed before SAM shows names or messages | `markup_in_metadata_is_neutralized` |
| A changed app record makes SAM delete or move your files | Records with unsafe IDs are ignored; SAM deletes and moves only inside its own folders, after resolving `..` | `removing_a_sandbox_never_deletes_outside_sams_unpack_folder`, `undoing_an_update_never_moves_files_outside_sams_backup_folder` |
| A changed app record adds a line to SAM's menu entry that starts the app without a sandbox | Only clean values go into SAM's menu entry | `app_metadata_cannot_add_lines_to_sams_menu_entry`, `a_hostile_name_adds_no_line_to_sams_menu_entry` |
| A script, another tool or a damaged disk changes an app's settings | Every record SAM saves carries a checksum; a record that does not match does not start until you confirm its settings | `an_app_changed_outside_sam_starts_only_after_confirmation` |
| An update replaces SAM itself with someone else's program | SAM installs an update of itself only with a valid signature from one of its release keys, whose fingerprints are built into SAM; without such a key it does not update itself and points to the release page | `sam_updates_itself_only_with_its_release_key`, `without_a_release_key_sam_never_updates_itself`, `sam_refuses_a_forged_update_that_carries_its_release_key`, `a_second_key_in_the_file_cannot_borrow_a_trusted_name` |
| An update replaces an app with someone else's | A signed AppImage whose signing key changes is refused until you accept the new key, and so is an update whose signature cannot be checked (GnuPG missing); updates use HTTPS only | `key_changes_are_noticed`, `an_update_signed_with_another_key_waits_for_consent`, `an_update_that_cannot_be_checked_needs_consent_after_a_valid_signature`, `updates_are_downloaded_over_https_only`, `an_update_never_comes_over_plain_http`, `a_second_key_in_the_file_cannot_borrow_a_trusted_name` |

## What SAM cannot protect against

These limits are real, and SAM says so rather than pretend otherwise.

- **Programs that run as you outside any sandbox.** A program you started
  without SAM has all of your rights: it can change SAM's files, the menu
  entries in your home folder, or SAM's program file, and it can read SAM's
  memory. A password dialog when SAM starts would not stop that program,
  because the program never passes through the dialog; SAM therefore has
  none. What SAM does instead: it notices app records that something else
  changed (the checksum above) and refuses to start such an app until you
  confirm its settings, and it never deletes or moves files outside its own
  folders because of a record. A program that targets SAM on purpose can
  compute the checksum too, so this catches scripts, other tools and damaged
  files, not deliberate attacks. Real protection against such programs needs
  them to run in a sandbox as well.
- **X11.** An app with X11 access can read keystrokes and capture the
  screen of every X11 app. SAM grants X11 only when you allow it or an app
  cannot run without it, and says what it costs.
- **Bugs in the kernel, in graphics drivers and in firmware.** They bypass
  every sandbox that runs in user space. GPU access in particular widens what
  an app can reach in the kernel.
- **Malware that is already root,** or that gained your password.
- **Access you grant.** An app with your Documents folder can read and
  change your documents; an app with the keyring can read every password in
  it. SAM explains each switch, but it cannot judge the app's intentions.
- **Social engineering:** an app that talks you into granting more.
- **The services you allow.** With "This computer only", the app reaches the
  services on your computer whose ports you list, and whatever they allow.
- **Portals** let an app ask for things (a file, a screenshot, a camera);
  your desktop asks you first, and SAM relies on that.
- **Updates of unsigned apps.** Most AppImages are not signed. Their updates
  come from the publisher's server over HTTPS and are checked against the
  checksum that server publishes, which catches damaged downloads but not a
  server that was taken over. Such an update runs in the same sandbox with
  the same access as before, and it can be undone. Signed apps are safer:
  an update whose signing key changes is refused until you accept it.

## How this is checked

- The evil-AppImage suite (`crates/sam-runner/tests/evil.rs`) and the
  breakout test run in CI on every push.
- The fuzz tests run a few hundred rounds in CI; longer sessions run with
  `SAM_FUZZ_ITERS=100000 cargo test -p sam-runner --test fuzz`.
- The sandbox check in SAM's window (**Test**) confirms from inside each
  sandbox that its settings apply.
- An outside security review is planned before the beta.
