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
| An app reads your files, keys or passwords | A private home; only the folders you grant are visible; with full home access, keys and credential stores stay hidden (also behind a link into a read-only place, and also as a named pipe or socket), and the file that says where your user folders are stays read-only, so other apps' folder grants cannot be redirected | `every_hostile_appimage_fails_to_escape` (ReadKey, ReadOtherApp), `every_breakout_attempt_from_a_real_sandbox_fails`, `user_folder_locations_stay_read_only_with_a_writable_home`, `the_home_protections_hold_whatever_else_is_granted`, `credentials_behind_links_pipes_and_sockets_stay_hidden` |
| An app makes itself start later outside the sandbox (autostart, `.bashrc`, menu entries, services) | These paths are never writable, and the folders above them cannot be renamed, whatever else is granted. With full home access, startup files that did not exist and replaced links are moved aside as soon as they appear (renamed in place or deleted when SAM's folder cannot take them; never silently); Landlock does not guard them then, because the whole home is writable; settings of programs not on the list are not covered (security.md, *Full home access*): an app gets it only with a warning, for apps you trust | the evil suite (WriteAutostart, WriteBashrc), the breakout test, `full_home_access_cannot_leave_anything_that_runs_later`, `the_home_protections_hold_whatever_else_is_granted`, `a_new_start_file_never_stays_silently` |
| An app replaces SAM's own program, which every menu entry runs outside the sandbox (SAM's AppImage kept in a folder the app may write, such as `~/Downloads`) | SAM's AppImage and its programs are read-only wherever the sandbox shows them writable, and the folders above them cannot be renamed | `an_app_can_never_replace_the_programs_that_menu_entries_run`, `sams_own_programs_are_read_only_wherever_an_app_could_write_them` |
| An app types commands into your terminal | The syscall filter refuses `TIOCSTI`; terminal programs run on SAM's own pseudo-terminal, which drops clipboard and report escape codes | `every_breakout_attempt_from_a_real_sandbox_fails` (`TIOCSTI` and `TIOCLINUX` answer the filter's `EPERM`), the evil suite (TypeIntoTerminal: only the filter's `EPERM` counts as blocked), `a_sandboxed_terminal_app_cannot_reach_past_the_terminal` (escape codes, from a real sandbox), `the_app_cannot_reach_the_outer_terminal` |
| An app starts a program outside the sandbox through a desktop service (systemd, the Flatpak spawn portal, a launcher) | The filtered D-Bus proxy allows only a short list of services; host tools like `systemd-run` and `flatpak-spawn` are replaced by stand-ins; allowing a service that acts outside the sandbox, a terminal that runs any command it is sent among them, is rated Dangerous and asks first | the evil suite (Systemd, FlatpakSpawn, Launcher), the breakout test (`systemd-run`), `host_tools_that_start_programs_outside_meet_their_stand_ins` (both stand-ins, in a real sandbox), `a_terminal_that_runs_commands_is_dangerous_to_reach` |
| An app poses as a desktop service (takes over a portal's or the notification service's name) | SAM refuses dangerous names and names of services that start on demand | the evil suite (ImpersonatePortal), `own_names_that_are_refused` |
| An app reads your passwords from the keyring | The keyring is blocked unless you allow it, and the switch says that the keyring does not separate apps | the evil suite (Keyring) |
| An app uses the network when it should not | No network: its own empty network; "This computer only": pasta with only the ports you list, every other service on your computer stays unreachable | the evil suite (NetworkWhenOff), `each_permission_grants_exactly_its_access_in_a_real_sandbox` (a listed and an unlisted port) |
| An app keeps running unsupervised after SAM's launcher crashes or is killed | The sandbox dies with its launcher: Bubblewrap's `--die-with-parent`, and a parent-death signal on the process SAM starts (pasta with "This computer only") | `without_network_the_sandbox_dies_with_its_launcher`, `with_this_computer_only_the_sandbox_dies_with_its_launcher` |
| SAM claims protection it did not apply (Landlock or the syscall filter missing at a start) | The start is recorded with its missing layers; the command line warns, a start from the menu shows a notification while the app runs, the app's page and the overview show it; a syscall filter that fails to load stops the start | `a_start_without_the_helper_reports_its_missing_layers`, `a_wanted_layer_that_was_not_applied_is_reported_missing`, `a_start_without_a_wanted_protection_layer_is_marked`, `a_syscall_filter_that_fails_to_load_stops_the_start`, `a_missing_layer_is_told_while_the_app_runs`, `a_menu_start_is_told_when_a_protection_layer_is_missing` |
| An app's settings run its code before Landlock and the syscall filter (`LD_PRELOAD` or `LD_LIBRARY_PATH` in its variables, from a setting or an imported preset) | The app's own variables never reach SAM's helper, which applies the layers: the helper sets them for the app alone, once its layers are in place | `the_apps_variables_reach_it_only_after_the_helpers_layers` |
| An app gets an open descriptor from the program that started SAM (a terminal's or launcher's leak) and writes past SAM's terminal filter or into another program | SAM's programs mark every descriptor they inherited close-on-exec before they start anything, so only the standard three reach the sandbox | `a_descriptor_sam_inherited_never_reaches_the_app` |
| Another user on the computer reads an app's private data (its home, its layer of the app folder, its logs) | These folders are for your user only (0700) and the logs readable by you only (0600), also when an older SAM made them readable for everyone | `private_folders_and_logs_are_for_the_user_only` |
| A program in the app asks for a sandbox of its own (`bwrap`) to get more than the app | Room service builds it outside, from the app's own view only (each folder opened beneath its place, no link out), with SAM's layers before anything of the request runs; options that could give more are refused; rooms end with the app | `room_service_builds_working_rooms_that_never_get_more_than_their_app`, `every_room_is_a_subset_of_its_app`, `under_this_computer_only_a_room_reaches_no_more_than_its_app` |
| An app watches your other windows or keystrokes | Wayland with a security context, so the compositor withholds its protocols for the clipboard in the background, screen capture, fake input and other windows; X11 only when you allow it (and the X11 switch says what it costs) | `each_permission_grants_exactly_its_access_in_a_real_sandbox` (in the KWin session of `tests/gui/desktop-sandbox.sh`: the app's connection lacks every such protocol a client of the compositor's own socket gets; needs a newer KWin than CI's 5.27, which offers no security contexts), `wayland_security_context_socket_is_used` |
| A hostile AppImage escapes while being unpacked (paths with `..`, symlinks out of the image, setuid bits, huge images) | SAM's own unpacker with limits on size, files and time, run in a sandbox; the limits, and one on memory, hold for every unpacking program while it runs, so an image SAM's reader cannot read gets no tool without them; a full disk stops unpacking; setuid bits removed; paths checked | `every_unpacking_tool_meets_the_limits_while_it_runs`, `a_full_disk_in_the_unpack_sandbox_stops_unpacking`, `paths_climbing_out_of_the_image_are_refused`, `an_entry_named_dot_dot_writes_nothing_outside_the_app`, `unpacking_removes_setuid_bits`, `a_menu_start_after_free_space_unpacks_inside_a_sandbox`, `without_the_command_line_a_menu_start_refuses_to_unpack`, the evil suite (SymlinkToKey, SetuidInImage) |
| A damaged or hostile AppImage crashes SAM | The parsers are fuzzed; a reader crash becomes an error; one bad file does not stop the list | `changed_appimages_never_crash_or_escape_the_unpacker`, `one_damaged_appimage_does_not_stop_the_list` |
| A crafted key or signature in an AppImage exploits a bug in GnuPG when SAM checks the signature | GnuPG reads them only inside the unpack sandbox (no network, nothing of the home, the syscall filter) | `gnupg_reads_an_appimages_key_and_signature_only_in_a_sandbox` |
| A package renames SAM's programs (for example a wrapped program in Nix), so that SAM no longer recognises them and unpacks AppImages or runs GnuPG on their keys without a sandbox where none can be built | Every release build of SAM refuses to unpack there, whatever its program is called, and says what is missing (Bubblewrap, or the `sam-jail` next to the program), so an added AppImage's signature counts as not checked; the one exception is SAM's own update, whose signature GnuPG still checks directly there (see docs/security.md, "Signatures"); SAM's own programs refuse in every build; only a developer build of a program that is not SAM's (a test) unpacks in its own process | `a_release_build_of_any_name_never_unpacks_without_a_sandbox`, `sams_programs_refuse_without_a_sandbox_in_every_build`, `sams_programs_never_unpack_without_a_sandbox` |
| An app's output talks SAM into granting access | Suggestions based on what an app printed always ask first and are labelled as the app's request, and never offer a service that acts outside the sandbox (a terminal included); a diagnostic trace (which the app can write) never grants more than a real folder of shared system data, and SAM reads it only as a plain file of limited size, never through a link or from a named pipe | `app_output_cannot_buy_dangerous_grants`, `a_forged_trace_line_cannot_widen_a_low_risk_grant`, `the_apps_own_words_never_give_it_a_terminal_to_talk_to`, `the_trace_is_read_only_as_a_plain_file_of_limited_size` |
| Text from an app tricks you in SAM's window | Markup and control characters are removed before SAM shows names or messages | `markup_in_metadata_is_neutralized` |
| A changed app record makes SAM delete or move your files | Records with unsafe IDs are ignored; SAM deletes and moves only inside its own folders, after resolving `..`; going back puts the earlier version only into the app's own folder; the data of an app whose record SAM cannot read is not offered for deletion | `removing_a_sandbox_never_deletes_outside_sams_unpack_folder`, `undoing_an_update_never_moves_files_outside_sams_backup_folder`, `going_back_puts_the_earlier_version_only_into_the_apps_folder`, `data_of_an_unreadable_record_is_not_offered_for_deletion` |
| A changed app record adds a line to SAM's menu entry that starts the app without a sandbox | Only clean values go into SAM's menu entry | `app_metadata_cannot_add_lines_to_sams_menu_entry`, `a_hostile_name_adds_no_line_to_sams_menu_entry` |
| Another tool's menu entry starts the AppImage without its sandbox, from the menu or when you open one of its file types | SAM shows such entries as a warning; hiding one deletes it for your user (`Hidden=true`), so it neither shows in the menu nor opens files; an entry only taken out of the menu (`NoDisplay`) that still opens files counts as unsandboxed | `a_hidden_entry_no_longer_opens_files`, `entries_that_still_open_files_are_not_taken_for_hidden`, `hide_and_restore_user_entry` |
| A script, another tool or a damaged disk changes an app's settings | Every record SAM saves carries a checksum; a record that does not match, has none, or claims an older format than the checksum (which came after format 1) does not start until you confirm its settings, and the question names what they let the app do (SAM can tell that they changed, not what changed) | `an_app_changed_outside_sam_starts_only_after_confirmation`, `records_changed_outside_sam_are_recognized`, `confirming_changed_settings_names_what_they_allow`, `tests/gui/app-page-atspi.sh` |
| An AppImage names itself after another app, so that a command meant for that app changes it instead | A reference that names more than one app by any rule is refused with their IDs, unless the app named exactly so was added before all the others | `an_apps_own_name_never_captures_a_reference_to_another_app`, `a_name_an_app_chose_cannot_take_over_another_apps_query` |
| An update replaces SAM itself with someone else's program | SAM installs an update of itself only with a valid signature from one of its release keys, whose fingerprints are built into SAM; without such a key it does not update itself and points to the release page | `sam_updates_itself_only_with_its_release_key`, `without_a_release_key_sam_never_updates_itself`, `sam_refuses_a_forged_update_that_carries_its_release_key`, `a_second_key_in_the_file_cannot_borrow_a_trusted_name` |
| A changed draft release gets SAM's release key (a replaced AppImage, one built for an older release, an added file, a swapped checksum list) | The signing script lets the key sign only files GitHub's build provenance shows the release build of that very tag made, source tarballs that match the package recipe, and the checksum lists it writes itself; any other file stops it before the key is used | `the_release_key_signs_no_appimage_the_release_build_did_not_make`, `an_appimage_built_for_an_older_release_is_not_signed`, `a_file_added_to_a_draft_release_stops_the_signing`, `source_files_that_differ_from_the_package_recipe_are_not_signed`, `a_checked_draft_is_signed_with_its_checksum_lists_written_again` |
| An update replaces an app with someone else's | A signed AppImage whose signing key changes is refused until you accept the new key, and so is an update whose signature cannot be checked (GnuPG missing); the yes covers only the file you were shown, never a second download; a signature recorded as not checked is checked again at update time; updates use HTTPS only | `key_changes_are_noticed`, `an_update_signed_with_another_key_waits_for_consent`, `consent_to_a_new_key_covers_only_the_file_that_was_shown`, `an_update_that_cannot_be_checked_needs_consent_after_a_valid_signature`, `an_update_compares_keys_even_when_the_installed_signature_was_never_checked`, `updates_are_downloaded_over_https_only`, `an_update_never_comes_over_plain_http`, `a_second_key_in_the_file_cannot_borrow_a_trusted_name` |
| Another app swaps an AppImage it can write to, so that adding it, unpacking it again, an update or going back gives its program this app's permissions | Adding and unpacking again work from one copy in SAM's own folder, so what is unpacked is what was checked and recorded, and a changed file is marked; an update and going back refuse a file that is not the one SAM unpacked, read the update source from a checked copy in SAM's own folder, and unpack the checked download, not the file in the AppImage's folder | `what_is_unpacked_is_what_sam_checked_even_if_the_file_is_swapped`, `an_appimage_swapped_before_an_update_is_not_updated_into_its_sandbox`, `an_update_unpacks_the_checked_download_even_if_the_placed_file_is_swapped`, `going_back_refuses_a_current_version_swapped_outside_sam`, `going_back_keeps_a_copy_of_the_newer_version_no_other_app_can_change` |
| An update server names the new file after a command (`sudo` in `~/.local/bin`) | The published name is used only when it is a plain `.AppImage` name; otherwise the old name stays | `an_update_never_takes_a_published_name_that_is_not_an_appimage_name`, `only_a_plain_appimage_name_is_taken_from_an_update` |
| A hostile or broken update server fills the disk or the memory, or hands out a build that cannot run | SAM stops a download at the published length itself; a release description is read whole or not at all; descriptions with countless tiny blocks are not planned with, and the old version is mapped, not read; an update for another processor is refused before anything changes | `a_server_that_sends_more_than_announced_cannot_fill_the_disk`, `a_full_download_stops_at_the_published_length_whatever_the_server_sends`, `a_whole_answer_is_never_cut_off_and_handed_on_as_complete`, `a_description_with_tiny_or_countless_blocks_is_refused_before_allocating`, `an_update_built_for_another_processor_is_not_installed` |

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
- **The moment between unplugging a game controller and its removal.**
  With *Game controllers*, SAM takes an unplugged controller's node out of
  the running app at once, so a keyboard plugged in later and given the
  same number never takes its place. A handle the app already holds could
  otherwise open the node again through `/proc/self/fd`; Landlock closes
  that way, so SAM takes a node out only where its helper reports Landlock
  in place and the app cannot make namespaces of its own. Elsewhere an
  unplug ends the app. What remains are two short times in which a new
  device would have to appear at the same number: between the unplug and
  the removal (milliseconds), and at the start, between SAM choosing the
  controllers and the sandbox being ready to watch (until Bubblewrap and
  SAM's helper have reported, at most about 5 seconds).
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
