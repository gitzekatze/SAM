# 🛠️ SAM development dashboard

> **What this page is:** the front page for people who work on SAM. It shows
> whether SAM is healthy right now, every test with the promise it keeps, how
> the version reports changed over time, and the latest commits. For people
> who use SAM, the front page is [README.md](README.md).
>
> Generated on 2026-11-15 at 07:20 by `scripts/dashboard.py`. It is
> regenerated with every version report (`make report`), so it shows the state
> at the end of the last phase of work.

## At a glance

[![CI](https://github.com/gitzekatze/SAM/actions/workflows/ci.yml/badge.svg)](https://github.com/gitzekatze/SAM/actions/workflows/ci.yml)

| | |
|---|---|
| **Tests** | ✅ 218 pass, 0 fail in the latest version report |
| **Version** | 0.1.0 (the number changes only when a version is published) |
| **Latest commit** | `983638c` Repair: use the system's copy of a bundled library that is too old |
| **Commits so far** | 145 |
| **Version reports** | 6; the newest is [0.1.0-983638c](docs/reports/0.1.0-983638c.md) |

> **How to read the badge:** it shows the last CI run on GitHub (unit,
> integration, sandbox and window tests on Ubuntu; sandbox tests on Fedora).
> Green means every test passed there; click it for the details.

## Health of each part

> **What you see:** for each part of SAM, its tests in the latest version
> report, and how much of its code those tests run (line coverage, the bar).
> Low coverage hints where a regression test may be missing; it is not a
> grade. The window (sam-gtk) is mostly checked by the scripted window tests
> further down, which line coverage does not count.

| Part | What it does | Tests | Line coverage |
|---|---|---|---|
| **sam-core** | Permission model, risk, warnings, configuration and file formats | ✅ 27 passing | `█████████████████░░░` 86.6 % |
| **sam-detect** | Recognizing AppImages and what they need (ELF, toolkits, signatures) | ✅ 19 passing | `███████████████░░░░░` 74.6 % |
| **sam-intake** | Unpacking AppImages safely, metadata, menu entries | ✅ 25 passing | `█████████████████░░░` 83.8 % |
| **sam-profile** | Recommendations, the user's presets, change checks, permission tags | ✅ 13 passing | `█████████████████░░░` 87.3 % |
| **sam-sandbox** | Building the Bubblewrap command from the permissions | ✅ 17 passing | `███████████████████░` 95.1 % |
| **sam-runner** | Operations: add, launch, verify, repair, update, group changes; the sandbox at run time | ✅ 86 passing | `██████████████░░░░░░` 71.2 % |
| **sam-storage** | App records, presets and logs on disk | ✅ 8 passing | `███████████████████░` 92.9 % |
| **sam-jail-cli** | The command line and its JSON interface | ✅ 14 passing | `███░░░░░░░░░░░░░░░░░` 15.8 % |
| **sam-gtk** | The window (logic that runs without a display) | ✅ 9 passing | `█░░░░░░░░░░░░░░░░░░░` 2.7 % |

## Speed

> **What you see:** how long SAM's steps take, measured by `sam-jail dev bench`
> on a test AppImage with 2,000 files and on 120 sandboxed apps. Each step runs
> several times after a warm-up run; the fastest run is shown, because it is the
> one least disturbed by other programs. The last column compares with the
> previous report: 🔺 means more than 25 % slower, 🔻 more than 25 % faster.
> A busy computer can cause such a change, so measure twice before you believe it.

| Step | Fastest run | Since the previous report |
|---|---|---|
| Recognizing the AppImage format of a file (reading its headers). | 0.007 ms | ≈ -1 % |
| Unpacking an AppImage with 2,000 files (16 MB) safely, without running it. | 46.185 ms | ≈ -1 % |
| Analyzing the unpacked app: its programs, libraries and toolkit. | 5.993 ms | ≈ +7 % |
| Recommending permissions from the app's metadata and analysis. | 0.001 ms | 🔺 +33 % |
| Building the Bubblewrap command from a set of permissions. | 0.299 ms | ≈ +1 % |
| Creating a sandbox for that AppImage end to end (unpack, analyze, recommend, save). | 218.510 ms | ≈ -2 % |
| Starting an app in a real sandbox until it has exited (an app that exits at once). | 59.021 ms | ≈ +6 % |
| Listing 120 sandboxed apps with their tags for the Permissions page. | 28.369 ms | ≈ +1 % |

## Tests

> **What you see:** every automated test, counted per part. A **unit test** checks
> one piece of code on its own. An **integration test** runs the real program end
> to end, often inside a real sandbox. A **regression test** ⟲ guards against a bug
> that really happened, and fails without its fix. Every test keeps one promise,
> stated in a complete sentence. The same list with links to the code is the
> [test library](docs/test-library.md).

| Part | Unit | Integration | Regression ⟲ | Total | |
|---|---|---|---|---|---|
| **sam-core** | 27 | 0 | 1 | 27 | `█████░░░░░░░░░░` |
| **sam-detect** | 18 | 1 | 0 | 19 | `███░░░░░░░░░░░░` |
| **sam-intake** | 24 | 1 | 1 | 25 | `████░░░░░░░░░░░` |
| **sam-profile** | 13 | 0 | 0 | 13 | `██░░░░░░░░░░░░░` |
| **sam-sandbox** | 17 | 0 | 0 | 17 | `███░░░░░░░░░░░░` |
| **sam-runner** | 48 | 38 | 2 | 86 | `███████████████` |
| **sam-storage** | 8 | 0 | 1 | 8 | `█░░░░░░░░░░░░░░` |
| **sam-jail-cli** | 0 | 14 | 1 | 14 | `██░░░░░░░░░░░░░` |
| **sam-gtk** | 9 | 0 | 1 | 9 | `██░░░░░░░░░░░░░` |
| **all parts** | **164** | **54** | **7** | **218** | |

### Scripted checks of the window and of real AppImages

> These run SAM's window or real AppImages in an invisible desktop session. The
> window smoke test runs in CI; the others are started by hand.

- `tests/gui/smoke.sh` — Every page of the window opens without GTK warnings, criticals or panics, in a wide and a narrow window.
- `tests/gui/permissions-atspi.sh` — Through the accessibility interface: the Permissions page selects apps, names its controls, warns before an app loses something it needs, applies a group change, and Undo restores every app; tag filters cycle.
- `tests/gui/app-page-atspi.sh` — Through the accessibility interface: the app page has one Test button with a visible test state, the trash button as high as Test and Launch, advice in one group, a visible "Files This App Saved" row, and a remove dialog whose three choices are not preselected and whose button cannot be pressed before a choice.
- `tests/gui/taskbar-kwin.sh` — In a hidden KWin session, a sandboxed app's window is named after SAM's menu entry, so the taskbar shows the app's own icon and name.
- `crates/sam-runner/tests/fuzz.rs with SAM_FUZZ_ITERS=100000` — A long fuzzing session: hundreds of thousands of changed inputs for every parser of untrusted data, without a crash.
- `tests/real-apps/run.sh` — Real AppImages from the test sets start in their sandbox; results are compared with the last baseline.

### Every test

> Click a part to unfold its tests. The promise is the first sentence of the test's
> own comment; the name links to the code.

<details><summary><b>sam-core</b> — Permission model, risk, warnings, configuration and file formats (27 tests)</summary>

| Kind | Promise | Test |
|---|---|---|
| unit | A complete configuration file with every section loads without loss. | [`a_complete_configuration_file_loads_every_setting`](crates/sam-core/src/config.rs#L304) |
| unit | Settings can be changed by key, and old theme names are migrated to Light, Dark or System. | [`settings_change_by_key_and_old_theme_names_are_migrated`](crates/sam-core/src/config.rs#L338) |
| unit | SAM refuses to overwrite a file written by a newer SAM and reads files without a format number as format 0. | [`files_from_a_newer_sam_are_never_overwritten`](crates/sam-core/src/format.rs#L97) |
| unit | Bubblewrap versions are compared correctly, including missing or malformed version text. | [`bubblewrap_versions_are_compared_correctly`](crates/sam-core/src/host.rs#L130) |
| unit | The X11 display number is read from every common DISPLAY form, and remote displays are refused. | [`the_x11_display_number_is_read_from_every_display_form`](crates/sam-core/src/host.rs#L454) |
| unit | Only real socket paths are taken from a D-Bus address; abstract sockets are not. | [`only_real_socket_paths_are_taken_from_a_dbus_address`](crates/sam-core/src/host.rs#L463) |
| unit | Changing an app's settings clears the record of a failed start, so the app is no longer shown as broken. | [`profile_change_clears_broken_launch`](crates/sam-core/src/model.rs#L639) |
| unit | An app with compatibility risk carries a warning badge until it has started successfully once. | [`apps_with_compatibility_risk_are_marked_until_they_start`](crates/sam-core/src/model.rs#L657) |
| unit ⟲ | Regression: sandboxed windows carried the app's id as their app ID while SAM's menu entry is "sam-<id>.desktop", so the taskbar found no entry and showed a generic icon. | [`the_window_id_matches_the_name_of_sams_menu_entry`](crates/sam-core/src/paths.rs#L117) |
| unit | An app may not own a bus name of a desktop service or of a service that starts on demand; its own application names stay allowed. | [`own_names_that_are_refused`](crates/sam-core/src/permissions.rs#L843) |
| unit | Folder access is read from both the old form (true/false) and the current form ("ro", "rw"). | [`access_from_bool_and_str`](crates/sam-core/src/permissions.rs#L855) |
| unit | Permissions can be read and set by key, and unknown keys or values are refused. | [`set_and_get_keys`](crates/sam-core/src/permissions.rs#L868) |
| unit | A bus name the user blocks stays blocked even when a wildcard in the allowed list would match it. | [`blocked_names_win_over_wildcards`](crates/sam-core/src/permissions.rs#L887) |
| unit | Settings saved with options SAM no longer has still load, with the removed options mapped to their safe meaning. | [`old_profiles_with_removed_options_still_load`](crates/sam-core/src/permissions.rs#L899) |
| unit | Permissions saved as TOML load back unchanged. | [`permissions_saved_as_toml_load_back_unchanged`](crates/sam-core/src/permissions.rs#L913) |
| unit | Raw sandbox arguments saved under their old name still load. | [`old_extra_backend_args_still_load`](crates/sam-core/src/permissions.rs#L926) |
| unit | Only plain shared-library file names are accepted as system libraries: no folders, no `..`, nothing that is not a library. | [`only_plain_library_names_are_accepted`](crates/sam-core/src/permissions.rs#L934) |
| unit | SAM's strictest window profile counts as low risk. | [`the_strictest_window_profile_is_low_risk`](crates/sam-core/src/risk.rs#L308) |
| unit | Full home access counts as dangerous, and as think twice when it is read-only. | [`full_home_is_dangerous`](crates/sam-core/src/risk.rs#L315) |
| unit | Full network together with X11 makes the settings think twice (high risk). | [`network_and_x11_high`](crates/sam-core/src/risk.rs#L325) |
| unit | Paths that hold keys or the whole system (~/.ssh, /etc, /) are recognized as sensitive; ordinary folders are not. | [`key_and_system_folders_count_as_sensitive`](crates/sam-core/src/risk.rs#L336) |
| unit | Names become safe identifiers made of lowercase letters, digits and dashes. | [`names_become_safe_identifiers`](crates/sam-core/src/util.rs#L175) |
| unit | Shell quoting keeps spaces, quotes and empty strings intact. | [`shell_quoting_keeps_spaces_and_quotes_intact`](crates/sam-core/src/util.rs#L182) |
| unit | Text from an app is shown without markup or control characters, and long text is shortened. | [`neutralizes_markup_and_controls`](crates/sam-core/src/util.rs#L196) |
| unit | Dangerous settings (X11, full home, system bus, network an app does not need) each produce a warning. | [`each_dangerous_setting_produces_its_warning`](crates/sam-core/src/warnings.rs#L259) |
| unit | SAM's strictest window profile produces no danger warning. | [`strict_has_no_danger`](crates/sam-core/src/warnings.rs#L276) |
| unit | The X11 warning disappears when the user turns it off in the preferences. | [`x11_warning_can_be_disabled`](crates/sam-core/src/warnings.rs#L283) |

</details>

<details><summary><b>sam-detect</b> — Recognizing AppImages and what they need (ELF, toolkits, signatures) (19 tests)</summary>

| Kind | Promise | Test |
|---|---|---|
| unit | An ordinary program file is not taken for an AppImage. | [`plain_elf_is_not_appimage`](crates/sam-detect/src/appimage.rs#L287) |
| unit | A type 2 AppImage (ELF with the AppImage magic and a squashfs image) is recognized. | [`a_type_2_appimage_is_recognized`](crates/sam-detect/src/appimage.rs#L295) |
| unit | An AppImage with a DwarFS image instead of squashfs is recognized. | [`an_appimage_with_a_dwarfs_image_is_recognized`](crates/sam-detect/src/appimage.rs#L322) |
| unit | A file that is not an ELF program is not taken for an AppImage. | [`a_file_that_is_no_program_is_not_an_appimage`](crates/sam-detect/src/appimage.rs#L343) |
| unit | An AppImage runs on the same processor and 32-bit builds on their 64-bit relatives; ARM builds never run on x86-64 or the other way. | [`appimages_run_only_on_a_matching_processor`](crates/sam-detect/src/appimage.rs#L358) |
| unit | Bundled libraries are sorted into system, graphics, display-controlled and dangerous classes. | [`bundled_libraries_are_sorted_by_what_they_reach`](crates/sam-detect/src/classify.rs#L221) |
| unit | Programs that load graphics libraries only at run time are recognized as needing the GPU. | [`programs_that_load_graphics_at_run_time`](crates/sam-detect/src/elf.rs#L919) |
| unit | A missing optional library is reported with the feature it provides, not as a broken app. | [`missing_optional_libraries_name_the_feature`](crates/sam-detect/src/elf.rs#L936) |
| unit | Programs that choose the Qt platform themselves (X11 or Wayland) are recognized. | [`programs_that_choose_the_qt_platform`](crates/sam-detect/src/elf.rs#L972) |
| unit | A bundled Qt Wayland plugin counts as usable only when its Wayland client library is present. | [`qt_wayland_plugin_needs_its_client_library`](crates/sam-detect/src/elf.rs#L989) |
| unit | Start scripts that force X11 are recognized, so SAM grants X11 to those apps. | [`start_scripts_that_force_x11`](crates/sam-detect/src/elf.rs#L1000) |
| unit | When the AppImage starts through a shell script, SAM finds the program the script starts. | [`the_program_behind_a_start_script_is_found`](crates/sam-detect/src/elf.rs#L1034) |
| unit | An AppImage that asks for administrator rights (pkexec) is marked as unsafe to sandbox. | [`an_appimage_asking_for_admin_rights_is_unsafe_to_sandbox`](crates/sam-detect/src/elf.rs#L1048) |
| unit | Electron apps are recognized by their markers, and bundled library symlinks are followed. | [`electron_markers_and_bundled_symlinks`](crates/sam-detect/src/elf.rs#L1056) |
| unit | Libraries an app finds relative to its own folder ($ORIGIN) are counted as bundled, not as missing. | [`origin_relative_needed_paths`](crates/sam-detect/src/elf.rs#L1069) |
| unit | The C library version an app needs is read from its symbol versions. | [`the_c_library_version_an_app_needs_is_read`](crates/sam-detect/src/elf.rs#L1082) |
| unit | Both forms of update information (a direct zsync address and GitHub releases) are understood. | [`both_forms_of_update_information_are_understood`](crates/sam-detect/src/update_info.rs#L104) |
| unit | Wildcards in update information match the right file name and not the build for another processor. | [`update_wildcards_match_only_the_right_build`](crates/sam-detect/src/update_info.rs#L122) |
| integration | The signature of a signed AppImage is checked with GnuPG. | [`signed_appimage_is_checked`](crates/sam-detect/tests/signature.rs#L19) |

</details>

<details><summary><b>sam-intake</b> — Unpacking AppImages safely, metadata, menu entries (25 tests)</summary>

| Kind | Promise | Test |
|---|---|---|
| unit | SAM's menu entry starts the app only through SAM's sandbox: no value taken from the app (name, comment, categories, file types, window class) can add a line such as a second "Exec=" to it, even from a record changed outside SAM. | [`app_metadata_cannot_add_lines_to_sams_menu_entry`](crates/sam-intake/src/desktop.rs#L246) |
| unit | Program paths in menu entries are quoted so spaces and dollar signs cannot change the command. | [`menu_entry_paths_are_quoted_against_spaces_and_dollar_signs`](crates/sam-intake/src/desktop.rs#L264) |
| unit | SAM's menu entry starts the app through sam-jail-run, never the AppImage directly. | [`sams_menu_entry_starts_the_app_only_through_sam`](crates/sam-intake/src/desktop.rs#L272) |
| unit | SAM's menu entry never claims links, folders or desktop files, so a sandboxed app cannot take over opening them. | [`launcher_mime_types_drop_hijack_targets`](crates/sam-intake/src/desktop.rs#L289) |
| unit | Unpacking does not start when the folder clearly has too little room; the message names the folder, both sizes, and where to choose another folder. | [`unpacking_refuses_to_start_without_enough_free_space`](crates/sam-intake/src/extract.rs#L532) |
| unit | A full disk during unpacking is recognized, also inside an error chain, so SAM can clean up and say what happened. | [`a_full_disk_during_unpacking_is_recognized`](crates/sam-intake/src/extract.rs#L545) |
| unit | A changed AppImage file is noticed by its fingerprint. | [`a_changed_appimage_file_is_noticed`](crates/sam-intake/src/fingerprint.rs#L94) |
| unit | A readable name is taken from an AppImage's file name, without version and architecture. | [`a_readable_name_is_taken_from_the_file_name`](crates/sam-intake/src/id.rs#L64) |
| unit | App IDs are stable and unique, also when two AppImages have the same name. | [`app_ids_stay_unique_when_names_collide`](crates/sam-intake/src/id.rs#L72) |
| unit | The AppImage a foreign menu entry starts is found in its Exec line, also behind env and with quotes. | [`the_appimage_behind_a_foreign_menu_entry_is_found`](crates/sam-intake/src/menu.rs#L231) |
| unit | An unsandboxed menu entry in the user's folder is hidden on request and restored exactly as it was. | [`hide_and_restore_user_entry`](crates/sam-intake/src/menu.rs#L239) |
| unit | An unsandboxed menu entry in a system folder is hidden through an entry in the user's folder, without touching the system file. | [`system_entry_gets_override`](crates/sam-intake/src/menu.rs#L267) |
| unit | The desktop file inside an AppImage is read with name, translations, categories and file types. | [`the_desktop_file_inside_an_appimage_is_read`](crates/sam-intake/src/metadata.rs#L203) |
| unit | Name, icon and categories are read from the unpacked app. | [`reads_metadata_and_icon`](crates/sam-intake/src/metadata.rs#L213) |
| unit | Unpacking stops with a clear error when it takes longer than the time limit, so a huge or hostile AppImage cannot keep SAM busy forever. | [`unpacking_stops_at_the_time_limit`](crates/sam-intake/src/normalize.rs#L175) |
| unit | A symlink that points outside the unpacked app is recognized. | [`symlinks_pointing_outside_the_app_are_recognized`](crates/sam-intake/src/normalize.rs#L186) |
| unit | Paths from the AppImage image are made relative, and paths that climb out with .. | [`paths_climbing_out_of_the_image_are_refused`](crates/sam-intake/src/normalize.rs#L196) |
| unit | Unpacking removes setuid bits and makes files read-only for others. | [`unpacking_removes_setuid_bits`](crates/sam-intake/src/normalize.rs#L204) |
| unit | Unpacking stops when the AppImage contains more files than the limit. | [`unpacking_stops_at_the_file_limit`](crates/sam-intake/src/normalize.rs#L234) |
| unit | The name and icon of an AppImage are read without unpacking or running it. | [`peeks_name_and_icon_without_extracting`](crates/sam-intake/src/peek.rs#L125) |
| unit | Icon paths from the AppImage cannot climb out of the unpacked app. | [`icon_paths_cannot_climb_out_of_the_app`](crates/sam-intake/src/peek.rs#L139) |
| unit | Every SquashFS compression AppImages use is unpacked by the built-in reader, so none needs the AppImage's own extractor. | [`appimages_with_every_compression_unpack`](crates/sam-intake/src/testkit.rs#L147) |
| unit | A built AppImage is recognized and unpacked, with setuid bits removed. | [`a_built_appimage_is_detected_and_unpacked_safely`](crates/sam-intake/src/testkit.rs#L166) |
| unit | Unpacking stops at the size limit and leaves no partial files behind. | [`size_limit_aborts_and_cleans_up`](crates/sam-intake/src/testkit.rs#L203) |
| integration ⟲ | Regression: reading the name and icon of an AppImage whose SquashFS image makes the reader panic gives an error instead of crashing SAM. | [`a_damaged_squashfs_image_gives_an_error_instead_of_a_crash`](crates/sam-intake/tests/damaged.rs#L14) |

</details>

<details><summary><b>sam-profile</b> — Recommendations, the user's presets, change checks, permission tags (13 tests)</summary>

| Kind | Promise | Test |
|---|---|---|
| unit | Terminal programs get no display, GPU or desktop bus access. | [`terminal_programs_get_no_display`](crates/sam-profile/src/lib.rs#L503) |
| unit | The category of an app is recognized from its desktop categories. | [`the_app_category_is_recognized_from_its_desktop_categories`](crates/sam-profile/src/lib.rs#L519) |
| unit | Recommended permissions fit the category: a browser gets the network and Downloads, an editor no network. | [`recommendations_fit_the_category`](crates/sam-profile/src/lib.rs#L537) |
| unit | What SAM finds in the app (GPU, X11-only toolkit) adjusts the recommendation. | [`what_sam_finds_in_the_app_adjusts_the_recommendation`](crates/sam-profile/src/lib.rs#L552) |
| unit | The change check names what an app would lose that it needs, and the dangerous access it would gain. | [`change_check_flags_removals_and_additions`](crates/sam-profile/src/lib.rs#L562) |
| unit | A hidden folder is not a reason to warn that an app stops working: it is listed apart (regression for the group warning, which only interrupts for breakage). | [`folders_are_not_breakage_but_lost_local_network_and_bus_are`](crates/sam-profile/src/lib.rs#L587) |
| unit | An app that needs sound is warned about in the switch's word. | [`lost_sound_is_named_sound`](crates/sam-profile/src/lib.rs#L608) |
| unit | A new preset starts without home, network or system bus access. | [`preset_template_is_strict`](crates/sam-profile/src/lib.rs#L620) |
| unit | The bus names an app may own come from its application ID and window class, never from protocol or desktop-service names. | [`own_names_from_the_id_and_the_window_class`](crates/sam-profile/src/lib.rs#L639) |
| unit | An app with SAM's strictest window profile shows no tags, because it has nothing beyond the basics. | [`a_strict_window_app_has_no_tags`](crates/sam-profile/src/tags.rs#L141) |
| unit | Tags appear in the family order Network, Files, Devices, Desktop, and read-only access is marked. | [`tags_follow_the_family_order_and_mark_read_only`](crates/sam-profile/src/tags.rs#L147) |
| unit | Dangerous access gets red tags, and the filtered desktop bus, which every app has, gets none. | [`dangerous_access_is_red_and_filtered_bus_has_no_tag`](crates/sam-profile/src/tags.rs#L170) |
| unit | One name per permission: where the risk list names a permission that also has a tag, both use the same words (regression: "Audio" vs "Sound", "GPU" vs "GPU acceleration", "Show in folder"). | [`tags_and_the_risk_list_use_the_same_words`](crates/sam-profile/src/tags.rs#L216) |

</details>

<details><summary><b>sam-sandbox</b> — Building the Bubblewrap command from the permissions (17 tests)</summary>

| Kind | Promise | Test |
|---|---|---|
| unit | Games built with SDL get a silent sound driver when sound is off, so they start instead of failing. | [`sdl_gets_its_silent_driver_without_sound_access`](crates/sam-sandbox/src/lib.rs#L1368) |
| unit | Extra library folders of the system loader (for example CUDA) are visible to the app read-only. | [`the_loaders_extra_library_folders_are_shown_read_only`](crates/sam-sandbox/src/lib.rs#L1377) |
| unit | The app gets a new terminal session, unless it runs on SAM's terminal relay. | [`a_new_session_unless_the_app_is_on_sams_own_terminal`](crates/sam-sandbox/src/lib.rs#L1385) |
| unit | Files and folders named when starting an app are passed in, but never sensitive folders like autostart. | [`files_and_folders_named_on_the_command_line`](crates/sam-sandbox/src/lib.rs#L1394) |
| unit | The strictest profile builds a sandbox without network, environment or capabilities, with the app read-only. | [`the_strictest_profile_shares_nothing_and_keeps_the_app_read_only`](crates/sam-sandbox/src/lib.rs#L1451) |
| unit | The X11 login cookie is rewritten for the display number inside the sandbox. | [`xauthority_gets_the_sandbox_display_number`](crates/sam-sandbox/src/lib.rs#L1472) |
| unit | With a Wayland security context, the app sees only that socket, not the desktop's own. | [`wayland_security_context_socket_is_used`](crates/sam-sandbox/src/lib.rs#L1490) |
| unit | Each granted permission adds exactly its part to the Bubblewrap command. | [`each_permission_adds_exactly_its_part_to_the_command`](crates/sam-sandbox/src/lib.rs#L1500) |
| unit | The filtered desktop bus reaches the app only through SAM's proxy. | [`filtered_dbus_uses_proxy`](crates/sam-sandbox/src/lib.rs#L1525) |
| unit | The app runs with the user's IDs, and host tools that could leave the sandbox (systemd-run) are replaced by harmless stand-ins. | [`the_app_runs_as_the_user_and_host_tools_are_replaced_by_stand_ins`](crates/sam-sandbox/src/lib.rs#L1538) |
| unit | With "this computer only", the network namespace is left to pasta. | [`localhost_network_leaves_netns_to_pasta`](crates/sam-sandbox/src/lib.rs#L1557) |
| unit | A writable app folder uses an overlay; the unpacked app itself stays unchanged. | [`writable_appdir_uses_overlay`](crates/sam-sandbox/src/lib.rs#L1566) |
| unit | Without nested namespaces, the sandbox disables user namespaces and starts through SAM's helper. | [`without_nested_namespaces_user_namespaces_are_disabled`](crates/sam-sandbox/src/lib.rs#L1579) |
| unit | "Game controllers" exposes only joysticks, never keyboards or mice. | [`gamepads_only_exposes_joysticks`](crates/sam-sandbox/src/lib.rs#L1590) |
| unit | With the GPU, the NVIDIA driver modules are visible; other kernel modules are not. | [`nvidia_modules_are_exposed_with_the_gpu`](crates/sam-sandbox/src/lib.rs#L1608) |
| unit | Extra sockets are passed in only when they really are sockets. | [`extra_sockets_must_be_sockets`](crates/sam-sandbox/src/lib.rs#L1619) |
| unit | A bundled library listed in advanced.system_libraries is replaced by the system's copy at its place in the app folder; names with folders or `..`, libraries the app does not bundle and libraries the system does not have are ignored. | [`system_copies_replace_only_bundled_libraries_by_plain_name`](crates/sam-sandbox/src/lib.rs#L1637) |

</details>

<details><summary><b>sam-runner</b> — Operations: add, launch, verify, repair, update, group changes; the sandbox at run time (86 tests)</summary>

| Kind | Promise | Test |
|---|---|---|
| unit | Without Bubblewrap, the message says which package to install. | [`missing_bubblewrap_names_the_package_to_install`](crates/sam-runner/src/bwrap.rs#L42) |
| unit | When the system forbids user namespaces, the message explains that and never claims Bubblewrap is missing: the user already has it, and an "install bubblewrap" hint would send them the wrong way. | [`disabled_user_namespaces_are_explained_not_called_missing`](crates/sam-runner/src/bwrap.rs#L53) |
| unit | A setuid Bubblewrap works without unprivileged user namespaces, so SAM does not refuse it. | [`setuid_bubblewrap_works_without_user_namespaces`](crates/sam-runner/src/bwrap.rs#L69) |
| unit | SAM's own bus check reaches the session bus on a desktop. | [`reaches_the_session_bus`](crates/sam-runner/src/dbus_check.rs#L172) |
| unit | SAM's own D-Bus message for the bus check has the correct wire format. | [`the_bus_check_message_has_the_correct_wire_format`](crates/sam-runner/src/dbus_check.rs#L184) |
| unit | An app may register a tray icon only while the tray service is allowed. | [`tray_names_follow_watcher_permission`](crates/sam-runner/src/dbus_proxy.rs#L114) |
| unit | Failed file and socket accesses are read from a diagnostic trace. | [`failed_accesses_are_read_from_a_trace`](crates/sam-runner/src/diagnose.rs#L322) |
| unit | Failed accesses are mapped to the permission that would fix them (X11 socket, GPU device), and unknown paths to none. | [`failed_accesses_map_to_the_permission_that_fixes_them`](crates/sam-runner/src/diagnose.rs#L337) |
| unit | A GPU device that fails to open while the GPU is already allowed is reported as "already granted", not as a suggestion to allow the GPU (regression: neovide on NVIDIA got "Enable GPU acceleration" twice). | [`a_failure_despite_the_permission_is_not_suggested_again`](crates/sam-runner/src/diagnose.rs#L354) |
| unit | A missing cache, settings or data folder in the app's private home is the app's own and is not reported, while a missing document folder is (regression: ~/.cache/nvidia was suggested as a folder to grant). | [`the_apps_own_folders_in_its_private_home_are_not_reported`](crates/sam-runner/src/diagnose.rs#L372) |
| unit | A failed attempt to change a file's mode is not missing access (regression: NVIDIA's driver chmods /dev/nvidia-modeset, which fails for every ordinary user, and diagnose reported it as a GPU problem). | [`failed_changes_to_a_file_are_not_missing_access`](crates/sam-runner/src/diagnose.rs#L389) |
| unit | Checking whether a system file is writable is not missing access (regression: Zrythm and mpv ask access(W_OK) for files in /usr, which fails for every user, and diagnose suggested granting /usr/lib/lv2). | [`write_checks_on_system_folders_are_not_missing_access`](crates/sam-runner/src/diagnose.rs#L401) |
| unit | A file in /etc is suggested, never added by itself, because it describes this computer (regression: /etc/fstab and /etc/pacman.conf were "low risk" and added automatically, although the apps ran without them). | [`files_in_etc_are_suggested_and_not_added_automatically`](crates/sam-runner/src/diagnose.rs#L414) |
| unit | The app's own settings folder in its private home is not reported as a sensitive folder (regression: ~/.config was "dangerous"). | [`the_apps_own_settings_folder_is_not_reported_as_sensitive`](crates/sam-runner/src/diagnose.rs#L427) |
| unit | A bug report never contains the user's name or home path: both are replaced before the text is shown for copying. | [`bug_reports_hide_the_user_name_and_home_path`](crates/sam-runner/src/doctor.rs#L342) |
| unit | The Landlock rules allow writing exactly in the folders the permissions grant. | [`landlock_allows_writing_exactly_in_granted_folders`](crates/sam-runner/src/kernel.rs#L313) |
| unit | The syscall filter compiles in every variant and always blocks mount and io_uring. | [`the_syscall_filter_compiles_and_blocks_mount_and_io_uring`](crates/sam-runner/src/kernel.rs#L330) |
| unit | Without Bubblewrap, starting an app stops while it is being prepared, before any process is started, and the error says what to install. | [`a_start_without_bubblewrap_stops_before_anything_runs`](crates/sam-runner/src/launch.rs#L866) |
| unit | Bubblewrap setup errors are told apart from errors of the app itself. | [`sandbox_setup_errors_are_told_apart_from_app_errors`](crates/sam-runner/src/launch.rs#L886) |
| unit | A start is judged by whether Bubblewrap announced the app, not by what the app printed. | [`a_start_is_judged_by_whether_the_app_started`](crates/sam-runner/src/launch.rs#L899) |
| unit | With "this computer only", the app reaches only the ports on this computer the user lists. | [`only_listed_host_ports`](crates/sam-runner/src/netns.rs#L78) |
| unit | When SAM's recommendation improves, the user's own changes are kept. | [`user_changes_survive_better_recommendation`](crates/sam-runner/src/ops/mod.rs#L387) |
| unit | An update signed with another key, or not signed at all, is noticed. | [`key_changes_are_noticed`](crates/sam-runner/src/ops/mod.rs#L439) |
| unit | The sandbox check tells a real folder of the user from a private stand-in. | [`folder_check_tells_real_from_private`](crates/sam-runner/src/probe.rs#L389) |
| unit | The progress bar follows the weights of the steps of creating a sandbox. | [`fractions_follow_the_step_weights`](crates/sam-runner/src/progress.rs#L131) |
| unit | Unpacking progress counts the bytes written. | [`bytes_written_are_counted`](crates/sam-runner/src/progress.rs#L150) |
| unit | Ordinary terminal output, colors and links pass through the relay unchanged. | [`ordinary_output_passes_unchanged`](crates/sam-runner/src/pty.rs#L600) |
| unit | Escape codes that read or write the clipboard are removed from an app's terminal output. | [`clipboard_codes_are_removed`](crates/sam-runner/src/pty.rs#L610) |
| unit | Escape codes that report the window title or pass through tmux are removed; setting the title stays allowed. | [`title_reports_and_tmux_passthrough_are_removed`](crates/sam-runner/src/pty.rs#L629) |
| unit | An escape code hidden inside a removed code cannot slip through. | [`an_escape_inside_a_removed_code_starts_a_new_sequence`](crates/sam-runner/src/pty.rs#L643) |
| unit | Logs get plain text without escape codes. | [`plain_text_for_the_log`](crates/sam-runner/src/pty.rs#L652) |
| unit | Apps started from a terminal get SAM's terminal relay; apps without a terminal get none. | [`terminal_apps_get_sams_terminal_relay`](crates/sam-runner/src/pty.rs#L658) |
| unit | A second pseudo-terminal stands in for the user's terminal: SAM's side of it is `Outer`, the test plays the terminal program. | [`typing_and_output_pass_and_leftover_replies_are_discarded`](crates/sam-runner/src/pty.rs#L669) |
| unit | An app on SAM's terminal relay cannot type into the user's real terminal. | [`the_app_cannot_reach_the_outer_terminal`](crates/sam-runner/src/pty.rs#L722) |
| unit | SAM accepts an update of itself only with a valid signature from one of its release keys; unsigned, changed, unchecked or otherwise signed updates are refused (regression: self-update installed any AppImage the update information pointed to). | [`sam_updates_itself_only_with_its_release_key`](crates/sam-runner/src/release_key.rs#L57) |
| unit | Without a built-in release key, SAM never updates itself, whatever the download looks like. | [`without_a_release_key_sam_never_updates_itself`](crates/sam-runner/src/release_key.rs#L72) |
| unit | Compatibility mode lists only what it actually changes, in the words of the switches. | [`compatibility_mode_names_only_what_it_changes`](crates/sam-runner/src/repair.rs#L533) |
| unit | A repair step says in a sentence what it turns on or off, with the switch's own explanation of what that allows. | [`a_repair_step_says_what_it_changes_and_costs`](crates/sam-runner/src/repair.rs#L544) |
| unit | An app that fails to register its bus name gets a repair step that allows exactly that name. | [`own_name_requests_become_a_repair`](crates/sam-runner/src/repair.rs#L564) |
| unit | Error messages in an app's output are mapped to the repair step that fixes them. | [`analyzer_maps_errors_to_fixes`](crates/sam-runner/src/repair.rs#L581) |
| unit | The repair ladder leaves out steps already applied and steps that would change nothing. | [`ladder_skips_applied_and_noop_steps`](crates/sam-runner/src/repair.rs#L628) |
| unit | The repair steps offer a writable app folder only where an overlay can work: not where SAM's overlay folder cannot hold one (regression: the step was offered by Bubblewrap's version alone, and on such disks the app then started read-only anyway). | [`a_writable_app_folder_is_offered_only_where_it_can_work`](crates/sam-runner/src/repair.rs#L648) |
| unit | The header of a zsync file is read (file name, size, checksum). | [`the_zsync_header_is_read`](crates/sam-runner/src/updates.rs#L355) |
| unit | Download addresses in zsync files are resolved, and plain-HTTP addresses are refused. | [`update_download_addresses_are_resolved_and_http_refused`](crates/sam-runner/src/updates.rs#L365) |
| unit | Update downloads use HTTPS only; HTTP and file addresses are refused. | [`updates_are_downloaded_over_https_only`](crates/sam-runner/src/updates.rs#L376) |
| unit | An update is rebuilt from the old version plus the changed blocks. | [`an_update_is_rebuilt_from_the_old_version_and_changed_blocks`](crates/sam-runner/src/zsync.rs#L311) |
| unit | The rolling checksum of the update transfer matches a direct computation at every offset. | [`the_rolling_checksum_matches_a_direct_computation`](crates/sam-runner/src/zsync.rs#L347) |
| unit | Compressed or incomplete zsync files are refused. | [`refuses_compressed_and_broken_files`](crates/sam-runner/src/zsync.rs#L361) |
| integration | H1: an app printing a fake Bubblewrap error is not a sandbox failure. | [`fake_bwrap_error_is_not_a_sandbox_failure`](crates/sam-runner/tests/adversarial.rs#L20) |
| integration | H2/M4: suggestions derived from app output never grant escape-capable services or protected folders, and are always marked as app-derived. | [`app_output_cannot_buy_dangerous_grants`](crates/sam-runner/tests/adversarial.rs#L43) |
| integration | H3: markup in an AppImage's name or comment is neutralized before it is stored or shown. | [`markup_in_metadata_is_neutralized`](crates/sam-runner/tests/adversarial.rs#L61) |
| integration | M1: a launcher never registers URL schemes, directories or executables. | [`launcher_drops_hijack_mime_types`](crates/sam-runner/tests/adversarial.rs#L72) |
| integration | Robustness: malformed desktop files and files that only look like AppImages must not crash the parsers (simple deterministic fuzzing). | [`parsers_survive_garbage`](crates/sam-runner/tests/adversarial.rs#L83) |
| integration | Every security promise holds inside a real sandbox: each breakout attempt fails. | [`every_breakout_attempt_from_a_real_sandbox_fails`](crates/sam-runner/tests/breakout.rs#L147) |
| integration | Every hostile AppImage, added and started like any other, fails to get out of its sandbox: it cannot read keys, SAM's settings or another app's files; cannot write autostart entries, shell startup files or host temporary files; cannot type into the terminal, reach the network when it has none, see host processes or change its own app folder; cannot reach systemd, the Flatpak spawn portal, the keyring or a launcher service, nor take over a portal's name on the desktop bus; and a symlink or setuid bit in its image gains it nothing. | [`every_hostile_appimage_fails_to_escape`](crates/sam-runner/tests/evil.rs#L127) |
| integration | Changed AppImages are recognized or refused, and unpacked or refused, without a panic; unpacking writes only inside its own folder and keeps its time limit. | [`changed_appimages_never_crash_or_escape_the_unpacker`](crates/sam-runner/tests/fuzz.rs#L119) |
| integration | Changed desktop files, zsync files and update information are parsed or refused without a panic. | [`changed_text_inputs_never_crash_the_parsers`](crates/sam-runner/tests/fuzz.rs#L170) |
| integration | Changed ELF programs inside an unpacked app are analyzed or skipped without a panic. | [`changed_programs_never_crash_the_analysis`](crates/sam-runner/tests/fuzz.rs#L198) |
| integration | A dry run of a group change saves nothing and names what each app would lose. | [`a_dry_run_changes_nothing_and_names_what_would_stop_working`](crates/sam-runner/tests/groups.rs#L35) |
| integration | A group change saves only the apps whose value changes, and one undo restores all of them. | [`only_changed_apps_are_saved_and_one_undo_restores_all_of_them`](crates/sam-runner/tests/groups.rs#L51) |
| integration | A group change with an invalid value or an unknown app changes no app. | [`an_invalid_value_or_unknown_app_changes_no_app`](crates/sam-runner/tests/groups.rs#L71) |
| integration | The Permissions overview lists every sandboxed app with its tags and states. | [`the_overview_lists_every_sandboxed_app_with_tags_and_states`](crates/sam-runner/tests/groups.rs#L85) |
| integration | SAM ships no presets; old built-in names are free for the user, and applying a preset asks before it removes something an app needs. | [`sam_ships_no_presets_and_old_built_in_names_are_free_for_the_user`](crates/sam-runner/tests/groups.rs#L97) |
| integration | Saving an app's settings as a preset keeps them exactly. | [`saving_an_apps_settings_as_a_preset_keeps_them_exactly`](crates/sam-runner/tests/groups.rs#L116) |
| integration | Inside a real sandbox, each permission grants exactly its access and nothing more. | [`each_permission_grants_exactly_its_access_in_a_real_sandbox`](crates/sam-runner/tests/matrix.rs#L81) |
| integration | When the folder for the writable app folder's changes cannot hold an overlay, the app still starts, with a read-only app folder and a warning that says why (regression: on Fedora in a container, SAM's data folder was on an overlay, and the app failed with a raw Bubblewrap error). | [`an_app_starts_read_only_when_its_writable_app_folder_cannot_work`](crates/sam-runner/tests/overlay_fallback.rs#L31) |
| integration | AppImages are listed before they have a sandbox; only creating the sandbox adds SAM's menu entry and hides unsandboxed ones, and removing it puts them back. | [`found_appimages_get_a_menu_entry_only_with_a_sandbox`](crates/sam-runner/tests/overview.rs#L12) |
| integration | Inside a real sandbox, each profile shows exactly the files and services it allows. | [`a_real_sandbox_shows_exactly_what_each_profile_allows`](crates/sam-runner/tests/sandbox.rs#L58) |
| integration | Turning compatibility mode off restores exactly the settings the user had before. | [`turning_compatibility_mode_off_restores_exactly_the_settings_from_before`](crates/sam-runner/tests/settings.rs#L30) |
| integration | Undoing repair steps restores the settings from before the first step. | [`undoing_repair_steps_restores_the_settings_from_before_the_first_step`](crates/sam-runner/tests/settings.rs#L44) |
| integration | "Reset to recommendation" brings back SAM's recommended settings and turns compatibility mode off. | [`reset_to_recommendation_brings_back_the_recommended_settings`](crates/sam-runner/tests/settings.rs#L64) |
| integration | A running app keeps its sandbox: removing it is refused until the app is closed (a launch holds a lock in the app's runtime folder). | [`removing_a_sandbox_while_its_app_runs_is_refused`](crates/sam-runner/tests/settings.rs#L81) |
| integration | Removing a sandbox with "keep my data" keeps the app's private home; without it, the home is deleted. | [`removing_with_keep_my_data_keeps_the_private_home_and_without_deletes_it`](crates/sam-runner/tests/settings.rs#L98) |
| integration | When a sandboxed app's AppImage is moved to another searched folder, SAM recognizes it by its content and offers to follow it. | [`a_moved_appimage_is_recognized_by_its_content`](crates/sam-runner/tests/settings.rs#L117) |
| integration | A repair step can be switched off on its own: exactly what that step changed goes back, and the other applied steps stay. | [`switching_off_one_repair_step_keeps_the_others`](crates/sam-runner/tests/settings.rs#L135) |
| integration | Freeing space deletes the unpacked copy, and unpacking again brings the app back. | [`freeing_space_deletes_the_unpacked_copy_and_unpacking_restores_it`](crates/sam-runner/tests/space.rs#L12) |
| integration | Closing an app ends all of its running starts. | [`stop_closes_running_apps`](crates/sam-runner/tests/stop.rs#L49) |
| integration ⟲ | Regression: the unpack folder in a record was only checked with Path::starts_with, which does not resolve "..": "extracted/../../victim" passed, and removing the sandbox deleted the victim folder. | [`removing_a_sandbox_never_deletes_outside_sams_unpack_folder`](crates/sam-runner/tests/tamper.rs#L22) |
| integration | A record whose id climbs out of SAM's folders cannot be loaded, so no operation can reach the folders that id would name. | [`a_record_with_a_climbing_id_reaches_nothing`](crates/sam-runner/tests/tamper.rs#L42) |
| integration ⟲ | Regression (found in the test audit): "go back to the earlier version" moved the file a record named as the backup, wherever it was. | [`undoing_an_update_never_moves_files_outside_sams_backup_folder`](crates/sam-runner/tests/tamper.rs#L61) |
| integration | An app whose settings were changed outside SAM does not start until the user has confirmed them; changes SAM makes itself never count as such. | [`an_app_changed_outside_sam_starts_only_after_confirmation`](crates/sam-runner/tests/tamper.rs#L78) |
| integration | Uninstalling SAM removes all of its files and restores the menu entries it had hidden. | [`uninstall_removes_everything_and_restores_menus`](crates/sam-runner/tests/uninstall.rs#L16) |
| integration | Uninstalling refuses to delete a folder that is not SAM's, such as the home folder. | [`uninstall_refuses_folders_that_are_not_sams`](crates/sam-runner/tests/uninstall.rs#L67) |
| integration | Undoing an update puts the previous version back. | [`undo_puts_the_previous_version_back`](crates/sam-runner/tests/update.rs#L14) |
| integration | The sandbox check passes when the settings apply, and catches a setting that does not apply. | [`the_sandbox_check_passes_and_catches_mismatches`](crates/sam-runner/tests/verify.rs#L19) |
| integration | An AppImage for ARM is refused on an x86-64 computer with a sentence that names both processors and what to download instead, and nothing is stored (regression: SAM created a sandbox for an arm64 Neovim and failed only at the start, with "permission denied or wrong format"). | [`an_appimage_for_another_processor_gets_no_sandbox`](crates/sam-runner/tests/wrong_processor.rs#L13) |

</details>

<details><summary><b>sam-storage</b> — App records, presets and logs on disk (8 tests)</summary>

| Kind | Promise | Test |
|---|---|---|
| unit | With more launches in one second than logs are kept, the newest log survives the pruning after its launch (regression: on a fast machine a pruned name was reused, sorted as the oldest and deleted at once). | [`the_newest_log_survives_pruning_within_one_second`](crates/sam-storage/src/lib.rs#L497) |
| unit | A record SAM saved loads as unchanged; a record changed afterwards by something else is recognized as changed outside SAM; a record from before the checksum existed still loads as unchanged; and saving it again through SAM makes it unchanged again. | [`records_changed_outside_sam_are_recognized`](crates/sam-storage/src/lib.rs#L513) |
| unit | A preset is always stored inside the presets folder, whatever its name: names like "../../evil" or "/etc/x" (typed, or from an imported file) cannot place a file elsewhere. | [`preset_names_cannot_place_files_outside_the_presets_folder`](crates/sam-storage/src/lib.rs#L538) |
| unit ⟲ | Regression (found in the test audit): a record changed outside SAM with an id like "../../.ssh" would have pointed the folders SAM deletes on removal (private home, logs) outside SAM's own folders. | [`records_with_unsafe_or_mismatched_ids_are_not_loaded`](crates/sam-storage/src/lib.rs#L556) |
| unit | The newest log is found even when two logs start within the same second. | [`the_newest_log_is_found_even_within_one_second`](crates/sam-storage/src/lib.rs#L569) |
| unit | Apps are found by name or ID, and an ambiguous name is refused. | [`apps_are_found_by_name_or_id_and_ambiguous_names_are_refused`](crates/sam-storage/src/lib.rs#L584) |
| unit | Presets in the older flat format still load. | [`presets_in_the_older_flat_format_still_load`](crates/sam-storage/src/lib.rs#L604) |
| unit | A saved preset loads back unchanged, found by its name in any letter case. | [`a_saved_preset_loads_back_unchanged`](crates/sam-storage/src/lib.rs#L631) |

</details>

<details><summary><b>sam-jail-cli</b> — The command line and its JSON interface (14 tests)</summary>

| Kind | Promise | Test |
|---|---|---|
| integration | The permission model is the base: it depends on no other SAM part, so every other part can use it without creating a cycle. | [`the_permission_model_depends_on_no_other_part`](crates/sam-jail-cli/tests/architecture.rs#L50) |
| integration | The window contains no sandbox logic: it depends only on the permission model and reaches everything else through `sam-jail --json`, so the window and the command line always behave the same. | [`the_window_reaches_sam_only_through_the_command_line`](crates/sam-jail-cli/tests/architecture.rs#L58) |
| integration | The parts that handle untrusted AppImage content or build the sandbox depend only on the parts below them, never on the operations layer, the command line or the window. | [`lower_parts_never_depend_on_higher_ones`](crates/sam-jail-cli/tests/architecture.rs#L66) |
| integration | The sandbox command builder depends only on the permission model, so what it builds follows from the permissions alone. | [`the_sandbox_builder_depends_only_on_the_permission_model`](crates/sam-jail-cli/tests/architecture.rs#L79) |
| integration | The component diagram in docs/architecture.md shows exactly the real dependencies between the parts: no arrow is missing and none is invented. | [`the_component_diagram_shows_the_real_dependencies`](crates/sam-jail-cli/tests/architecture.rs#L86) |
| integration | The JSON interface lists apps with their tags, changes a permission for several apps, and restores them with the returned "previous" object. | [`group_list_set_and_restore_round_trip`](crates/sam-jail-cli/tests/interface.rs#L56) |
| integration | A group change with an invalid value, an unknown key or no app is refused, and no app changes. | [`group_set_refuses_bad_input_without_changing_anything`](crates/sam-jail-cli/tests/interface.rs#L84) |
| integration | The command line lists only the user's own presets; the template is strict, and saved presets carry no built-in flag. | [`presets_are_the_users_own_only`](crates/sam-jail-cli/tests/interface.rs#L96) |
| integration ⟲ | Regression (found by the fuzzer): one damaged AppImage in a searched folder made `sam-jail discover` crash, so the window's list stayed empty. | [`one_damaged_appimage_does_not_stop_the_list`](crates/sam-jail-cli/tests/interface.rs#L115) |
| integration | Files from older SAM versions are migrated to the current format, and the originals are kept. | [`old_formats_are_migrated_and_kept`](crates/sam-jail-cli/tests/robustness.rs#L48) |
| integration | Files from a newer SAM are never changed by an older one. | [`newer_formats_are_left_untouched`](crates/sam-jail-cli/tests/robustness.rs#L70) |
| integration | Damaged files are moved aside and reported, and SAM carries on. | [`damaged_files_are_moved_aside_and_reported`](crates/sam-jail-cli/tests/robustness.rs#L95) |
| integration | Mangled files never make SAM crash. | [`mangled_files_never_crash`](crates/sam-jail-cli/tests/robustness.rs#L125) |
| integration | `sam-jail version` answers with the JSON interface version even when the configuration cannot be read. | [`version_reports_the_json_interface`](crates/sam-jail-cli/tests/robustness.rs#L154) |

</details>

<details><summary><b>sam-gtk</b> — The window (logic that runs without a display) (9 tests)</summary>

| Kind | Promise | Test |
|---|---|---|
| unit | The group switches offer only permissions and values SAM accepts (`sam-jail group set` would refuse anything else), and each value of a permission appears once. | [`group_switches_offer_only_valid_values`](crates/sam-gtk/src/all_perms.rs#L947) |
| unit | Shift-click selects every app between the app clicked before and the app clicked now, in either direction; without an earlier click, only the app clicked now. | [`shift_click_selects_the_apps_between_two_clicks`](crates/sam-gtk/src/all_perms.rs#L972) |
| unit | A tag filter cycles through three states with each click: only apps with the permission, only apps without it, and off. | [`a_tag_filter_cycles_through_has_has_not_and_off`](crates/sam-gtk/src/all_perms.rs#L984) |
| unit | The list shows an app only when it passes every filter at once: the search text, each state filter, and each tag filter in its state. | [`the_list_shows_only_apps_that_pass_every_filter`](crates/sam-gtk/src/all_perms.rs#L993) |
| unit | Personal folders explain where they are; other permissions keep their description unchanged. | [`folder_explanations_name_the_path`](crates/sam-gtk/src/all_perms.rs#L1011) |
| unit | The user guide keeps the text of a list item that has a nested list below it. | [`nested_items_keep_their_text`](crates/sam-gtk/src/guide.rs#L274) |
| unit ⟲ | Regression: the "startup" handler that loads SAM's style sheet was connected after `register()`, which emits "startup" for the first instance at once. | [`the_style_sheet_handler_is_connected_before_register`](crates/sam-gtk/src/main.rs#L428) |
| unit | Every color SAM's window uses has a style rule: the badge tones in the code, the three risk levels of tags and badges, and the outline. | [`every_color_in_use_has_a_style_rule`](crates/sam-gtk/src/main.rs#L439) |
| unit | The folder watcher reacts to AppImages and ignores hidden files and downloads in progress. | [`the_folder_watcher_ignores_hidden_files_and_unfinished_downloads`](crates/sam-gtk/src/window.rs#L1356) |

</details>

## Version reports

> **What you see:** every version report, newest first. A report is made at the end
> of each phase of work and before each published version; it compares the tests,
> the coverage, the speed and the dependencies with the report before.

| Report | Generated | Tests passing | Failing |
|---|---|---|---|
| [0.1.0-983638c](docs/reports/0.1.0-983638c.md) | 2026-11-15 07:20:42 | 218 | 0 |
| [0.1.0-53d8e50](docs/reports/0.1.0-53d8e50.md) | 2026-11-15 05:34:52 | 212 | 0 |
| [0.1.0-c20b843](docs/reports/0.1.0-c20b843.md) | 2026-11-15 00:08:58 | 201 | 0 |
| [0.1.0-26c4617](docs/reports/0.1.0-26c4617.md) | 2026-11-14 21:22:22 | 193 | 0 |
| [0.1.0-984380d](docs/reports/0.1.0-984380d.md) | 2026-11-14 20:56:07 | 190 | 0 |
| [0.1.0-36e9b42](docs/reports/0.1.0-36e9b42.md) | 2026-11-14 20:40:46 | 189 | 0 |

## Latest commits

> **What you see:** the 30 newest changes to SAM, newest first. Each commit message
> explains what changed and why; the hash links to the change on GitHub.

| Commit | Date | Change |
|---|---|---|
| [`983638c`](https://github.com/gitzekatze/SAM/commit/983638c) | 2026-11-15 | Repair: use the system's copy of a bundled library that is too old |
| [`dd5154e`](https://github.com/gitzekatze/SAM/commit/dd5154e) | 2026-11-15 | Release: test the finished AppImage on fresh systems; plain refusal on old ones |
| [`b078bd6`](https://github.com/gitzekatze/SAM/commit/b078bd6) | 2026-11-15 | License notices for the libraries built into SAM |
| [`ddc0628`](https://github.com/gitzekatze/SAM/commit/ddc0628) | 2026-11-15 | Intake: an AppImage for another processor gets no sandbox, with a clear reason |
| [`8d16cd3`](https://github.com/gitzekatze/SAM/commit/8d16cd3) | 2026-11-15 | Self-update: SAM replaces itself only with an update signed by its release key |
| [`802d8e1`](https://github.com/gitzekatze/SAM/commit/802d8e1) | 2026-11-15 | Version report at the end of Phase 6 |
| [`53d8e50`](https://github.com/gitzekatze/SAM/commit/53d8e50) | 2026-11-15 | New app icon (sam-icon 1.0) |
| [`7f41d40`](https://github.com/gitzekatze/SAM/commit/7f41d40) | 2026-11-15 | Repair: offer a writable app folder only where an overlay can work |
| [`584e0bd`](https://github.com/gitzekatze/SAM/commit/584e0bd) | 2026-11-15 | Diagnose: fewer false findings, and files in /etc are no longer added by themselves |
| [`fbe9729`](https://github.com/gitzekatze/SAM/commit/fbe9729) | 2026-11-15 | Sandbox: "localhost" resolves without the network on every distribution |
| [`456de89`](https://github.com/gitzekatze/SAM/commit/456de89) | 2026-11-15 | Logs: a launch's own log is never pruned right after the launch |
| [`11bdfba`](https://github.com/gitzekatze/SAM/commit/11bdfba) | 2026-11-15 | Writable app folder: test that an overlay really works, else start read-only |
| [`efd5298`](https://github.com/gitzekatze/SAM/commit/efd5298) | 2026-11-15 | CI (Fedora): lift the user-namespace restriction on the runner, then run Fedora |
| [`5430e1e`](https://github.com/gitzekatze/SAM/commit/5430e1e) | 2026-11-15 | Diagnose: no false findings for file changes, own folders or granted access |
| [`98f429a`](https://github.com/gitzekatze/SAM/commit/98f429a) | 2026-11-15 | CI (Fedora): install su (util-linux), which the container image lacks |
| [`a5b6da2`](https://github.com/gitzekatze/SAM/commit/a5b6da2) | 2026-11-15 | CI (Fedora): lift the runner kernel's user-namespace restriction |
| [`f2e16c7`](https://github.com/gitzekatze/SAM/commit/f2e16c7) | 2026-11-15 | CI: man page for repair --undo-step; Fedora job runs as an ordinary user |
| [`fa7fcfd`](https://github.com/gitzekatze/SAM/commit/fa7fcfd) | 2026-11-15 | Dashboard: summary at a glance, bars, a note on each section |
| [`2df2a41`](https://github.com/gitzekatze/SAM/commit/2df2a41) | 2026-11-15 | Development dashboard (DEVELOPMENT.md); harness: start time, memory, tray, portals, missing files |
| [`872f0bd`](https://github.com/gitzekatze/SAM/commit/872f0bd) | 2026-11-15 | Phase 6, part 1: full disk, clearer errors, real-app checks; CI fixes |
| [`42ee8c4`](https://github.com/gitzekatze/SAM/commit/42ee8c4) | 2026-11-15 | Version report at the end of Phase 5 (0.1.0, c20b843) |
| [`c20b843`](https://github.com/gitzekatze/SAM/commit/c20b843) | 2026-11-15 | Phase 5, part 3: fuzzing (and the crash it found), threat model, Fedora CI |
| [`f9b57fa`](https://github.com/gitzekatze/SAM/commit/f9b57fa) | 2026-11-14 | Phase 5, part 2: SAM notices settings changed outside SAM |
| [`0cd9acc`](https://github.com/gitzekatze/SAM/commit/0cd9acc) | 2026-11-14 | Phase 5, part 1: the evil-AppImage suite |
| [`0de9db0`](https://github.com/gitzekatze/SAM/commit/0de9db0) | 2026-11-14 | App page: trash button as high as Test and Launch |
| [`73745e5`](https://github.com/gitzekatze/SAM/commit/73745e5) | 2026-11-14 | Version report at the end of Phase 4 (0.1.0, 26c4617) |
| [`26c4617`](https://github.com/gitzekatze/SAM/commit/26c4617) | 2026-11-14 | Phase 4: clear decisions on the app page |
| [`2c249c1`](https://github.com/gitzekatze/SAM/commit/2c249c1) | 2026-11-14 | Version report at the end of Phase 3 (0.1.0, 984380d) |
| [`984380d`](https://github.com/gitzekatze/SAM/commit/984380d) | 2026-11-14 | Benchmarks: warm-up run, more runs, compare the fastest run |
| [`97bb2cf`](https://github.com/gitzekatze/SAM/commit/97bb2cf) | 2026-11-14 | Phase 3: a calmer main window |

The full history is at [https://github.com/gitzekatze/SAM/commits/main](https://github.com/gitzekatze/SAM/commits/main).
