# SAM's functions and their proofs

> **What this page is:** every function SAM promises, with the tests that
> prove it, the code that carries it, and the scripted checks that try it on
> real apps or in the window. A test may prove several functions. The page
> is generated from [functions.toml](functions.toml) by
> `scripts/function-map.py`; CI checks that every test belongs to a function
> and every function has a test or a stated gap.
>
> Test results are from the newest version report (2026-11-15 17:32:32).

**40 functions:** 16 proven by passing tests, 23 with new tests not yet in a report, 0 with a failing test, 1 by scripted checks, 0 with a gap, 308 tests in all.

| | Function | Components | Tests | Result |
|---|---|---|---|---|
| 1 | [SAM finds AppImages in the folders you choose and shows them, sandboxed or not, without running anything.](#1) | sam-gtk, sam-runner, sam-intake | 5 | ✅ |
| 2 | [SAM recognizes the AppImage formats in use today (type 2 with a SquashFS or DwarFS image; the old, rare type 1 is unpacked with bsdtar but not tested) and refuses files that aren't AppImages, or are for the wrong processor, with a clear message.](#2) | sam-runner, sam-intake, sam-detect | 9 | ✅ 🆕 2 new tests since the report |
| 3 | [SAM unpacks an AppImage safely: without running it, inside a sandbox, with limits on size, number of files and time, and with a check of free disk space.](#3) | sam-runner, sam-intake | 19 | ✅ 🆕 6 new tests since the report |
| 4 | [SAM reads the name, icon, description and update source from the app itself, and removes markup or control characters before showing them.](#4) | sam-intake, sam-core | 6 | ✅ |
| 5 | [A damaged or hostile AppImage can't crash SAM or stop the list.](#5) | sam-intake, sam-detect | 7 | ✅ 🆕 1 new test since the report |
| 6 | [SAM recommends permissions from what the app is (window app, terminal tool, game, browser and so on), starting as strict as possible.](#6) | sam-detect, sam-profile | 16 | ✅ 🆕 1 new test since the report |
| 7 | [SAM explains every permission in plain language and shows how risky it is.](#7) | sam-gtk, sam-core | 10 | ✅ 🆕 2 new tests since the report |
| 8 | [You can change permissions per app, for several apps at once, or through your own presets.](#8) | sam-runner, sam-profile, sam-storage, sam-core | 18 | ✅ |
| 9 | [Things an app printed can never grant it access on their own; SAM always asks.](#9) | sam-runner | 2 | ✅ 🆕 1 new test since the report |
| 10 | [The app sees only a private home folder and the folders you grant.](#10) | sam-sandbox | 9 | ✅ 🆕 2 new tests since the report |
| 11 | [Keys, passwords and the files of your other apps stay hidden, even with full home access.](#11) | sam-sandbox, sam-core | 8 | ✅ 🆕 2 new tests since the report |
| 12 | [Network: none, "This computer only" (selected ports), or full.](#12) | sam-runner, sam-sandbox | 5 | ✅ 🆕 2 new tests since the report |
| 13 | [The app reaches only allowed desktop services (a filtered D-Bus) and can't start programs outside its sandbox.](#13) | sam-runner, sam-sandbox, sam-core | 15 | ✅ 🆕 3 new tests since the report |
| 14 | [Display: Wayland with a security context; X11 only when allowed, with its cost explained.](#14) | sam-runner, sam-sandbox, sam-core | 3 | ✅ |
| 15 | [Sound, GPU, camera and game controllers only when allowed.](#15) | sam-sandbox | 4 | ✅ |
| 16 | [The app can't make itself start later outside the sandbox (autostart, shell startup files, menu entries).](#16) | sam-runner, sam-sandbox | 8 | ✅ 🆕 5 new tests since the report |
| 17 | [The app can't type into your terminal.](#17) | sam-runner, sam-sandbox | 15 | ✅ 🆕 4 new tests since the report |
| 18 | [Optional: a writable app folder (changes go to a separate layer); where that's impossible, a read-only start with an explanation.](#18) | sam-runner, sam-sandbox, sam-core | 4 | ✅ |
| 19 | [Starting from SAM's window, from the menu, or from the terminal always goes through the sandbox.](#19) | sam-runner, sam-intake, sam-core | 10 | ✅ |
| 20 | [SAM checks from inside the sandbox that every setting applies (the sandbox check).](#20) | sam-runner | 10 | ✅ 🆕 8 new tests since the report |
| 21 | [A second start, closing, and stopping work cleanly and leave nothing behind.](#21) | sam-runner, sam-core | 6 | ✅ 🆕 2 new tests since the report |
| 22 | [Logs of every start are kept, with old ones removed automatically.](#22) | sam-runner, sam-storage | 3 | ✅ 🆕 1 new test since the report |
| 23 | [After a failed start, SAM says what went wrong and offers a fix with one click.](#23) | sam-gtk, sam-runner | 6 | ✅ |
| 24 | [Repair steps go from mild to strong, and each one can be undone.](#24) | sam-runner, sam-sandbox | 7 | ✅ |
| 25 | [The diagnose run finds missing files and suggests only what helps.](#25) | sam-runner | 9 | ✅ 🆕 1 new test since the report |
| 26 | [Compatibility mode as a last resort, with its cost explained, and it can be undone.](#26) | sam-runner | 2 | ✅ |
| 27 | [SAM notices app settings that something else changed and asks before starting the app.](#27) | sam-runner, sam-storage | 2 | ✅ |
| 28 | [Updates use HTTPS only, keep the old version so it can be restored, and refuse a changed signing key until you accept it.](#28) | sam-runner, sam-detect | 21 | ✅ 🆕 3 new tests since the report |
| 29 | [SAM notices AppImages that were moved or changed.](#29) | sam-runner, sam-intake | 4 | ✅ 🆕 2 new tests since the report |
| 30 | [Removing an app deletes only SAM's own folders, never your files.](#30) | sam-runner, sam-storage, sam-core | 6 | ✅ |
| 31 | [Disk space per app, and freeing space.](#31) | sam-runner | 1 | ✅ |
| 32 | [Uninstalling SAM removes everything it created and brings back menu entries it hid.](#32) | sam-runner, sam-intake | 2 | ✅ |
| 33 | [The doctor check finds problems with the system or an app.](#33) | sam-runner, sam-core | 11 | ✅ 🆕 5 new tests since the report |
| 34 | [Privacy: SAM sends nothing on its own, and a bug report never contains your name, home path, addresses or secrets.](#34) | sam-runner | 6 | ✅ 🆕 5 new tests since the report |
| 35 | [The overview of all apps, with clear status badges.](#35) | sam-gtk, sam-storage, sam-core | 5 | ✅ |
| 36 | [The Permission Manager, for one app or several, with tags in the same colors everywhere.](#36) | sam-gtk, sam-profile | 12 | ✅ 🆕 1 new test since the report |
| 37 | [SAM speaks English, German, Spanish and French: every text in the window and every message from SAM's core. You can choose SAM's language in the main menu; apps keep the system's.](#37) | sam-gtk, sam-core | 6 | ✅ 🆕 4 new tests since the report |
| 40 | [The window can be used with the keyboard alone and with a screen reader: every control has a name it can say and takes keyboard focus.](#40) | sam-gtk | 0 | scripted check |
| 38 | [SAM's own files survive: files from older versions are migrated, files from newer versions stay untouched, and damaged files are moved aside without stopping SAM.](#38) | sam-storage, sam-core | 12 | ✅ |
| 39 | [SAM's parts stay cleanly separated: the window reaches the core only through the command line and decides by codes, never by reading messages, and the parts that handle untrusted content never depend on the higher ones.](#39) | sam-jail-cli | 16 | ✅ 🆕 8 new tests since the report |

## Components and their functions

The components are those of the [architecture](architecture.md#level-3-components) (C4 level 3).

| Component | Functions it carries |
|---|---|
| sam-gtk | [1](#1), [7](#7), [23](#23), [35](#35), [36](#36), [37](#37), [40](#40) |
| sam-jail-cli | [39](#39) |
| sam-runner | [1](#1), [2](#2), [3](#3), [8](#8), [9](#9), [12](#12), [13](#13), [14](#14), [16](#16), [17](#17), [18](#18), [19](#19), [20](#20), [21](#21), [22](#22), [23](#23), [24](#24), [25](#25), [26](#26), [27](#27), [28](#28), [29](#29), [30](#30), [31](#31), [32](#32), [33](#33), [34](#34) |
| sam-intake | [1](#1), [2](#2), [3](#3), [4](#4), [5](#5), [19](#19), [29](#29), [32](#32) |
| sam-detect | [2](#2), [5](#5), [6](#6), [28](#28) |
| sam-profile | [6](#6), [8](#8), [36](#36) |
| sam-sandbox | [10](#10), [11](#11), [12](#12), [13](#13), [14](#14), [15](#15), [16](#16), [17](#17), [18](#18), [24](#24) |
| sam-storage | [8](#8), [22](#22), [27](#27), [30](#30), [35](#35), [38](#38) |
| sam-core | [4](#4), [7](#7), [8](#8), [11](#11), [13](#13), [14](#14), [18](#18), [19](#19), [21](#21), [30](#30), [33](#33), [35](#35), [37](#37), [38](#38) |

## A. Bringing an AppImage in

<a id="1"></a>
### 1. SAM finds AppImages in the folders you choose and shows them, sandboxed or not, without running anything.

| Test | Promise | Result |
|---|---|---|
| [`peeks_name_and_icon_without_extracting`](../crates/sam-intake/src/peek.rs#L157) | The name and icon of an AppImage are read without unpacking or running it. | ✅ |
| [`the_appimage_behind_a_foreign_menu_entry_is_found`](../crates/sam-intake/src/menu.rs#L295) | The AppImage a foreign menu entry starts is found in its Exec line, also behind env and with quotes. | ✅ |
| [`app_ids_stay_unique_when_names_collide`](../crates/sam-intake/src/id.rs#L98) | App IDs are stable and unique, also when two AppImages have the same name. | ✅ |
| [`found_appimages_get_a_menu_entry_only_with_a_sandbox`](../crates/sam-runner/tests/overview.rs#L13) | AppImages are listed before they have a sandbox; only creating the sandbox adds SAM's menu entry and hides unsandboxed ones, and removing it puts them back. | ✅ |
| [`the_folder_watcher_ignores_hidden_files_and_unfinished_downloads`](../crates/sam-gtk/src/window.rs#L1865) | The folder watcher reacts to AppImages and ignores hidden files and downloads in progress. | ✅ |

**Code:** [`sam-intake/src/peek.rs`](../crates/sam-intake/src/peek.rs), [`sam-intake/src/menu.rs`](../crates/sam-intake/src/menu.rs), [`sam-intake/src/id.rs`](../crates/sam-intake/src/id.rs), [`sam-runner/src/ops/overview.rs`](../crates/sam-runner/src/ops/overview.rs), [`sam-gtk/src/window.rs`](../crates/sam-gtk/src/window.rs)

<a id="2"></a>
### 2. SAM recognizes the AppImage formats in use today (type 2 with a SquashFS or DwarFS image; the old, rare type 1 is unpacked with bsdtar but not tested) and refuses files that aren't AppImages, or are for the wrong processor, with a clear message.

| Test | Promise | Result |
|---|---|---|
| [`plain_elf_is_not_appimage`](../crates/sam-detect/src/appimage.rs#L328) | An ordinary program file is not taken for an AppImage. | ✅ |
| [`a_type_2_appimage_is_recognized`](../crates/sam-detect/src/appimage.rs#L336) | A type 2 AppImage (ELF with the AppImage magic and a squashfs image) is recognized. | ✅ |
| [`an_appimage_with_a_dwarfs_image_is_recognized`](../crates/sam-detect/src/appimage.rs#L401) | An AppImage with a DwarFS image instead of squashfs is recognized. | ✅ |
| [`a_file_that_is_no_program_is_not_an_appimage`](../crates/sam-detect/src/appimage.rs#L422) | A file that is not an ELF program is not taken for an AppImage. | ✅ |
| [`appimages_run_only_on_a_matching_processor`](../crates/sam-detect/src/appimage.rs#L437) | An AppImage runs on the same processor and 32-bit builds on their 64-bit relatives; ARM builds never run on x86-64 or the other way. | ✅ |
| [`appimages_with_every_compression_unpack`](../crates/sam-intake/src/testkit.rs#L237) | Every SquashFS compression AppImages use is unpacked by the built-in reader, so none needs the AppImage's own extractor. | ✅ |
| [`an_appimage_for_another_processor_gets_no_sandbox`](../crates/sam-runner/tests/wrong_processor.rs#L14) | An AppImage for ARM is refused on an x86-64 computer with a sentence that names both processors and what to download instead, and nothing is stored (regression: SAM created a sandbox for an arm64 Neovim and failed only at the start, with "permission denied or wrong format"). | ✅ |
| [`an_appimage_shorter_than_its_image_is_incomplete`](../crates/sam-detect/src/appimage.rs#L364) | A download that broke off is recognized: the file is shorter than its SquashFS image says, and a complete one is not. | 🆕 new |
| [`a_download_that_broke_off_is_refused_and_nothing_is_kept`](../crates/sam-runner/tests/incomplete.rs#L9) | A download that broke off is refused and nothing is kept. | 🆕 new |

**Code:** [`sam-detect/src/appimage.rs`](../crates/sam-detect/src/appimage.rs), [`sam-intake/src/extract.rs`](../crates/sam-intake/src/extract.rs), [`sam-runner/src/ops/add.rs`](../crates/sam-runner/src/ops/add.rs)

**Also tried by:** [`tests/real-apps/run.sh`](../tests/real-apps/run.sh)

<a id="3"></a>
### 3. SAM unpacks an AppImage safely: without running it, inside a sandbox, with limits on size, number of files and time, and with a check of free disk space.

| Test | Promise | Result |
|---|---|---|
| [`unpacking_refuses_to_start_without_enough_free_space`](../crates/sam-intake/src/extract.rs#L790) | Unpacking does not start when the folder clearly has too little room; the message names the folder, both sizes, and where to choose another folder. | ✅ |
| [`a_full_disk_during_unpacking_is_recognized`](../crates/sam-intake/src/extract.rs#L821) | A full disk during unpacking is recognized, also inside an error chain, so SAM can clean up and say what happened. | ✅ |
| [`unpacking_stops_at_the_time_limit`](../crates/sam-intake/src/normalize.rs#L215) | Unpacking stops with a clear error when it takes longer than the time limit, so a huge or hostile AppImage cannot keep SAM busy forever. | ✅ |
| [`symlinks_pointing_outside_the_app_are_recognized`](../crates/sam-intake/src/normalize.rs#L229) | A symlink that points outside the unpacked app is recognized. | ✅ |
| [`paths_climbing_out_of_the_image_are_refused`](../crates/sam-intake/src/normalize.rs#L242) | Paths from the AppImage image are made relative, and paths that climb out with .. | ✅ |
| [`unpacking_removes_setuid_bits`](../crates/sam-intake/src/normalize.rs#L253) | Unpacking removes setuid bits and makes files read-only for others. | ✅ |
| [`unpacking_stops_at_the_file_limit`](../crates/sam-intake/src/normalize.rs#L310) | Unpacking stops when the AppImage contains more files than the limit. | ✅ |
| [`a_built_appimage_is_detected_and_unpacked_safely`](../crates/sam-intake/src/testkit.rs#L268) | A built AppImage is recognized and unpacked, with setuid bits removed. | ✅ |
| [`size_limit_aborts_and_cleans_up`](../crates/sam-intake/src/testkit.rs#L327) | Unpacking stops at the size limit and leaves no partial files behind. | ✅ |
| [`fractions_follow_the_step_weights`](../crates/sam-runner/src/progress.rs#L152) | The progress bar follows the weights of the steps of creating a sandbox. | ✅ |
| [`bytes_written_are_counted`](../crates/sam-runner/src/progress.rs#L177) | Unpacking progress counts the bytes written. | ✅ |
| [`unpacking_stops_exactly_at_its_limits`](../crates/sam-intake/tests/limits.rs#L45) | The file-count and size limits let an app through that reaches them exactly and stop one entry or one byte more; a time limit of zero stops at once. | ✅ |
| [`only_an_exceeded_limit_counts_as_one`](../crates/sam-intake/src/extract.rs#L831) | Only an exceeded limit counts as one: other errors are not explained as a limit the user could raise. | ✅ |
| [`without_consent_the_appimages_own_unpacker_never_runs`](../crates/sam-intake/tests/damaged.rs#L25) | When SAM's own readers cannot unpack an AppImage, its own unpacker (code from the AppImage) runs only after the user agreed: without consent the unpacking stops and asks, and nothing of the AppImage runs. | 🆕 new |
| [`a_menu_start_after_free_space_unpacks_inside_a_sandbox`](../crates/sam-jail-cli/tests/unpack.rs#L87) | A menu start after free space unpacks inside a sandbox. | 🆕 new |
| [`without_the_command_line_a_menu_start_refuses_to_unpack`](../crates/sam-jail-cli/tests/unpack.rs#L110) | Without the command line a menu start refuses to unpack. | 🆕 new |
| [`sams_programs_never_unpack_without_a_sandbox`](../crates/sam-runner/src/ops/overview.rs#L474) | Sams programs never unpack without a sandbox. | 🆕 new |
| [`a_menu_start_unpacks_in_a_sandbox_with_the_cli_next_to_it`](../crates/sam-runner/src/ops/overview.rs#L462) | A menu start unpacks in a sandbox with the cli next to it. | 🆕 new |
| [`tests_and_benchmarks_may_unpack_in_their_own_process`](../crates/sam-runner/src/ops/overview.rs#L495) | Tests and benchmarks may unpack in their own process. | 🆕 new |

**Code:** [`sam-intake/src/extract.rs`](../crates/sam-intake/src/extract.rs), [`sam-intake/src/normalize.rs`](../crates/sam-intake/src/normalize.rs), [`sam-runner/src/progress.rs`](../crates/sam-runner/src/progress.rs)

<a id="4"></a>
### 4. SAM reads the name, icon, description and update source from the app itself, and removes markup or control characters before showing them.

| Test | Promise | Result |
|---|---|---|
| [`the_desktop_file_inside_an_appimage_is_read`](../crates/sam-intake/src/metadata.rs#L261) | The desktop file inside an AppImage is read with name, translations, categories and file types. | ✅ |
| [`reads_metadata_and_icon`](../crates/sam-intake/src/metadata.rs#L274) | Name, icon and categories are read from the unpacked app. | ✅ |
| [`a_readable_name_is_taken_from_the_file_name`](../crates/sam-intake/src/id.rs#L81) | A readable name is taken from an AppImage's file name, without version and architecture. | ✅ |
| [`icon_paths_cannot_climb_out_of_the_app`](../crates/sam-intake/src/peek.rs#L171) | Icon paths from the AppImage cannot climb out of the unpacked app. | ✅ |
| [`neutralizes_markup_and_controls`](../crates/sam-core/src/util.rs#L330) | Text from an app is shown without markup or control characters, and long text is shortened. | ✅ |
| [`markup_in_metadata_is_neutralized`](../crates/sam-runner/tests/adversarial.rs#L95) | H3: markup in an AppImage's name or comment is neutralized before it is stored or shown. | ✅ |

**Code:** [`sam-intake/src/metadata.rs`](../crates/sam-intake/src/metadata.rs), [`sam-intake/src/peek.rs`](../crates/sam-intake/src/peek.rs), [`sam-intake/src/id.rs`](../crates/sam-intake/src/id.rs), [`sam-core/src/util.rs`](../crates/sam-core/src/util.rs)

<a id="5"></a>
### 5. A damaged or hostile AppImage can't crash SAM or stop the list.

| Test | Promise | Result |
|---|---|---|
| [`reading_a_file_of_an_appimage_is_bounded`](../crates/sam-core/src/util.rs#L296) | A link to a device that never ends, or a file larger than the limit, cannot fill SAM's memory (regression: an AppImage whose AppRun links to /dev/zero made adding it grow without end). | 🆕 new |
| [`a_damaged_squashfs_image_gives_an_error_instead_of_a_crash`](../crates/sam-intake/tests/damaged.rs#L15) ⟲ | Regression: reading the name and icon of an AppImage whose SquashFS image makes the reader panic gives an error instead of crashing SAM. | ✅ |
| [`parsers_survive_garbage`](../crates/sam-runner/tests/adversarial.rs#L132) | Robustness: malformed desktop files and files that only look like AppImages must not crash the parsers (simple deterministic fuzzing). | ✅ |
| [`changed_appimages_never_crash_or_escape_the_unpacker`](../crates/sam-runner/tests/fuzz.rs#L141) | Changed AppImages are recognized or refused, and unpacked or refused, without a panic; unpacking writes only inside its own folder and keeps its time limit. | ✅ |
| [`changed_text_inputs_never_crash_the_parsers`](../crates/sam-runner/tests/fuzz.rs#L223) | Changed desktop files, zsync files and update information are parsed or refused without a panic. | ✅ |
| [`changed_programs_never_crash_the_analysis`](../crates/sam-runner/tests/fuzz.rs#L255) | Changed ELF programs inside an unpacked app are analyzed or skipped without a panic. | ✅ |
| [`one_damaged_appimage_does_not_stop_the_list`](../crates/sam-jail-cli/tests/interface.rs#L187) ⟲ | Regression (found by the fuzzer): one damaged AppImage in a searched folder made `sam-jail discover` crash, so the window's list stayed empty. | ✅ |

**Code:** [`sam-intake/src/peek.rs`](../crates/sam-intake/src/peek.rs), [`sam-intake/src/extract.rs`](../crates/sam-intake/src/extract.rs), [`sam-detect/src/elf.rs`](../crates/sam-detect/src/elf.rs)

## B. Choosing the right permissions

<a id="6"></a>
### 6. SAM recommends permissions from what the app is (window app, terminal tool, game, browser and so on), starting as strict as possible.

| Test | Promise | Result |
|---|---|---|
| [`a_development_tool_gets_no_project_folder_on_its_own_word`](../crates/sam-profile/src/lib.rs#L761) | An app that calls itself a development tool gets Documents, but no writable project folder: the category is the AppImage's own claim, and a project folder lets an app plant code that runs outside the sandbox (git hooks, .envrc). | 🆕 new |
| [`terminal_programs_get_no_display`](../crates/sam-profile/src/lib.rs#L734) | Terminal programs get no display, GPU or desktop bus access. | ✅ |
| [`the_app_category_is_recognized_from_its_desktop_categories`](../crates/sam-profile/src/lib.rs#L791) | The category of an app is recognized from its desktop categories. | ✅ |
| [`recommendations_fit_the_category`](../crates/sam-profile/src/lib.rs#L856) | Recommended permissions fit the category: a browser gets the network and Downloads, an editor no network. | ✅ |
| [`what_sam_finds_in_the_app_adjusts_the_recommendation`](../crates/sam-profile/src/lib.rs#L871) | What SAM finds in the app (GPU, X11-only toolkit) adjusts the recommendation. | ✅ |
| [`bundled_libraries_are_sorted_by_what_they_reach`](../crates/sam-detect/src/classify.rs#L262) | Bundled libraries are sorted into system, graphics, display-controlled and dangerous classes. | ✅ |
| [`programs_that_load_graphics_at_run_time`](../crates/sam-detect/src/elf.rs#L1223) | Programs that load graphics libraries only at run time are recognized as needing the GPU. | ✅ |
| [`missing_optional_libraries_name_the_feature`](../crates/sam-detect/src/elf.rs#L1249) | A missing optional library is reported with the feature it provides, not as a broken app. | ✅ |
| [`programs_that_choose_the_qt_platform`](../crates/sam-detect/src/elf.rs#L1336) | Programs that choose the Qt platform themselves (X11 or Wayland) are recognized. | ✅ |
| [`qt_wayland_plugin_needs_its_client_library`](../crates/sam-detect/src/elf.rs#L1357) | A bundled Qt Wayland plugin counts as usable only when its Wayland client library is present. | ✅ |
| [`start_scripts_that_force_x11`](../crates/sam-detect/src/elf.rs#L1371) | Start scripts that force X11 are recognized, so SAM grants X11 to those apps. | ✅ |
| [`the_program_behind_a_start_script_is_found`](../crates/sam-detect/src/elf.rs#L1441) | When the AppImage starts through a shell script, SAM finds the program the script starts. | ✅ |
| [`an_appimage_asking_for_admin_rights_is_unsafe_to_sandbox`](../crates/sam-detect/src/elf.rs#L1463) | An AppImage that asks for administrator rights (pkexec) is marked as unsafe to sandbox. | ✅ |
| [`electron_markers_and_bundled_symlinks`](../crates/sam-detect/src/elf.rs#L1471) | Electron apps are recognized by their markers, and bundled library symlinks are followed. | ✅ |
| [`origin_relative_needed_paths`](../crates/sam-detect/src/elf.rs#L1484) | Libraries an app finds relative to its own folder ($ORIGIN) are counted as bundled, not as missing. | ✅ |
| [`the_c_library_version_an_app_needs_is_read`](../crates/sam-detect/src/elf.rs#L1500) | The C library version an app needs is read from its symbol versions. | ✅ |

**Code:** [`sam-profile/src/lib.rs`](../crates/sam-profile/src/lib.rs), [`sam-detect/src/elf.rs`](../crates/sam-detect/src/elf.rs), [`sam-detect/src/classify.rs`](../crates/sam-detect/src/classify.rs)

**Also tried by:** [`tests/real-apps/run.sh`](../tests/real-apps/run.sh)

<a id="7"></a>
### 7. SAM explains every permission in plain language and shows how risky it is.

| Test | Promise | Result |
|---|---|---|
| [`the_strictest_window_profile_is_low_risk`](../crates/sam-core/src/risk.rs#L553) | The strictest window profile is low risk. | ✅ |
| [`full_home_is_dangerous`](../crates/sam-core/src/risk.rs#L560) | Full home access counts as dangerous, and as think twice when it is read-only. | ✅ |
| [`network_and_x11_high`](../crates/sam-core/src/risk.rs#L570) | Full network together with X11 makes the settings think twice (high risk). | ✅ |
| [`each_dangerous_setting_produces_its_warning`](../crates/sam-core/src/warnings.rs#L303) | Dangerous settings (X11, full home, system bus, network an app does not need) each produce a warning. | ✅ |
| [`strict_has_no_danger`](../crates/sam-core/src/warnings.rs#L325) | SAM's strictest window profile produces no danger warning. | ✅ |
| [`x11_warning_can_be_disabled`](../crates/sam-core/src/warnings.rs#L332) | The X11 warning disappears when the user turns it off in the preferences. | ✅ |
| [`tags_and_the_risk_list_use_the_same_words`](../crates/sam-profile/src/tags.rs#L262) | One name per permission: where the risk list names a permission that also has a tag, both use the same words (regression: "Audio" vs "Sound", "GPU" vs "GPU acceleration", "Show in folder"). | ✅ |
| [`folder_explanations_name_the_path`](../crates/sam-gtk/src/all_perms.rs#L1429) | Personal folders explain where they are; other permissions keep their description unchanged. | ✅ |
| [`risk_has_the_same_three_words_everywhere`](../crates/sam-core/src/risk.rs#L530) | SAM's strictest window profile counts as low risk. | 🆕 new |
| [`the_full_session_bus_is_rated_dangerous`](../crates/sam-core/src/risk.rs#L542) | The full session bus reaches systemd, which can start programs outside the sandbox, so it is rated like allowing systemd by name. | 🆕 new |

**Code:** [`sam-core/src/permissions.rs`](../crates/sam-core/src/permissions.rs), [`sam-core/src/risk.rs`](../crates/sam-core/src/risk.rs), [`sam-core/src/warnings.rs`](../crates/sam-core/src/warnings.rs), [`sam-gtk/src/all_perms.rs`](../crates/sam-gtk/src/all_perms.rs)

<a id="8"></a>
### 8. You can change permissions per app, for several apps at once, or through your own presets.

| Test | Promise | Result |
|---|---|---|
| [`set_and_get_keys`](../crates/sam-core/src/permissions.rs#L1071) | Permissions can be read and set by key, and unknown keys or values are refused. | ✅ |
| [`change_check_flags_removals_and_additions`](../crates/sam-profile/src/lib.rs#L889) | The change check names what an app would lose that it needs, and the dangerous access it would gain. | ✅ |
| [`folders_are_not_breakage_but_lost_local_network_and_bus_are`](../crates/sam-profile/src/lib.rs#L927) | A hidden folder is not a reason to warn that an app stops working: it is listed apart (regression for the group warning, which only interrupts for breakage). | ✅ |
| [`lost_sound_is_named_sound`](../crates/sam-profile/src/lib.rs#L957) | An app that needs sound is warned about in the switch's word. | ✅ |
| [`preset_template_is_strict`](../crates/sam-profile/src/lib.rs#L975) | A new preset starts without home, network or system bus access. | ✅ |
| [`user_changes_survive_better_recommendation`](../crates/sam-runner/src/ops/mod.rs#L466) | When SAM's recommendation improves, the user's own changes are kept. | ✅ |
| [`a_dry_run_changes_nothing_and_names_what_would_stop_working`](../crates/sam-runner/tests/groups.rs#L56) | A dry run of a group change saves nothing and names what each app would lose. | ✅ |
| [`only_changed_apps_are_saved_and_one_undo_restores_all_of_them`](../crates/sam-runner/tests/groups.rs#L82) | A group change saves only the apps whose value changes, and one undo restores all of them. | ✅ |
| [`an_invalid_value_or_unknown_app_changes_no_app`](../crates/sam-runner/tests/groups.rs#L113) | A group change with an invalid value or an unknown app changes no app. | ✅ |
| [`sam_ships_no_presets_and_old_built_in_names_are_free_for_the_user`](../crates/sam-runner/tests/groups.rs#L152) | SAM ships no presets; old built-in names are free for the user, and applying a preset asks before it removes something an app needs. | ✅ |
| [`saving_an_apps_settings_as_a_preset_keeps_them_exactly`](../crates/sam-runner/tests/groups.rs#L188) | Saving an app's settings as a preset keeps them exactly. | ✅ |
| [`reset_to_recommendation_brings_back_the_recommended_settings`](../crates/sam-runner/tests/settings.rs#L83) | "Reset to recommendation" brings back SAM's recommended settings and turns compatibility mode off. | ✅ |
| [`preset_names_cannot_place_files_outside_the_presets_folder`](../crates/sam-storage/src/lib.rs#L656) | A preset is always stored inside the presets folder, whatever its name: names like "../../evil" or "/etc/x" (typed, or from an imported file) cannot place a file elsewhere. | ✅ |
| [`a_saved_preset_loads_back_unchanged`](../crates/sam-storage/src/lib.rs#L795) | A saved preset loads back unchanged, found by its name in any letter case. | ✅ |
| [`group_list_set_and_restore_round_trip`](../crates/sam-jail-cli/tests/interface.rs#L79) | The JSON interface lists apps with their tags, changes a permission for several apps, and restores them with the returned "previous" object. | ✅ |
| [`group_set_refuses_bad_input_without_changing_anything`](../crates/sam-jail-cli/tests/interface.rs#L134) | A group change with an invalid value, an unknown key or no app is refused, and no app changes. | ✅ |
| [`presets_are_the_users_own_only`](../crates/sam-jail-cli/tests/interface.rs#L157) | The command line lists only the user's own presets; the template is strict, and saved presets carry no built-in flag. | ✅ |
| [`each_permission_adds_exactly_its_part_to_the_command`](../crates/sam-sandbox/src/lib.rs#L2097) | Each granted permission adds exactly its part to the Bubblewrap command. | ✅ |

**Code:** [`sam-core/src/permissions.rs`](../crates/sam-core/src/permissions.rs), [`sam-profile/src/lib.rs`](../crates/sam-profile/src/lib.rs), [`sam-runner/src/ops/profiles.rs`](../crates/sam-runner/src/ops/profiles.rs), [`sam-storage/src/lib.rs`](../crates/sam-storage/src/lib.rs)

**Also tried by:** [`tests/gui/permissions-atspi.sh`](../tests/gui/permissions-atspi.sh)

<a id="9"></a>
### 9. Things an app printed can never grant it access on their own; SAM always asks.

| Test | Promise | Result |
|---|---|---|
| [`app_output_cannot_buy_dangerous_grants`](../crates/sam-runner/tests/adversarial.rs#L74) | H2/M4: suggestions derived from app output never grant escape-capable services or protected folders, and are always marked as app-derived. | ✅ |
| [`a_forged_trace_line_cannot_widen_a_low_risk_grant`](../crates/sam-runner/src/diagnose.rs#L528) | A forged trace line cannot widen a low-risk grant: paths with ".." are ignored, and a grant is only ever a real folder of shared system data, never a parent such as /usr. | 🆕 new |

**Code:** [`sam-runner/src/repair.rs`](../crates/sam-runner/src/repair.rs)

## C. The sandbox

<a id="10"></a>
### 10. The app sees only a private home folder and the folders you grant.

| Test | Promise | Result |
|---|---|---|
| [`a_writable_folder_stays_writable_in_a_read_only_home`](../crates/sam-sandbox/src/lib.rs#L1832) | With the home read-only, a folder set to read/write stays writable; one set to read-only adds nothing (the home shows it read-only). | 🆕 new |
| [`the_strictest_profile_shares_nothing_and_keeps_the_app_read_only`](../crates/sam-sandbox/src/lib.rs#L1990) | The strictest profile builds a sandbox without network, environment or capabilities, with the app read-only. | ✅ |
| [`files_and_folders_named_on_the_command_line`](../crates/sam-sandbox/src/lib.rs#L1914) | Files and folders named when starting an app are passed in, but never sensitive folders like autostart. | ✅ |
| [`the_loaders_extra_library_folders_are_shown_read_only`](../crates/sam-sandbox/src/lib.rs#L1874) | Extra library folders of the system loader (for example CUDA) are visible to the app read-only. | ✅ |
| [`each_permission_adds_exactly_its_part_to_the_command`](../crates/sam-sandbox/src/lib.rs#L2097) | Each granted permission adds exactly its part to the Bubblewrap command. | ✅ |
| [`a_real_sandbox_shows_exactly_what_each_profile_allows`](../crates/sam-runner/tests/sandbox.rs#L63) | Inside a real sandbox, each profile shows exactly the files and services it allows. | ✅ |
| [`each_permission_grants_exactly_its_access_in_a_real_sandbox`](../crates/sam-runner/tests/matrix.rs#L101) | Inside a real sandbox, each permission grants exactly its access and nothing more. | ✅ |
| [`only_proper_variable_names_are_set`](../crates/sam-sandbox/src/lib.rs#L2659) | Only proper variable names are set inside the sandbox, and no value with a NUL byte. | ✅ |
| [`user_folders_come_from_user_dirs_dirs`](../crates/sam-core/src/host.rs#L689) | The user folders come from user-dirs.dirs, with the usual names as fallbacks; a folder set to $HOME is disabled (contract xdg-folders). | 🆕 new |

**Code:** [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs)

<a id="11"></a>
### 11. Keys, passwords and the files of your other apps stay hidden, even with full home access.

| Test | Promise | Result |
|---|---|---|
| [`sams_own_folders_stay_hidden_inside_an_opened_folder`](../crates/sam-sandbox/src/lib.rs#L2547) | SAM's own folders stay hidden inside a folder opened with the app, and inside a runner's bind, at the path the bind shows them under. | 🆕 new |
| [`key_and_system_folders_count_as_sensitive`](../crates/sam-core/src/risk.rs#L581) | Paths that hold keys or the whole system (~/.ssh, /etc, /) are recognized as sensitive; ordinary folders are not. | ✅ |
| [`every_breakout_attempt_from_a_real_sandbox_fails`](../crates/sam-runner/tests/breakout.rs#L152) | Every security promise holds inside a real sandbox: each breakout attempt fails. | ✅ |
| [`every_hostile_appimage_fails_to_escape`](../crates/sam-runner/tests/evil.rs#L158) | Every hostile AppImage, added and started like any other, fails to get out of its sandbox: it cannot read keys, SAM's settings or another app's files; cannot write autostart entries, shell startup files or host temporary files; cannot type into the terminal, reach the network when it has none, see host processes or change its own app folder; cannot reach systemd, the Flatpak spawn portal, the keyring or a launcher service, nor take over a portal's name on the desktop bus; and a symlink or setuid bit in its image gains it nothing. | ✅ |
| [`credential_files_and_folders_in_the_home_are_masked`](../crates/sam-sandbox/src/lib.rs#L2613) | With the whole home granted, credential files are replaced by an empty file and credential folders by an empty folder. | ✅ |
| [`home_protection_is_prepared_only_for_a_writable_home`](../crates/sam-sandbox/src/lib.rs#L2640) | Protected folders are created in the real home only before a start that can write the home, never otherwise. | ✅ |
| [`sams_own_folders_stay_hidden_inside_a_granted_folder`](../crates/sam-sandbox/src/lib.rs#L2526) | SAM's own folders stay hidden when a granted folder contains them, and nothing extra is added when no grant shows them. | ✅ |
| [`user_folder_locations_stay_read_only_with_a_writable_home`](../crates/sam-sandbox/src/lib.rs#L2581) | With the home writable, the file that says where the user folders are stays read-only, so an app cannot point other apps' Documents or Downloads grant at another folder. | 🆕 new |

**Code:** [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs), [`sam-core/src/risk.rs`](../crates/sam-core/src/risk.rs)

<a id="12"></a>
### 12. Network: none, "This computer only" (selected ports), or full.

| Test | Promise | Result |
|---|---|---|
| [`localhost_network_leaves_netns_to_pasta`](../crates/sam-sandbox/src/lib.rs#L2215) | With "this computer only", the network namespace is left to pasta. | ✅ |
| [`only_listed_host_ports`](../crates/sam-runner/src/netns.rs#L115) | With "this computer only", the app reaches only the ports on this computer the user lists. | ✅ |
| [`each_permission_grants_exactly_its_access_in_a_real_sandbox`](../crates/sam-runner/tests/matrix.rs#L101) | Inside a real sandbox, each permission grants exactly its access and nothing more. | ✅ |
| [`a_pasta_command_ending_in_the_separator_is_refused_not_a_panic`](../crates/sam-runner/src/launch.rs#L1519) | A pasta command ending in the separator is refused not a panic. | 🆕 new |
| [`the_status_shell_goes_between_the_separator_and_the_program`](../crates/sam-runner/src/launch.rs#L1526) | The status shell goes between the separator and the program. | 🆕 new |

**Code:** [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs), [`sam-runner/src/netns.rs`](../crates/sam-runner/src/netns.rs)

<a id="13"></a>
### 13. The app reaches only allowed desktop services (a filtered D-Bus) and can't start programs outside its sandbox.

| Test | Promise | Result |
|---|---|---|
| [`own_names_that_are_refused`](../crates/sam-core/src/permissions.rs#L1043) | An app may not own a bus name of a desktop service or of a service that starts on demand; its own application names stay allowed. | ✅ |
| [`blocked_names_win_over_wildcards`](../crates/sam-core/src/permissions.rs#L1090) | A bus name the user blocks stays blocked even when a wildcard in the allowed list would match it. | ✅ |
| [`only_real_socket_paths_are_taken_from_a_dbus_address`](../crates/sam-core/src/host.rs#L732) | Only real socket paths are taken from a D-Bus address; abstract sockets are not. | ✅ |
| [`own_names_from_the_id_and_the_window_class`](../crates/sam-profile/src/lib.rs#L998) | The bus names an app may own come from its application ID and window class, never from protocol or desktop-service names. | ✅ |
| [`filtered_dbus_uses_proxy`](../crates/sam-sandbox/src/lib.rs#L2147) | The filtered desktop bus reaches the app only through SAM's proxy. | ✅ |
| [`the_app_runs_as_the_user_and_host_tools_are_replaced_by_stand_ins`](../crates/sam-sandbox/src/lib.rs#L2170) | The app runs with the user's IDs, and host tools that could leave the sandbox (systemd-run) are replaced by harmless stand-ins. | ✅ |
| [`without_nested_namespaces_user_namespaces_are_disabled`](../crates/sam-sandbox/src/lib.rs#L2248) | Without nested namespaces, the sandbox disables user namespaces and starts through SAM's helper. | ✅ |
| [`extra_sockets_must_be_sockets`](../crates/sam-sandbox/src/lib.rs#L2304) | Extra sockets are passed in only when they really are sockets. | ✅ |
| [`tray_names_follow_watcher_permission`](../crates/sam-runner/src/dbus_proxy.rs#L164) | An app may register a tray icon only while the tray service is allowed. | ✅ |
| [`the_syscall_filter_compiles_and_blocks_mount_and_io_uring`](../crates/sam-runner/src/kernel.rs#L401) | The syscall filter compiles in every variant and always blocks mount and io_uring. | ✅ |
| [`every_breakout_attempt_from_a_real_sandbox_fails`](../crates/sam-runner/tests/breakout.rs#L152) | Every security promise holds inside a real sandbox: each breakout attempt fails. | ✅ |
| [`every_hostile_appimage_fails_to_escape`](../crates/sam-runner/tests/evil.rs#L158) | Every hostile AppImage, added and started like any other, fails to get out of its sandbox: it cannot read keys, SAM's settings or another app's files; cannot write autostart entries, shell startup files or host temporary files; cannot type into the terminal, reach the network when it has none, see host processes or change its own app folder; cannot reach systemd, the Flatpak spawn portal, the keyring or a launcher service, nor take over a portal's name on the desktop bus; and a symlink or setuid bit in its image gains it nothing. | ✅ |
| [`a_socket_counts_as_ready_only_when_it_accepts`](../crates/sam-runner/src/dbus_proxy.rs#L186) | The proxy counts as ready only when its socket accepts connections, not when the file merely exists (regression: the sandbox check sometimes found the session bus refused right after the start). | 🆕 new |
| [`only_a_real_socket_counts_as_a_desktop_service`](../crates/sam-core/src/host.rs#L702) | Only a real socket counts as a desktop service. | 🆕 new |
| [`services_that_start_on_demand_are_recognized`](../crates/sam-core/src/host.rs#L674) | Services that start on demand are recognized from their folders, including the user's own (contract dbus-activatable). | 🆕 new |

**Code:** [`sam-runner/src/dbus_proxy.rs`](../crates/sam-runner/src/dbus_proxy.rs), [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs), [`sam-core/src/permissions.rs`](../crates/sam-core/src/permissions.rs), [`sam-runner/src/kernel.rs`](../crates/sam-runner/src/kernel.rs)

<a id="14"></a>
### 14. Display: Wayland with a security context; X11 only when allowed, with its cost explained.

| Test | Promise | Result |
|---|---|---|
| [`wayland_security_context_socket_is_used`](../crates/sam-sandbox/src/lib.rs#L2070) | With a Wayland security context, the app sees only that socket, not the desktop's own. | ✅ |
| [`xauthority_gets_the_sandbox_display_number`](../crates/sam-sandbox/src/lib.rs#L2040) | The X11 login cookie is rewritten for the display number inside the sandbox. | ✅ |
| [`the_x11_display_number_is_read_from_every_display_form`](../crates/sam-core/src/host.rs#L723) | The X11 display number is read from every common DISPLAY form, and remote displays are refused. | ✅ |

**Code:** [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs), [`sam-runner/src/wayland_ctx.rs`](../crates/sam-runner/src/wayland_ctx.rs), [`sam-core/src/host.rs`](../crates/sam-core/src/host.rs)

<a id="15"></a>
### 15. Sound, GPU, camera and game controllers only when allowed.

| Test | Promise | Result |
|---|---|---|
| [`sdl_gets_its_silent_driver_without_sound_access`](../crates/sam-sandbox/src/lib.rs#L1862) | Games built with SDL get a silent sound driver when sound is off, so they start instead of failing. | ✅ |
| [`gamepads_only_exposes_joysticks`](../crates/sam-sandbox/src/lib.rs#L2272) | "Game controllers" exposes only joysticks, never keyboards or mice. | ✅ |
| [`nvidia_modules_are_exposed_with_the_gpu`](../crates/sam-sandbox/src/lib.rs#L2290) | With the GPU, the NVIDIA driver modules are visible; other kernel modules are not. | ✅ |
| [`each_permission_grants_exactly_its_access_in_a_real_sandbox`](../crates/sam-runner/tests/matrix.rs#L101) | Inside a real sandbox, each permission grants exactly its access and nothing more. | ✅ |

**Code:** [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs)

<a id="16"></a>
### 16. The app can't make itself start later outside the sandbox (autostart, shell startup files, menu entries).

| Test | Promise | Result |
|---|---|---|
| [`full_home_access_cannot_leave_anything_that_runs_later`](../crates/sam-runner/tests/full_home.rs#L50) | Full home access cannot leave anything that runs later. | 🆕 new |
| [`only_what_would_run_later_is_moved_aside`](../crates/sam-sandbox/src/lib.rs#L2440) | After a start with a writable home, only what could make the computer run something is moved aside: a new startup file, a replaced link to a protected folder, a key folder the app was not given. | 🆕 new |
| [`protected_parents_are_locked_and_linked_keys_hidden`](../crates/sam-sandbox/src/lib.rs#L2492) | With a writable home, the folders above protected places are mount points of their own (so they cannot be renamed away), and a key folder that is a link is hidden where it points. | 🆕 new |
| [`landlock_allows_writing_exactly_in_granted_folders`](../crates/sam-runner/src/kernel.rs#L378) | The Landlock rules allow writing exactly in the folders the permissions grant. | ✅ |
| [`every_breakout_attempt_from_a_real_sandbox_fails`](../crates/sam-runner/tests/breakout.rs#L152) | Every security promise holds inside a real sandbox: each breakout attempt fails. | ✅ |
| [`every_hostile_appimage_fails_to_escape`](../crates/sam-runner/tests/evil.rs#L158) | Every hostile AppImage, added and started like any other, fails to get out of its sandbox: it cannot read keys, SAM's settings or another app's files; cannot write autostart entries, shell startup files or host temporary files; cannot type into the terminal, reach the network when it has none, see host processes or change its own app folder; cannot reach systemd, the Flatpak spawn portal, the keyring or a launcher service, nor take over a portal's name on the desktop bus; and a symlink or setuid bit in its image gains it nothing. | ✅ |
| [`every_known_syscall_has_been_reviewed`](../crates/sam-runner/tests/syscalls.rs#L67) | Every known syscall has been reviewed. | 🆕 new |
| [`the_review_list_matches_the_filter`](../crates/sam-runner/tests/syscalls.rs#L86) | The review list says which syscalls the filter blocks; it must match the filter itself, or the review would describe a filter that does not exist. | 🆕 new |

**Code:** [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs), [`sam-runner/src/kernel.rs`](../crates/sam-runner/src/kernel.rs)

<a id="17"></a>
### 17. The app can't type into your terminal.

| Test | Promise | Result |
|---|---|---|
| [`output_shown_in_a_terminal_is_filtered_without_the_relay`](../crates/sam-runner/src/launch.rs#L1549) | With its input redirected an app has no terminal relay; its output shown in a terminal still loses clipboard codes and title reports, even split over two lines. | 🆕 new |
| [`plain_text_survives_unfinished_and_odd_codes`](../crates/sam-runner/src/pty.rs#L833) | The log's plain text survives every unfinished or odd code: one cut off at the end of the data (no read past it), a title ended by ESC \\ with text after it, a backslash inside a title, and an ESC with intermediate bytes at the very end (found by mutation testing: no test reached these edges). | 🆕 new |
| [`only_tmux_itself_counts_as_tmux_passthrough`](../crates/sam-runner/src/pty.rs#L857) | Only "tmux;" itself is tmux passthrough: a DCS that merely starts with "t" passes unchanged (found by mutation testing). | 🆕 new |
| [`leading_zeros_do_not_smuggle_a_code`](../crates/sam-runner/src/pty.rs#L777) | Leading zeros do not smuggle a code past the filter: terminals read "0052" as 52 and "021" as 21, and so does SAM; a number too long for any real code is removed whole (regression: an 11-digit OSC 52 was cut to 5 and passed on). | 🆕 new |
| [`a_new_session_unless_the_app_is_on_sams_own_terminal`](../crates/sam-sandbox/src/lib.rs#L1885) | The app gets a new terminal session, unless it runs on SAM's terminal relay. | ✅ |
| [`ordinary_output_passes_unchanged`](../crates/sam-runner/src/pty.rs#L717) | Ordinary terminal output, colors and links pass through the relay unchanged. | ✅ |
| [`clipboard_codes_are_removed`](../crates/sam-runner/src/pty.rs#L755) | Escape codes that read or write the clipboard are removed from an app's terminal output. | ✅ |
| [`title_reports_and_tmux_passthrough_are_removed`](../crates/sam-runner/src/pty.rs#L794) | Escape codes that report the window title or pass through tmux are removed; setting the title stays allowed. | ✅ |
| [`an_escape_inside_a_removed_code_starts_a_new_sequence`](../crates/sam-runner/src/pty.rs#L811) | An escape code hidden inside a removed code cannot slip through. | ✅ |
| [`plain_text_for_the_log`](../crates/sam-runner/src/pty.rs#L820) | Logs get plain text without escape codes. | ✅ |
| [`terminal_apps_get_sams_terminal_relay`](../crates/sam-runner/src/pty.rs#L869) | Apps started from a terminal get SAM's terminal relay; apps without a terminal get none. | ✅ |
| [`typing_and_output_pass_and_leftover_replies_are_discarded`](../crates/sam-runner/src/pty.rs#L891) | A second pseudo-terminal stands in for the user's terminal: SAM's side of it is `Outer`, the test plays the terminal program. | ✅ |
| [`the_app_cannot_reach_the_outer_terminal`](../crates/sam-runner/src/pty.rs#L973) | An app on SAM's terminal relay cannot type into the user's real terminal. | ✅ |
| [`every_hostile_appimage_fails_to_escape`](../crates/sam-runner/tests/evil.rs#L158) | Every hostile AppImage, added and started like any other, fails to get out of its sandbox: it cannot read keys, SAM's settings or another app's files; cannot write autostart entries, shell startup files or host temporary files; cannot type into the terminal, reach the network when it has none, see host processes or change its own app folder; cannot reach systemd, the Flatpak spawn portal, the keyring or a launcher service, nor take over a portal's name on the desktop bus; and a symlink or setuid bit in its image gains it nothing. | ✅ |
| [`a_doubled_escape_does_not_smuggle_a_clipboard_code`](../crates/sam-runner/src/pty.rs#L729) | A doubled ESC in front of a clipboard code does not smuggle it past the filter: the terminal reads the second ESC as the start of the code, so the filter must too. | ✅ |

**Code:** [`sam-runner/src/pty.rs`](../crates/sam-runner/src/pty.rs), [`sam-runner/src/kernel.rs`](../crates/sam-runner/src/kernel.rs), [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs)

<a id="18"></a>
### 18. Optional: a writable app folder (changes go to a separate layer); where that's impossible, a read-only start with an explanation.

| Test | Promise | Result |
|---|---|---|
| [`writable_appdir_uses_overlay`](../crates/sam-sandbox/src/lib.rs#L2228) | A writable app folder uses an overlay; the unpacked app itself stays unchanged. | ✅ |
| [`an_app_starts_read_only_when_its_writable_app_folder_cannot_work`](../crates/sam-runner/tests/overlay_fallback.rs#L37) | When the folder for the writable app folder's changes cannot hold an overlay, the app still starts, with a read-only app folder and a warning that says why (regression: on Fedora in a container, SAM's data folder was on an overlay, and the app failed with a raw Bubblewrap error). | ✅ |
| [`a_writable_app_folder_is_offered_only_where_it_can_work`](../crates/sam-runner/src/repair.rs#L950) | The repair steps offer a writable app folder only where an overlay can work: not where SAM's overlay folder cannot hold one (regression: the step was offered by Bubblewrap's version alone, and on such disks the app then started read-only anyway). | ✅ |
| [`the_app_folder_stays_read_only_unless_writable_is_granted`](../crates/sam-sandbox/src/lib.rs#L2416) | The app's own folder stays read-only unless "writable app folder" is granted, even when SAM has an overlay for it prepared. | ✅ |

**Code:** [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs), [`sam-runner/src/launch.rs`](../crates/sam-runner/src/launch.rs), [`sam-core/src/host.rs`](../crates/sam-core/src/host.rs)

## D. Starting and running

<a id="19"></a>
### 19. Starting from SAM's window, from the menu, or from the terminal always goes through the sandbox.

| Test | Promise | Result |
|---|---|---|
| [`sams_menu_entry_starts_the_app_only_through_sam`](../crates/sam-intake/src/desktop.rs#L355) | SAM's menu entry starts the app through sam-jail-run, never the AppImage directly. | ✅ |
| [`app_metadata_cannot_add_lines_to_sams_menu_entry`](../crates/sam-intake/src/desktop.rs#L309) | SAM's menu entry starts the app only through SAM's sandbox: no value taken from the app (name, comment, categories, file types, window class) can add a line such as a second "Exec=" to it, even from a record changed outside SAM. | ✅ |
| [`menu_entry_paths_are_quoted_against_spaces_and_dollar_signs`](../crates/sam-intake/src/desktop.rs#L344) | Program paths in menu entries are quoted so spaces and dollar signs cannot change the command. | ✅ |
| [`launcher_mime_types_drop_hijack_targets`](../crates/sam-intake/src/desktop.rs#L378) | SAM's menu entry never claims links, folders or desktop files, so a sandboxed app cannot take over opening them. | ✅ |
| [`launcher_drops_hijack_mime_types`](../crates/sam-runner/tests/adversarial.rs#L114) | M1: a launcher never registers URL schemes, directories or executables. | ✅ |
| [`hide_and_restore_user_entry`](../crates/sam-intake/src/menu.rs#L309) | An unsandboxed menu entry in the user's folder is hidden on request and restored exactly as it was. | ✅ |
| [`system_entry_gets_override`](../crates/sam-intake/src/menu.rs#L353) | An unsandboxed menu entry in a system folder is hidden through an entry in the user's folder, without touching the system file. | ✅ |
| [`found_appimages_get_a_menu_entry_only_with_a_sandbox`](../crates/sam-runner/tests/overview.rs#L13) | AppImages are listed before they have a sandbox; only creating the sandbox adds SAM's menu entry and hides unsandboxed ones, and removing it puts them back. | ✅ |
| [`shell_quoting_keeps_spaces_and_quotes_intact`](../crates/sam-core/src/util.rs#L316) | Shell quoting keeps spaces, quotes and empty strings intact. | ✅ |
| [`the_window_id_matches_the_name_of_sams_menu_entry`](../crates/sam-core/src/paths.rs#L209) ⟲ | Regression: sandboxed windows carried the app's id as their app ID while SAM's menu entry is "sam-<id>.desktop", so the taskbar found no entry and showed a generic icon. | ✅ |

**Code:** [`sam-intake/src/desktop.rs`](../crates/sam-intake/src/desktop.rs), [`sam-intake/src/menu.rs`](../crates/sam-intake/src/menu.rs), [`sam-runner/src/launch.rs`](../crates/sam-runner/src/launch.rs), [`sam-core/src/paths.rs`](../crates/sam-core/src/paths.rs)

**Also tried by:** [`tests/gui/flow-atspi.sh`](../tests/gui/flow-atspi.sh), [`tests/gui/taskbar-kwin.sh`](../tests/gui/taskbar-kwin.sh)

<a id="20"></a>
### 20. SAM checks from inside the sandbox that every setting applies (the sandbox check).

| Test | Promise | Result |
|---|---|---|
| [`a_check_reports_what_it_finds_not_what_it_hopes`](../crates/sam-runner/src/probe.rs#L580) | Each check reports what it finds, not what it hopes: run on facts that are the same on every computer, a check whose expectation is wrong fails, one whose expectation is right passes, and the report counts them (found by mutation testing: a check turning every failure into a pass went unnoticed). | 🆕 new |
| [`a_skipped_check_is_neither_passed_nor_failed`](../crates/sam-runner/src/probe.rs#L729) | A verdict is exactly pass, fail or "could not check": a skipped check counts neither as passed nor as failed. | 🆕 new |
| [`the_check_expects_each_folder_as_its_settings_show_it`](../crates/sam-runner/src/verify.rs#L795) | What the check expects of each folder: the folder's own setting, but never less than the home shows it (a read-only home shows Documents read-only even when Documents has no setting; a writable folder in a read-only home stays writable); keys only with full home and their own switch; extra folders like the home inside it. | 🆕 new |
| [`the_check_expects_the_rest_where_setting_and_computer_allow_it`](../crates/sam-runner/src/verify.rs#L880) | Network, display, sound, the session bus, the SSH agent, variables and the security layers: the check expects each only where both the setting and this computer provide it. | 🆕 new |
| [`folder_check_tells_real_from_private`](../crates/sam-runner/src/probe.rs#L761) | The sandbox check tells a real folder of the user from a private stand-in. | ✅ |
| [`the_sandbox_check_passes_and_catches_mismatches`](../crates/sam-runner/tests/verify.rs#L22) | The sandbox check passes when the settings apply, and catches a setting that does not apply. | ✅ |
| [`a_wanted_layer_that_was_not_applied_is_reported_missing`](../crates/sam-runner/src/launch.rs#L1482) | A wanted layer that was not applied is reported missing. | 🆕 new |
| [`a_start_without_the_helper_reports_its_missing_layers`](../crates/sam-jail-cli/tests/layers.rs#L32) | A start without the helper reports its missing layers. | 🆕 new |
| [`a_start_without_a_wanted_protection_layer_is_marked`](../crates/sam-core/src/model.rs#L763) | A start without a wanted protection layer is marked. | 🆕 new |
| [`sam_jail_run_refuses_a_sandbox_whose_settings_do_not_apply`](../crates/sam-jail-cli/tests/start_check.rs#L49) | Sam jail run refuses a sandbox whose settings do not apply. | 🆕 new |

**Code:** [`sam-runner/src/verify.rs`](../crates/sam-runner/src/verify.rs), [`sam-runner/src/probe.rs`](../crates/sam-runner/src/probe.rs)

**Also tried by:** [`tests/real-apps/run.sh`](../tests/real-apps/run.sh)

<a id="21"></a>
### 21. A second start, closing, and stopping work cleanly and leave nothing behind.

| Test | Promise | Result |
|---|---|---|
| [`stop_closes_running_apps`](../crates/sam-runner/tests/stop.rs#L66) | Closing an app ends all of its running starts. | ✅ |
| [`removing_a_sandbox_while_its_app_runs_is_refused`](../crates/sam-runner/tests/settings.rs#L104) | A running app keeps its sandbox: removing it is refused until the app is closed (a launch holds a lock in the app's runtime folder). | ✅ |
| [`the_overlay_check_leaves_no_folder_behind`](../crates/sam-core/src/host.rs#L182) | The overlay check leaves nothing behind, even the work folder the overlay locks (a leftover folder per check piled up in SAM's data). | ✅ |
| [`leftovers_of_earlier_overlay_checks_are_removed`](../crates/sam-core/src/host.rs#L200) | Folders left by earlier checks whose process is gone are removed; one of a check still running stays. | ✅ |
| [`without_network_the_sandbox_dies_with_its_launcher`](../crates/sam-jail-cli/tests/teardown.rs#L160) | Without network the sandbox dies with its launcher. | 🆕 new |
| [`with_this_computer_only_the_sandbox_dies_with_its_launcher`](../crates/sam-jail-cli/tests/teardown.rs#L169) | With this computer only the sandbox dies with its launcher. | 🆕 new |

**Code:** [`sam-runner/src/launch.rs`](../crates/sam-runner/src/launch.rs), [`sam-runner/src/ops/mod.rs`](../crates/sam-runner/src/ops/mod.rs), [`sam-core/src/host.rs`](../crates/sam-core/src/host.rs)

**Also tried by:** [`tests/real-apps/run.sh`](../tests/real-apps/run.sh)

<a id="22"></a>
### 22. Logs of every start are kept, with old ones removed automatically.

| Test | Promise | Result |
|---|---|---|
| [`the_newest_log_survives_pruning_within_one_second`](../crates/sam-storage/src/lib.rs#L597) | With more launches in one second than logs are kept, the newest log survives the pruning after its launch (regression: on a fast machine a pruned name was reused, sorted as the oldest and deleted at once). | ✅ |
| [`the_newest_log_is_found_even_within_one_second`](../crates/sam-storage/src/lib.rs#L715) | The newest log is found even when two logs start within the same second. | ✅ |
| [`a_launch_log_stops_growing_at_its_limit`](../crates/sam-runner/src/launch.rs#L1431) | An app that prints without end cannot fill the disk or SAM's memory: the launch log stops at its limit with a note, a line without an end is read in pieces, and the whole output is still read. | 🆕 new |

**Code:** [`sam-storage/src/lib.rs`](../crates/sam-storage/src/lib.rs), [`sam-runner/src/launch.rs`](../crates/sam-runner/src/launch.rs)

## E. Fixing apps that don't work

<a id="23"></a>
### 23. After a failed start, SAM says what went wrong and offers a fix with one click.

| Test | Promise | Result |
|---|---|---|
| [`a_start_without_bubblewrap_stops_before_anything_runs`](../crates/sam-runner/src/launch.rs#L1570) | Without Bubblewrap, starting an app stops while it is being prepared, before any process is started, and the error says what to install. | ✅ |
| [`sandbox_setup_errors_are_told_apart_from_app_errors`](../crates/sam-runner/src/launch.rs#L1607) | Bubblewrap setup errors are told apart from errors of the app itself. | ✅ |
| [`a_start_is_judged_by_whether_the_app_started`](../crates/sam-runner/src/launch.rs#L1628) | A start is judged by whether Bubblewrap announced the app, not by what the app printed. | ✅ |
| [`own_name_requests_become_a_repair`](../crates/sam-runner/src/repair.rs#L778) | An app that fails to register its bus name gets a repair step that allows exactly that name. | ✅ |
| [`analyzer_maps_errors_to_fixes`](../crates/sam-runner/src/repair.rs#L810) | Error messages in an app's output are mapped to the repair step that fixes them. | ✅ |
| [`fake_bwrap_error_is_not_a_sandbox_failure`](../crates/sam-runner/tests/adversarial.rs#L21) | H1: an app printing a fake Bubblewrap error is not a sandbox failure. | ✅ |

**Code:** [`sam-runner/src/repair.rs`](../crates/sam-runner/src/repair.rs), [`sam-runner/src/launch.rs`](../crates/sam-runner/src/launch.rs), [`sam-gtk/src/app_page/render.rs`](../crates/sam-gtk/src/app_page/render.rs)

**Also tried by:** [`tests/gui/app-page-atspi.sh`](../tests/gui/app-page-atspi.sh), [`tests/real-apps/run.sh`](../tests/real-apps/run.sh)

<a id="24"></a>
### 24. Repair steps go from mild to strong, and each one can be undone.

| Test | Promise | Result |
|---|---|---|
| [`a_repair_step_says_what_it_changes_and_costs`](../crates/sam-runner/src/repair.rs#L739) | A repair step says in a sentence what it turns on or off, with the switch's own explanation of what that allows. | ✅ |
| [`ladder_skips_applied_and_noop_steps`](../crates/sam-runner/src/repair.rs#L916) | The repair ladder leaves out steps already applied and steps that would change nothing. | ✅ |
| [`a_writable_app_folder_is_offered_only_where_it_can_work`](../crates/sam-runner/src/repair.rs#L950) | The repair steps offer a writable app folder only where an overlay can work: not where SAM's overlay folder cannot hold one (regression: the step was offered by Bubblewrap's version alone, and on such disks the app then started read-only anyway). | ✅ |
| [`undoing_repair_steps_restores_the_settings_from_before_the_first_step`](../crates/sam-runner/tests/settings.rs#L59) | Undoing repair steps restores the settings from before the first step. | ✅ |
| [`switching_off_one_repair_step_keeps_the_others`](../crates/sam-runner/tests/settings.rs#L165) | A repair step can be switched off on its own: exactly what that step changed goes back, and the other applied steps stay. | ✅ |
| [`only_plain_library_names_are_accepted`](../crates/sam-core/src/permissions.rs#L1145) | Only plain shared-library file names are accepted as system libraries: no folders, no `..`, nothing that is not a library. | ✅ |
| [`system_copies_replace_only_bundled_libraries_by_plain_name`](../crates/sam-sandbox/src/lib.rs#L2331) | A bundled library listed in advanced.system_libraries is replaced by the system's copy at its place in the app folder; names with folders or `..`, libraries the app does not bundle and libraries the system does not have are ignored. | ✅ |

**Code:** [`sam-runner/src/repair.rs`](../crates/sam-runner/src/repair.rs), [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs)

<a id="25"></a>
### 25. The diagnose run finds missing files and suggests only what helps.

| Test | Promise | Result |
|---|---|---|
| [`failed_accesses_are_read_from_a_trace`](../crates/sam-runner/src/diagnose.rs#L491) | Failed file and socket accesses are read from a diagnostic trace. | ✅ |
| [`failed_accesses_map_to_the_permission_that_fixes_them`](../crates/sam-runner/src/diagnose.rs#L511) | Failed accesses are mapped to the permission that would fix them (X11 socket, GPU device), and unknown paths to none. | ✅ |
| [`a_failure_despite_the_permission_is_not_suggested_again`](../crates/sam-runner/src/diagnose.rs#L552) | A GPU device that fails to open while the GPU is already allowed is reported as "already granted", not as a suggestion to allow the GPU (regression: neovide on NVIDIA got "Enable GPU acceleration" twice). | ✅ |
| [`the_apps_own_folders_in_its_private_home_are_not_reported`](../crates/sam-runner/src/diagnose.rs#L574) | A missing cache, settings or data folder in the app's private home is the app's own and is not reported, while a missing document folder is (regression: ~/.cache/nvidia was suggested as a folder to grant). | ✅ |
| [`failed_changes_to_a_file_are_not_missing_access`](../crates/sam-runner/src/diagnose.rs#L591) | A failed attempt to change a file's mode is not missing access (regression: NVIDIA's driver chmods /dev/nvidia-modeset, which fails for every ordinary user, and diagnose reported it as a GPU problem). | ✅ |
| [`write_checks_on_system_folders_are_not_missing_access`](../crates/sam-runner/src/diagnose.rs#L603) | Checking whether a system file is writable is not missing access (regression: Zrythm and mpv ask access(W_OK) for files in /usr, which fails for every user, and diagnose suggested granting /usr/lib/lv2). | ✅ |
| [`files_in_etc_are_suggested_and_not_added_automatically`](../crates/sam-runner/src/diagnose.rs#L619) | A file in /etc is suggested, never added by itself, because it describes this computer (regression: /etc/fstab and /etc/pacman.conf were "low risk" and added automatically, although the apps ran without them). | ✅ |
| [`the_apps_own_settings_folder_is_not_reported_as_sensitive`](../crates/sam-runner/src/diagnose.rs#L651) | The apps own settings folder is not reported as sensitive. | ✅ |
| [`diagnostic_runs_obey_the_preference`](../crates/sam-runner/src/diagnose.rs#L634) | The app's own settings folder in its private home is not reported as a sensitive folder (regression: ~/.config was "dangerous"). | 🆕 new |

**Code:** [`sam-runner/src/diagnose.rs`](../crates/sam-runner/src/diagnose.rs)

<a id="26"></a>
### 26. Compatibility mode as a last resort, with its cost explained, and it can be undone.

| Test | Promise | Result |
|---|---|---|
| [`compatibility_mode_names_only_what_it_changes`](../crates/sam-runner/src/repair.rs#L721) | Compatibility mode lists only what it actually changes, in the words of the switches. | ✅ |
| [`turning_compatibility_mode_off_restores_exactly_the_settings_from_before`](../crates/sam-runner/tests/settings.rs#L42) | Turning compatibility mode off restores exactly the settings the user had before. | ✅ |

**Code:** [`sam-runner/src/repair.rs`](../crates/sam-runner/src/repair.rs), [`sam-runner/src/ops/profiles.rs`](../crates/sam-runner/src/ops/profiles.rs)

## F. Keeping things safe over time

<a id="27"></a>
### 27. SAM notices app settings that something else changed and asks before starting the app.

| Test | Promise | Result |
|---|---|---|
| [`records_changed_outside_sam_are_recognized`](../crates/sam-storage/src/lib.rs#L617) | A record SAM saved loads as unchanged; a record changed afterwards by something else is recognized as changed outside SAM; a record from before the checksum existed still loads as unchanged; and saving it again through SAM makes it unchanged again. | ✅ |
| [`an_app_changed_outside_sam_starts_only_after_confirmation`](../crates/sam-runner/tests/tamper.rs#L107) | An app whose settings were changed outside SAM does not start until the user has confirmed them; changes SAM makes itself never count as such. | ✅ |

**Code:** [`sam-storage/src/lib.rs`](../crates/sam-storage/src/lib.rs), [`sam-runner/src/launch.rs`](../crates/sam-runner/src/launch.rs)

<a id="28"></a>
### 28. Updates use HTTPS only, keep the old version so it can be restored, and refuse a changed signing key until you accept it.

| Test | Promise | Result |
|---|---|---|
| [`both_forms_of_update_information_are_understood`](../crates/sam-detect/src/update_info.rs#L139) | Both forms of update information (a direct zsync address and GitHub releases) are understood. | ✅ |
| [`update_wildcards_match_only_the_right_build`](../crates/sam-detect/src/update_info.rs#L166) | Wildcards in update information match the right file name and not the build for another processor. | ✅ |
| [`signed_appimage_is_checked`](../crates/sam-detect/tests/signature.rs#L20) | The signature of a signed AppImage is checked with GnuPG. | ✅ |
| [`key_changes_are_noticed`](../crates/sam-runner/src/ops/mod.rs#L544) | An update signed with another key, or not signed at all, is noticed. | ✅ |
| [`sam_updates_itself_only_with_its_release_key`](../crates/sam-runner/src/release_key.rs#L104) | SAM accepts an update of itself only with a valid signature from one of its release keys; unsigned, changed, unchecked or otherwise signed updates are refused (regression: self-update installed any AppImage the update information pointed to). | ✅ |
| [`release_keys_are_full_fingerprints`](../crates/sam-runner/src/release_key.rs#L77) | Every built-in release key is a full fingerprint (40 hex characters), never a short key id that another key could share. | ✅ |
| [`signing_a_file_without_signature_sections_is_refused`](../crates/sam-jail-cli/tests/robustness.rs#L258) | Signing a file that has no AppImage signature sections is refused with a clear message, before GnuPG is asked anything, and the file stays as it was. | ✅ |
| [`without_a_release_key_sam_never_updates_itself`](../crates/sam-runner/src/release_key.rs#L140) | Without a built-in release key, SAM never updates itself, whatever the download looks like. | ✅ |
| [`the_zsync_header_is_read`](../crates/sam-runner/src/updates.rs#L591) | The header of a zsync file is read (file name, size, checksum). | ✅ |
| [`update_download_addresses_are_resolved_and_http_refused`](../crates/sam-runner/src/updates.rs#L615) | Download addresses in zsync files are resolved, and plain-HTTP addresses are refused. | ✅ |
| [`updates_are_downloaded_over_https_only`](../crates/sam-runner/src/updates.rs#L632) | Update downloads use HTTPS only; HTTP and file addresses are refused. | ✅ |
| [`an_update_is_rebuilt_from_the_old_version_and_changed_blocks`](../crates/sam-runner/src/zsync.rs#L405) | An update is rebuilt from the old version plus the changed blocks. | ✅ |
| [`the_rolling_checksum_matches_a_direct_computation`](../crates/sam-runner/src/zsync.rs#L459) | The rolling checksum of the update transfer matches a direct computation at every offset. | ✅ |
| [`refuses_compressed_and_broken_files`](../crates/sam-runner/src/zsync.rs#L475) | Compressed or incomplete zsync files are refused. | ✅ |
| [`undo_puts_the_previous_version_back`](../crates/sam-runner/tests/update.rs#L15) | Undoing an update puts the previous version back. | ✅ |
| [`undoing_an_update_never_moves_files_outside_sams_backup_folder`](../crates/sam-runner/tests/tamper.rs#L89) ⟲ | Regression (found in the test audit): "go back to the earlier version" moved the file a record named as the backup, wherever it was. | ✅ |
| [`block_checksums_match_the_zsync_definition`](../crates/sam-runner/src/zsync.rs#L353) | The block checksums are the ones zsync defines: MD4 of a block padded with zeros to the block size, and the weak sum cut to its last bytes. | ✅ |
| [`the_download_checksum_is_sha1_of_the_whole_file`](../crates/sam-runner/src/updates.rs#L571) | The checksum of a downloaded update is SHA-1 of the whole file, read in pieces; a file larger than one piece gives the same result. | ✅ |
| [`updates_download_only_changes_check_them_and_refuse_tampering`](../crates/sam-runner/tests/update_server.rs#L170) | Updates download only changes check them and refuse tampering. | 🆕 new |
| [`the_weak_hashes_stay_in_the_zsync_update_code`](../crates/sam-jail-cli/tests/architecture.rs#L206) | SHA-1 and MD4 are broken as protection against tampering. | 🆕 new |
| [`an_update_that_cannot_be_checked_needs_consent_after_a_valid_signature`](../crates/sam-runner/src/ops/mod.rs#L570) | A signed app whose update cannot be checked (GnuPG missing) is not waved through: SAM cannot tell whether the key changed. | 🆕 new |

**Code:** [`sam-runner/src/updates.rs`](../crates/sam-runner/src/updates.rs), [`sam-runner/src/zsync.rs`](../crates/sam-runner/src/zsync.rs), [`sam-runner/src/release_key.rs`](../crates/sam-runner/src/release_key.rs), [`sam-detect/src/update_info.rs`](../crates/sam-detect/src/update_info.rs), [`sam-detect/src/signature.rs`](../crates/sam-detect/src/signature.rs)

<a id="29"></a>
### 29. SAM notices AppImages that were moved or changed.

| Test | Promise | Result |
|---|---|---|
| [`a_swapped_appimage_does_not_start_until_it_is_confirmed`](../crates/sam-runner/tests/changed_appimage.rs#L13) | A swapped appimage does not start until it is confirmed. | 🆕 new |
| [`a_swapped_appimage_file_is_marked_and_old_records_stay_unchanged`](../crates/sam-core/src/model.rs#L698) | An AppImage file swapped outside SAM shows as changed outside SAM; while the mark is off it is not written, so every record saved before it existed keeps its checksum (no app looks changed after an update). | 🆕 new |
| [`a_changed_appimage_file_is_noticed`](../crates/sam-intake/src/fingerprint.rs#L107) | A changed AppImage file is noticed by its fingerprint. | ✅ |
| [`a_moved_appimage_is_recognized_by_its_content`](../crates/sam-runner/tests/settings.rs#L144) | When a sandboxed app's AppImage is moved to another searched folder, SAM recognizes it by its content and offers to follow it. | ✅ |

**Code:** [`sam-intake/src/fingerprint.rs`](../crates/sam-intake/src/fingerprint.rs), [`sam-runner/src/ops/maintain.rs`](../crates/sam-runner/src/ops/maintain.rs)

## G. Managing

<a id="30"></a>
### 30. Removing an app deletes only SAM's own folders, never your files.

| Test | Promise | Result |
|---|---|---|
| [`removing_a_sandbox_never_deletes_outside_sams_unpack_folder`](../crates/sam-runner/tests/tamper.rs#L34) ⟲ | Regression: the unpack folder in a record was only checked with Path::starts_with, which does not resolve "..": "extracted/../../victim" passed, and removing the sandbox deleted the victim folder. | ✅ |
| [`a_record_with_a_climbing_id_reaches_nothing`](../crates/sam-runner/tests/tamper.rs#L66) | A record whose id climbs out of SAM's folders cannot be loaded, so no operation can reach the folders that id would name. | ✅ |
| [`records_with_unsafe_or_mismatched_ids_are_not_loaded`](../crates/sam-storage/src/lib.rs#L685) ⟲ | Regression (found in the test audit): a record changed outside SAM with an id like "../../.ssh" would have pointed the folders SAM deletes on removal (private home, logs) outside SAM's own folders. | ✅ |
| [`removing_with_keep_my_data_keeps_the_private_home_and_without_deletes_it`](../crates/sam-runner/tests/settings.rs#L125) | Removing a sandbox with "keep my data" keeps the app's private home; without it, the home is deleted. | ✅ |
| [`removing_a_sandbox_while_its_app_runs_is_refused`](../crates/sam-runner/tests/settings.rs#L104) | A running app keeps its sandbox: removing it is refused until the app is closed (a launch holds a lock in the app's runtime folder). | ✅ |
| [`names_become_safe_identifiers`](../crates/sam-core/src/util.rs#L309) | Names become safe identifiers made of lowercase letters, digits and dashes. | ✅ |

**Code:** [`sam-runner/src/ops/maintain.rs`](../crates/sam-runner/src/ops/maintain.rs), [`sam-storage/src/lib.rs`](../crates/sam-storage/src/lib.rs), [`sam-core/src/util.rs`](../crates/sam-core/src/util.rs)

<a id="31"></a>
### 31. Disk space per app, and freeing space.

| Test | Promise | Result |
|---|---|---|
| [`freeing_space_deletes_the_unpacked_copy_and_unpacking_restores_it`](../crates/sam-runner/tests/space.rs#L13) | Freeing space deletes the unpacked copy, and unpacking again brings the app back. | ✅ |

**Code:** [`sam-runner/src/ops/maintain.rs`](../crates/sam-runner/src/ops/maintain.rs)

<a id="32"></a>
### 32. Uninstalling SAM removes everything it created and brings back menu entries it hid.

| Test | Promise | Result |
|---|---|---|
| [`uninstall_removes_everything_and_restores_menus`](../crates/sam-runner/tests/uninstall.rs#L17) | Uninstalling SAM removes all of its files and restores the menu entries it had hidden. | ✅ |
| [`uninstall_refuses_folders_that_are_not_sams`](../crates/sam-runner/tests/uninstall.rs#L123) | Uninstalling refuses to delete a folder that is not SAM's, such as the home folder. | ✅ |

**Code:** [`sam-runner/src/ops/maintain.rs`](../crates/sam-runner/src/ops/maintain.rs), [`sam-intake/src/menu.rs`](../crates/sam-intake/src/menu.rs)

<a id="33"></a>
### 33. The doctor check finds problems with the system or an app.

| Test | Promise | Result |
|---|---|---|
| [`missing_bubblewrap_names_the_package_to_install`](../crates/sam-runner/src/bwrap.rs#L55) | Without Bubblewrap, the message says which package to install. | ✅ |
| [`disabled_user_namespaces_are_explained_not_called_missing`](../crates/sam-runner/src/bwrap.rs#L66) | When the system forbids user namespaces, the message explains that and never claims Bubblewrap is missing: the user already has it, and an "install bubblewrap" hint would send them the wrong way. | ✅ |
| [`setuid_bubblewrap_works_without_user_namespaces`](../crates/sam-runner/src/bwrap.rs#L85) | A setuid Bubblewrap works without unprivileged user namespaces, so SAM does not refuse it. | ✅ |
| [`reaches_the_session_bus`](../crates/sam-runner/src/dbus_check.rs#L222) | SAM's own bus check reaches a session bus. | ✅ |
| [`the_bus_check_message_has_the_correct_wire_format`](../crates/sam-runner/src/dbus_check.rs#L272) | SAM's own D-Bus message for the bus check has the correct wire format. | ✅ |
| [`bubblewrap_versions_are_compared_correctly`](../crates/sam-core/src/host.rs#L228) | Bubblewrap versions are compared correctly, including missing or malformed version text. | ✅ |
| [`the_built_in_contract_map_parses`](../crates/sam-runner/src/contracts.rs#L550) | The built in contract map parses. | 🆕 new |
| [`every_contract_probe_is_known`](../crates/sam-runner/src/contracts.rs#L556) | Every contract probe is known. | 🆕 new |
| [`a_missing_portal_interface_breaks_the_portal_contract`](../crates/sam-runner/src/contracts.rs#L652) | A missing portal interface breaks the portal contract. | 🆕 new |
| [`the_quick_checks_notice_a_broken_or_missing_tool`](../crates/sam-jail-cli/tests/contracts.rs#L47) | The quick checks notice a broken or missing tool. | 🆕 new |
| [`a_broken_contract_fails_a_test_with_its_name_and_playbook`](../crates/sam-runner/src/contracts.rs#L568) | A broken contract fails a test with its name and playbook. | 🆕 new |

**Code:** [`sam-runner/src/doctor.rs`](../crates/sam-runner/src/doctor.rs), [`sam-runner/src/bwrap.rs`](../crates/sam-runner/src/bwrap.rs), [`sam-runner/src/dbus_check.rs`](../crates/sam-runner/src/dbus_check.rs), [`sam-core/src/host.rs`](../crates/sam-core/src/host.rs)

<a id="34"></a>
### 34. Privacy: SAM sends nothing on its own, and a bug report never contains your name, home path, addresses or secrets.

| Test | Promise | Result |
|---|---|---|
| [`given_environment_values_are_hidden_in_the_shown_command`](../crates/sam-core/src/sandbox.rs#L233) | Values of variables a person gave the app never reach the shown command; the names and SAM's own variables stay. | 🆕 new |
| [`bug_reports_hide_the_user_name_and_home_path`](../crates/sam-runner/src/doctor.rs#L803) | A bug report never contains the user's name or home path: both are replaced before the text is shown for copying. | ✅ |
| [`bug_reports_hide_names_addresses_and_secrets`](../crates/sam-runner/src/doctor.rs#L845) | Bug reports hide everything that identifies the user or gives access: a home folder with spaces, other users' folders, short user names, the computer's name, email addresses, logins and tokens in links, IP addresses, and the values of environment variables given to the app. | 🆕 new |
| [`a_bug_report_is_complete_and_redacted`](../crates/sam-runner/src/doctor.rs#L821) | A whole bug report (the system part) is produced and redacted: it names SAM's version and never the home folder or user name. | 🆕 new |
| [`update_checks_stay_off_unless_switched_on`](../crates/sam-core/src/config.rs#L449) | SAM contacts no update source on its own: the daily check when the window opens is off until the user switches it on. | 🆕 new |
| [`the_machine_id_reaches_only_apps_with_dbus`](../crates/sam-sandbox/src/lib.rs#L1895) | The machine ID identifies this computer; an app sees it only with D-Bus, which needs it, never without. | 🆕 new |

**Code:** [`sam-runner/src/doctor.rs`](../crates/sam-runner/src/doctor.rs)

## H. The window

<a id="35"></a>
### 35. The overview of all apps, with clear status badges.

| Test | Promise | Result |
|---|---|---|
| [`profile_change_clears_broken_launch`](../crates/sam-core/src/model.rs#L680) | Changing an app's settings clears the record of a failed start, so the app is no longer shown as broken. | ✅ |
| [`apps_with_compatibility_risk_are_marked_until_they_start`](../crates/sam-core/src/model.rs#L725) | An app with compatibility risk carries a warning badge until it has started successfully once. | ✅ |
| [`apps_are_found_by_name_or_id_and_ambiguous_names_are_refused`](../crates/sam-storage/src/lib.rs#L738) | Apps are found by name or ID, and an ambiguous name is refused. | ✅ |
| [`nested_items_keep_their_text`](../crates/sam-gtk/src/guide.rs#L351) | The user guide keeps the text of a list item that has a nested list below it. | ✅ |
| [`links_to_other_pages_open_on_github`](../crates/sam-gtk/src/guide.rs#L375) | Links in the guide to other documentation pages open on GitHub, since relative file names lead nowhere inside the window (regression: the link to "Terminal programs" pointed to security.md and did nothing). | ✅ |

**Code:** [`sam-gtk/src/window.rs`](../crates/sam-gtk/src/window.rs), [`sam-gtk/src/pages.rs`](../crates/sam-gtk/src/pages.rs), [`sam-core/src/model.rs`](../crates/sam-core/src/model.rs), [`sam-storage/src/lib.rs`](../crates/sam-storage/src/lib.rs)

**Also tried by:** [`tests/gui/session.sh`](../tests/gui/session.sh)

<a id="36"></a>
### 36. The Permission Manager, for one app or several, with tags in the same colors everywhere.

| Test | Promise | Result |
|---|---|---|
| [`a_strict_window_app_has_no_tags`](../crates/sam-profile/src/tags.rs#L163) | An app with SAM's strictest window profile shows no tags, because it has nothing beyond the basics. | ✅ |
| [`tags_follow_the_family_order_and_mark_read_only`](../crates/sam-profile/src/tags.rs#L173) | Tags appear in the family order Network, Files, Devices, Desktop, and read-only access is marked. | ✅ |
| [`dangerous_access_is_red_and_filtered_bus_has_no_tag`](../crates/sam-profile/src/tags.rs#L209) | Dangerous access gets red tags, and the filtered desktop bus, which every app has, gets none. | ✅ |
| [`tags_and_the_risk_list_use_the_same_words`](../crates/sam-profile/src/tags.rs#L262) | One name per permission: where the risk list names a permission that also has a tag, both use the same words (regression: "Audio" vs "Sound", "GPU" vs "GPU acceleration", "Show in folder"). | ✅ |
| [`the_overview_lists_every_sandboxed_app_with_tags_and_states`](../crates/sam-runner/tests/groups.rs#L134) | The Permissions overview lists every sandboxed app with its tags and states. | ✅ |
| [`group_switches_offer_only_valid_values`](../crates/sam-gtk/src/all_perms.rs#L1323) | The group switches offer only permissions and values SAM accepts (`sam-jail group set` would refuse anything else), and each value of a permission appears once. | ✅ |
| [`shift_click_selects_the_apps_between_two_clicks`](../crates/sam-gtk/src/all_perms.rs#L1356) | Shift-click selects every app between the app clicked before and the app clicked now, in either direction; without an earlier click, only the app clicked now. | ✅ |
| [`a_tag_filter_cycles_through_has_has_not_and_off`](../crates/sam-gtk/src/all_perms.rs#L1371) | A tag filter cycles through three states with each click: only apps with the permission, only apps without it, and off. | ✅ |
| [`the_list_shows_only_apps_that_pass_every_filter`](../crates/sam-gtk/src/all_perms.rs#L1380) | The list shows an app only when it passes every filter at once: the search text, each state filter, and each tag filter in its state. | ✅ |
| [`the_style_sheet_handler_is_connected_before_register`](../crates/sam-gtk/src/main.rs#L600) ⟲ | Regression: the "startup" handler that loads SAM's style sheet was connected after `register()`, which emits "startup" for the first instance at once. | ✅ |
| [`a_new_icon_marks_its_folders_as_changed`](../crates/sam-gtk/src/main.rs#L548) | A new icon is noticed by the desktop's icon caches: the folders from the icon up to the theme are marked as changed, also when an earlier version had replaced the icon in place; once they are newer than the icon, nothing is touched again (regression: the taskbar kept SAM's old icon). | 🆕 new |
| [`every_color_in_use_has_a_style_rule`](../crates/sam-gtk/src/main.rs#L614) | Every color SAM's window uses has a style rule: the badge tones in the code, the three risk levels of tags and badges, and the outline. | ✅ |

**Code:** [`sam-gtk/src/all_perms.rs`](../crates/sam-gtk/src/all_perms.rs), [`sam-gtk/src/perms.rs`](../crates/sam-gtk/src/perms.rs), [`sam-profile/src/tags.rs`](../crates/sam-profile/src/tags.rs), [`sam-gtk/src/main.rs`](../crates/sam-gtk/src/main.rs)

**Also tried by:** [`tests/gui/permissions-atspi.sh`](../tests/gui/permissions-atspi.sh)

<a id="37"></a>
### 37. SAM speaks English, German, Spanish and French: every text in the window and every message from SAM's core. You can choose SAM's language in the main menu; apps keep the system's.

| Test | Promise | Result |
|---|---|---|
| [`texts_without_a_translation_come_back_with_their_values`](../crates/sam-core/src/i18n.rs#L193) | Texts without a translation come back with their values. | ✅ |
| [`the_command_line_speaks_german_when_asked`](../crates/sam-jail-cli/tests/language.rs#L18) | The command line speaks german when asked. | ✅ |
| [`every_translated_language_can_be_chosen`](../crates/sam-core/src/i18n.rs#L179) | Without a translation, texts come back as written, placeholders are filled in by name (so a translation may reorder them), and the plural form follows the number. | 🆕 new |
| [`the_language_is_the_system_or_one_sam_speaks`](../crates/sam-core/src/config.rs#L462) | The window's language is empty (follow the system) or one of the languages SAM speaks; anything else is refused, and a wrong value in the file is reset to the system's language. | 🆕 new |
| [`the_chosen_language_and_the_systems_are_kept_apart`](../crates/sam-gtk/src/i18n.rs#L90) | Choosing a language sets it for the window and remembers the system's; going back to the system restores exactly what it had, also after several restarts. | 🆕 new |
| [`apps_keep_the_system_language_whatever_sams_window_shows`](../crates/sam-sandbox/src/lib.rs#L2370) | An app started from SAM's window keeps the system's language, even when the window itself shows another one. | 🆕 new |

**Code:** [`sam-core/src/i18n.rs`](../crates/sam-core/src/i18n.rs), [`sam-gtk/src/i18n.rs`](../crates/sam-gtk/src/i18n.rs), [`scripts/i18n.py`](../scripts/i18n.py), [`po/de.po`](../po/de.po), [`po/es.po`](../po/es.po), [`po/fr.po`](../po/fr.po)

**Also tried by:** [`tests/gui/flow-atspi.sh`](../tests/gui/flow-atspi.sh), [`scripts/i18n.py`](../scripts/i18n.py)

<a id="40"></a>
### 40. The window can be used with the keyboard alone and with a screen reader: every control has a name it can say and takes keyboard focus.

**Code:** [`sam-gtk/src/window.rs`](../crates/sam-gtk/src/window.rs), [`sam-gtk/src/app_page/mod.rs`](../crates/sam-gtk/src/app_page/mod.rs), [`sam-gtk/src/all_perms.rs`](../crates/sam-gtk/src/all_perms.rs), [`sam-gtk/src/guide.rs`](../crates/sam-gtk/src/guide.rs)

**Also tried by:** [`tests/gui/a11y-atspi.sh`](../tests/gui/a11y-atspi.sh)

## I. Foundations

<a id="38"></a>
### 38. SAM's own files survive: files from older versions are migrated, files from newer versions stay untouched, and damaged files are moved aside without stopping SAM.

| Test | Promise | Result |
|---|---|---|
| [`a_complete_configuration_file_loads_every_setting`](../crates/sam-core/src/config.rs#L409) | A complete configuration file with every section loads without loss. | ✅ |
| [`settings_change_by_key_and_old_theme_names_are_migrated`](../crates/sam-core/src/config.rs#L488) | Settings can be changed by key, and old theme names are migrated to Light, Dark or System. | ✅ |
| [`files_from_a_newer_sam_are_never_overwritten`](../crates/sam-core/src/format.rs#L102) | SAM refuses to overwrite a file written by a newer SAM and reads files without a format number as format 0. | ✅ |
| [`access_from_bool_and_str`](../crates/sam-core/src/permissions.rs#L1058) | Folder access is read from both the old form (true/false) and the current form ("ro", "rw"). | ✅ |
| [`old_profiles_with_removed_options_still_load`](../crates/sam-core/src/permissions.rs#L1108) | Settings saved with options SAM no longer has still load, with the removed options mapped to their safe meaning. | ✅ |
| [`permissions_saved_as_toml_load_back_unchanged`](../crates/sam-core/src/permissions.rs#L1123) | Permissions saved as TOML load back unchanged. | ✅ |
| [`old_extra_backend_args_still_load`](../crates/sam-core/src/permissions.rs#L1136) | Raw sandbox arguments saved under their old name still load. | ✅ |
| [`presets_in_the_older_flat_format_still_load`](../crates/sam-storage/src/lib.rs#L766) | Presets in the older flat format still load. | ✅ |
| [`old_formats_are_migrated_and_kept`](../crates/sam-jail-cli/tests/robustness.rs#L65) | Files from older SAM versions are migrated to the current format, and the originals are kept. | ✅ |
| [`newer_formats_are_left_untouched`](../crates/sam-jail-cli/tests/robustness.rs#L105) | Files from a newer SAM are never changed by an older one. | ✅ |
| [`damaged_files_are_moved_aside_and_reported`](../crates/sam-jail-cli/tests/robustness.rs#L150) | Damaged files are moved aside and reported, and SAM carries on. | ✅ |
| [`mangled_files_never_crash`](../crates/sam-jail-cli/tests/robustness.rs#L201) | Mangled files never make SAM crash. | ✅ |

**Code:** [`sam-core/src/format.rs`](../crates/sam-core/src/format.rs), [`sam-core/src/config.rs`](../crates/sam-core/src/config.rs), [`sam-core/src/permissions.rs`](../crates/sam-core/src/permissions.rs), [`sam-storage/src/lib.rs`](../crates/sam-storage/src/lib.rs)

**Also tried by:** [`tests/upgrade/run.sh`](../tests/upgrade/run.sh)

<a id="39"></a>
### 39. SAM's parts stay cleanly separated: the window reaches the core only through the command line and decides by codes, never by reading messages, and the parts that handle untrusted content never depend on the higher ones.

*An internal guarantee: it keeps SAM maintainable and is not a feature users see.*

| Test | Promise | Result |
|---|---|---|
| [`times_are_shown_without_a_date_library`](../crates/sam-core/src/util.rs#L269) | Times are shown without a date library: UTC dates exactly, local times in the computer's own zone and shape (chrono was dropped when it became unmaintained, RUSTSEC-2026-0543). | 🆕 new |
| [`the_permission_model_depends_on_no_other_part`](../crates/sam-jail-cli/tests/architecture.rs#L59) | The permission model is the base: it depends on no other SAM part, so every other part can use it without creating a cycle. | ✅ |
| [`the_window_reaches_sam_only_through_the_command_line`](../crates/sam-jail-cli/tests/architecture.rs#L67) | The window contains no sandbox logic: it depends only on the permission model and reaches everything else through `sam-jail --json`, so the window and the command line always behave the same. | ✅ |
| [`lower_parts_never_depend_on_higher_ones`](../crates/sam-jail-cli/tests/architecture.rs#L75) | The parts that handle untrusted AppImage content or build the sandbox depend only on the parts below them, never on the operations layer, the command line or the window. | ✅ |
| [`the_sandbox_builder_depends_only_on_the_permission_model`](../crates/sam-jail-cli/tests/architecture.rs#L98) | The sandbox command builder depends only on the permission model, so what it builds follows from the permissions alone. | ✅ |
| [`the_component_diagram_shows_the_real_dependencies`](../crates/sam-jail-cli/tests/architecture.rs#L105) | The component diagram in docs/architecture.md shows exactly the real dependencies between the parts: no arrow is missing and none is invented. | ✅ |
| [`diagram_labels_are_quoted_so_github_draws_them`](../crates/sam-jail-cli/tests/architecture.rs#L155) | Every box and arrow label in the documents' diagrams is quoted, so GitHub draws them: unquoted brackets or semicolons inside a label are a parse error there (the component diagram once failed that way). | ✅ |
| [`version_reports_the_json_interface`](../crates/sam-jail-cli/tests/robustness.rs#L240) | `sam-jail version` answers with the JSON interface version even when the configuration cannot be read. | ✅ |
| [`an_error_code_survives_added_context`](../crates/sam-core/src/error.rs#L137) | An error code survives added context. | ✅ |
| [`a_required_run_does_not_skip`](../crates/sam-runner/src/contracts.rs#L640) | Where a run must prove everything (CI), a skip is an error; locally it is a note. | 🆕 new |
| [`a_failing_section_is_named_and_the_next_still_runs`](../crates/sam-runner/src/contracts.rs#L619) | A failing section is named and the next still runs. | 🆕 new |
| [`a_skipped_test_is_recorded_with_its_reason`](../crates/sam-runner/src/contracts.rs#L537) | A skipped test is written to the skip log with its name and reason, one line each, so a run can report it instead of passing it silently. | 🆕 new |
| [`tests_find_the_helper_of_their_own_build`](../crates/sam-runner/src/lib.rs#L120) | A test program inside Cargo's build folder finds the helper of its own build, so tests that need it run instead of skipping; an installed program never looks above its own folder. | 🆕 new |
| [`a_build_never_takes_a_helper_from_path`](../crates/sam-runner/src/lib.rs#L96) | A program of a Cargo build whose helper is not built gets none, even when one is on PATH (an installed SAM or another build): the test then says it cannot run, instead of checking a different version. | 🆕 new |
| [`rooted_paths_have_a_runtime_folder_of_their_own`](../crates/sam-core/src/paths.rs#L172) | Rooted paths (tests) keep their runtime folders apart from SAM's real one and from every other root, and short enough for SAM's sockets. | 🆕 new |
| [`an_error_names_its_sam_function_and_keeps_its_message`](../crates/sam-core/src/error.rs#L113) | The code of an error survives being wrapped in context, so the window recognizes it whatever language the message is in. | 🆕 new |

**Code:** [`sam-jail-cli/tests/architecture.rs`](../crates/sam-jail-cli/tests/architecture.rs), [`docs/architecture.md`](../docs/architecture.md)

✅ passed in the newest version report · ❌ failed there · 🆕 new: added after that report, so it has no result yet (every test passes before it is committed; the next report fills it in) · ⟲ a regression test: it guards against a bug that really happened.
