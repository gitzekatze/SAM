# SAM's functions and their proofs

> **What this page is:** every function SAM promises, with the tests that
> prove it, the code that carries it, and the scripted checks that try it on
> real apps or in the window. A test may prove several functions. The page
> is generated from [functions.toml](functions.toml) by
> `scripts/function-map.py`; CI checks that every test belongs to a function
> and every function has a test or a stated gap.
>
> Test results are from the newest version report (2026-11-17 16:10:22).

**40 functions:** 11 proven by passing tests, 28 with new tests not yet in a report, 0 with a failing test, 1 by scripted checks, 0 with a gap, 473 tests in all.

| | Function | Components | Tests | Result |
|---|---|---|---|---|
| 1 | [SAM finds AppImages in the folders you choose and shows them, sandboxed or not, without running anything.](#1) | sam-gtk, sam-runner, sam-intake | 8 | ✅ 🆕 3 new tests since the report |
| 2 | [SAM recognizes the AppImage formats in use today (type 2 with a SquashFS or DwarFS image; the old, rare type 1 is unpacked with bsdtar but not tested) and refuses files that aren't AppImages, or are for the wrong processor, with a clear message.](#2) | sam-runner, sam-intake, sam-detect | 9 | ✅ |
| 3 | [SAM unpacks an AppImage safely: without running it, inside a sandbox, with limits on size, number of files and time, and with a check of free disk space.](#3) | sam-runner, sam-intake | 30 | ✅ 🆕 11 new tests since the report |
| 4 | [SAM reads the name, icon, description and update source from the app itself, and removes markup or control characters before showing them.](#4) | sam-intake, sam-core | 10 | ✅ 🆕 4 new tests since the report |
| 5 | [A damaged or hostile AppImage can't crash SAM or stop the list.](#5) | sam-intake, sam-detect | 11 | ✅ 🆕 4 new tests since the report |
| 6 | [SAM recommends permissions from what the app is (window app, terminal tool, game, browser and so on), starting as strict as possible.](#6) | sam-detect, sam-profile | 16 | ✅ |
| 7 | [SAM explains every permission in plain language and shows how risky it is.](#7) | sam-gtk, sam-core | 18 | ✅ 🆕 8 new tests since the report |
| 8 | [You can change permissions per app, for several apps at once, or through your own presets.](#8) | sam-runner, sam-profile, sam-storage, sam-core | 24 | ✅ 🆕 6 new tests since the report |
| 9 | [Things an app printed can never grant it access on their own; SAM always asks.](#9) | sam-runner | 3 | ✅ 🆕 1 new test since the report |
| 10 | [The app sees only a private home folder and the folders you grant.](#10) | sam-sandbox | 11 | ✅ 🆕 2 new tests since the report |
| 11 | [Keys, passwords and the files of your other apps stay hidden, even with full home access.](#11) | sam-sandbox, sam-core | 13 | ✅ 🆕 5 new tests since the report |
| 12 | [Network: none, "This computer only" (selected ports), or full.](#12) | sam-runner, sam-sandbox | 8 | ✅ 🆕 3 new tests since the report |
| 13 | [The app reaches only allowed desktop services (a filtered D-Bus) and can't start programs outside its sandbox.](#13) | sam-runner, sam-sandbox, sam-core | 32 | ✅ 🆕 17 new tests since the report |
| 14 | [Display: Wayland with a security context; X11 only when allowed, with its cost explained.](#14) | sam-runner, sam-sandbox, sam-core | 4 | ✅ 🆕 1 new test since the report |
| 15 | [Sound, GPU, camera and game controllers only when allowed.](#15) | sam-sandbox | 11 | ✅ 🆕 7 new tests since the report |
| 16 | [The app can't make itself start later outside the sandbox (autostart, shell startup files, menu entries).](#16) | sam-runner, sam-sandbox | 18 | ✅ 🆕 9 new tests since the report |
| 17 | [The app can't type into your terminal.](#17) | sam-runner, sam-sandbox | 44 | ✅ 🆕 29 new tests since the report |
| 18 | [Optional: a writable app folder (changes go to a separate layer); where that's impossible, a read-only start with an explanation.](#18) | sam-runner, sam-sandbox, sam-core | 4 | ✅ |
| 19 | [Starting from SAM's window, from the menu, or from the terminal always goes through the sandbox.](#19) | sam-runner, sam-intake, sam-core | 21 | ✅ 🆕 11 new tests since the report |
| 20 | [SAM checks from inside the sandbox that every setting applies (the sandbox check).](#20) | sam-runner | 13 | ✅ 🆕 3 new tests since the report |
| 21 | [A second start, closing, and stopping work cleanly and leave nothing behind.](#21) | sam-runner, sam-core | 8 | ✅ 🆕 2 new tests since the report |
| 22 | [Logs of every start are kept, with old ones removed automatically.](#22) | sam-runner, sam-storage | 3 | ✅ |
| 23 | [After a failed start, SAM says what went wrong and offers a fix with one click.](#23) | sam-gtk, sam-runner | 7 | ✅ 🆕 2 new tests since the report |
| 24 | [Repair steps go from mild to strong, and each one can be undone.](#24) | sam-runner, sam-sandbox | 14 | ✅ 🆕 7 new tests since the report |
| 25 | [The diagnose run finds missing files and suggests only what helps.](#25) | sam-runner | 9 | ✅ |
| 26 | [Compatibility mode as a last resort, with its cost explained, and it can be undone.](#26) | sam-runner | 3 | ✅ 🆕 1 new test since the report |
| 27 | [SAM notices app settings that something else changed and asks before starting the app.](#27) | sam-runner, sam-storage | 4 | ✅ 🆕 2 new tests since the report |
| 28 | [Updates use HTTPS only, keep the old version so it can be restored, and refuse a changed signing key until you accept it.](#28) | sam-runner, sam-detect | 39 | ✅ 🆕 18 new tests since the report |
| 29 | [SAM notices AppImages that were moved or changed.](#29) | sam-runner, sam-intake | 6 | ✅ 🆕 2 new tests since the report |
| 30 | [Removing an app deletes only SAM's own folders, never your files.](#30) | sam-runner, sam-storage, sam-core | 6 | ✅ |
| 31 | [Disk space per app, and freeing space.](#31) | sam-runner | 1 | ✅ |
| 32 | [Uninstalling SAM removes everything it created and brings back menu entries it hid.](#32) | sam-runner, sam-intake | 2 | ✅ |
| 33 | [The doctor check finds problems with the system or an app.](#33) | sam-runner, sam-core | 15 | ✅ 🆕 4 new tests since the report |
| 34 | [Privacy: SAM sends nothing on its own, and a bug report never contains your name, home path, addresses or secrets.](#34) | sam-runner | 8 | ✅ 🆕 2 new tests since the report |
| 35 | [The overview of all apps, with clear status badges.](#35) | sam-gtk, sam-storage, sam-core | 5 | ✅ |
| 36 | [The Permission Manager, for one app or several, with tags in the same colors everywhere.](#36) | sam-gtk, sam-profile | 12 | ✅ |
| 37 | [SAM speaks English, German, Spanish and French: every text in the window and every message from SAM's core. You can choose SAM's language in the main menu; apps keep the system's.](#37) | sam-gtk, sam-core | 6 | ✅ |
| 40 | [The window can be used with the keyboard alone and with a screen reader: every control has a name it can say and takes keyboard focus.](#40) | sam-gtk | 0 | scripted check |
| 38 | [SAM's own files survive: files from older versions are migrated, files from newer versions stay untouched, and damaged files are moved aside without stopping SAM.](#38) | sam-storage, sam-core | 13 | ✅ 🆕 1 new test since the report |
| 39 | [SAM's parts stay cleanly separated: the window reaches the core only through the command line and decides by codes, never by reading messages, and the parts that handle untrusted content never depend on the higher ones.](#39) | sam-jail-cli | 18 | ✅ 🆕 2 new tests since the report |

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
| [`peeks_name_and_icon_without_extracting`](../crates/sam-intake/src/peek.rs#L264) | The name and icon of an AppImage are read without unpacking or running it. | ✅ |
| [`the_appimage_behind_a_foreign_menu_entry_is_found`](../crates/sam-intake/src/menu.rs#L295) | The AppImage a foreign menu entry starts is found in its Exec line, also behind env and with quotes. | ✅ |
| [`app_ids_stay_unique_when_names_collide`](../crates/sam-intake/src/id.rs#L98) | App IDs are stable and unique, also when two AppImages have the same name. | ✅ |
| [`found_appimages_get_a_menu_entry_only_with_a_sandbox`](../crates/sam-runner/tests/overview.rs#L13) | AppImages are listed before they have a sandbox; only creating the sandbox adds SAM's menu entry and hides unsandboxed ones, and removing it puts them back. | ✅ |
| [`the_folder_watcher_ignores_hidden_files_and_unfinished_downloads`](../crates/sam-gtk/src/window.rs#L1931) | The folder watcher reacts to AppImages and ignores hidden files and downloads in progress. | ✅ |
| [`a_reader_gone_wrong_comes_to_nothing`](../crates/sam-intake/tests/preview_sandbox.rs#L50) | A reader gone wrong comes to nothing. | 🆕 new |
| [`the_overview_reads_names_inside_a_sandbox`](../crates/sam-jail-cli/tests/odd_names.rs#L252) | The overview reads an AppImage's name inside the preview sandbox, not in SAM's own process (audit I-F7): a recording stand-in in front of the real Bubblewrap sees the reader start, and the name still arrives. | 🆕 new |
| [`dropped_pipes_and_icon_bombs_never_reach_gtk`](../crates/sam-gtk/src/window.rs#L1887) | A named pipe dropped on the window is no AppImage, and checking it does not block the window until something writes to it (audit G-F16). | 🆕 new |

**Code:** [`sam-intake/src/peek.rs`](../crates/sam-intake/src/peek.rs), [`sam-intake/src/menu.rs`](../crates/sam-intake/src/menu.rs), [`sam-intake/src/id.rs`](../crates/sam-intake/src/id.rs), [`sam-runner/src/ops/overview.rs`](../crates/sam-runner/src/ops/overview.rs), [`sam-gtk/src/window.rs`](../crates/sam-gtk/src/window.rs)

<a id="2"></a>
### 2. SAM recognizes the AppImage formats in use today (type 2 with a SquashFS or DwarFS image; the old, rare type 1 is unpacked with bsdtar but not tested) and refuses files that aren't AppImages, or are for the wrong processor, with a clear message.

| Test | Promise | Result |
|---|---|---|
| [`plain_elf_is_not_appimage`](../crates/sam-detect/src/appimage.rs#L395) | An ordinary program file is not taken for an AppImage. | ✅ |
| [`a_type_2_appimage_is_recognized`](../crates/sam-detect/src/appimage.rs#L403) | A type 2 AppImage (ELF with the AppImage magic and a squashfs image) is recognized. | ✅ |
| [`an_appimage_with_a_dwarfs_image_is_recognized`](../crates/sam-detect/src/appimage.rs#L468) | An AppImage with a DwarFS image instead of squashfs is recognized. | ✅ |
| [`a_file_that_is_no_program_is_not_an_appimage`](../crates/sam-detect/src/appimage.rs#L489) | A file that is not an ELF program is not taken for an AppImage. | ✅ |
| [`appimages_run_only_on_a_matching_processor`](../crates/sam-detect/src/appimage.rs#L504) | An AppImage runs on the same processor and 32-bit builds on their 64-bit relatives; ARM builds never run on x86-64 or the other way. | ✅ |
| [`appimages_with_every_compression_unpack`](../crates/sam-intake/src/testkit.rs#L257) | Every SquashFS compression AppImages use is unpacked by the built-in reader, so none needs the AppImage's own extractor. | ✅ |
| [`an_appimage_for_another_processor_gets_no_sandbox`](../crates/sam-runner/tests/wrong_processor.rs#L14) | An AppImage for ARM is refused on an x86-64 computer with a sentence that names both processors and what to download instead, and nothing is stored (regression: SAM created a sandbox for an arm64 Neovim and failed only at the start, with "permission denied or wrong format"). | ✅ |
| [`an_appimage_shorter_than_its_image_is_incomplete`](../crates/sam-detect/src/appimage.rs#L431) | A download that broke off is recognized: the file is shorter than its SquashFS image says, and a complete one is not. | ✅ |
| [`a_download_that_broke_off_is_refused_and_nothing_is_kept`](../crates/sam-runner/tests/incomplete.rs#L9) | A download that broke off is refused and nothing is kept. | ✅ |

**Code:** [`sam-detect/src/appimage.rs`](../crates/sam-detect/src/appimage.rs), [`sam-intake/src/extract.rs`](../crates/sam-intake/src/extract.rs), [`sam-runner/src/ops/add.rs`](../crates/sam-runner/src/ops/add.rs)

**Also tried by:** [`tests/real-apps/run.sh`](../tests/real-apps/run.sh)

<a id="3"></a>
### 3. SAM unpacks an AppImage safely: without running it, inside a sandbox, with limits on size, number of files and time, and with a check of free disk space.

| Test | Promise | Result |
|---|---|---|
| [`an_appimages_own_extractor_cannot_open_the_kernels_rarely_used_doors`](../crates/sam-runner/tests/kernel_surface.rs#L228) | The AppImage's own extractor runs code from the AppImage: here a "runtime" that probes the doors when asked to unpack itself, after SAM's own reader failed on it and the person allowed the fallback. | 🆕 new |
| [`the_self_unpack_question_names_the_sandbox_and_the_reason`](../crates/sam-intake/src/extract.rs#L867) | The question before the AppImage unpacks itself says what the sandbox holds back, including the kernel limits (audit I-F17: it named only the network and the files), and why SAM could not. | 🆕 new |
| [`an_unpacking_tool_cannot_open_the_kernels_rarely_used_doors`](../crates/sam-runner/tests/kernel_surface.rs#L153) | An unpacking tool cannot open the kernels rarely used doors. | 🆕 new |
| [`unpacking_refuses_to_start_without_enough_free_space`](../crates/sam-intake/src/extract.rs#L909) | Unpacking does not start when the folder clearly has too little room; the message names the folder, both sizes, and where to choose another folder. | ✅ |
| [`a_full_disk_during_unpacking_is_recognized`](../crates/sam-intake/src/extract.rs#L940) | A full disk during unpacking is recognized, also inside an error chain, so SAM can clean up and say what happened. | ✅ |
| [`unpacking_stops_at_the_time_limit`](../crates/sam-intake/src/normalize.rs#L215) | Unpacking stops with a clear error when it takes longer than the time limit, so a huge or hostile AppImage cannot keep SAM busy forever. | ✅ |
| [`symlinks_pointing_outside_the_app_are_recognized`](../crates/sam-intake/src/normalize.rs#L229) | A symlink that points outside the unpacked app is recognized. | ✅ |
| [`paths_climbing_out_of_the_image_are_refused`](../crates/sam-intake/src/normalize.rs#L242) | Paths from the AppImage image are made relative, and paths that climb out with .. | ✅ |
| [`unpacking_removes_setuid_bits`](../crates/sam-intake/src/normalize.rs#L253) | Unpacking removes setuid bits and makes files read-only for others. | ✅ |
| [`unpacking_stops_at_the_file_limit`](../crates/sam-intake/src/normalize.rs#L310) | Unpacking stops when the AppImage contains more files than the limit. | ✅ |
| [`a_built_appimage_is_detected_and_unpacked_safely`](../crates/sam-intake/src/testkit.rs#L288) | A built AppImage is recognized and unpacked, with setuid bits removed. | ✅ |
| [`size_limit_aborts_and_cleans_up`](../crates/sam-intake/src/testkit.rs#L347) | Unpacking stops at the size limit and leaves no partial files behind. | ✅ |
| [`fractions_follow_the_step_weights`](../crates/sam-runner/src/progress.rs#L152) | The progress bar follows the weights of the steps of creating a sandbox. | ✅ |
| [`bytes_written_are_counted`](../crates/sam-runner/src/progress.rs#L177) | Unpacking progress counts the bytes written. | ✅ |
| [`unpacking_stops_exactly_at_its_limits`](../crates/sam-intake/tests/limits.rs#L45) | The file-count and size limits let an app through that reaches them exactly and stop one entry or one byte more; a time limit of zero stops at once. | ✅ |
| [`only_an_exceeded_limit_counts_as_one`](../crates/sam-intake/src/extract.rs#L950) | Only an exceeded limit counts as one: other errors are not explained as a limit the user could raise. | ✅ |
| [`without_consent_the_appimages_own_unpacker_never_runs`](../crates/sam-intake/tests/damaged.rs#L25) | When SAM's own readers cannot unpack an AppImage, its own unpacker (code from the AppImage) runs only after the user agreed: without consent the unpacking stops and asks, and nothing of the AppImage runs. | ✅ |
| [`a_menu_start_after_free_space_unpacks_inside_a_sandbox`](../crates/sam-jail-cli/tests/unpack.rs#L104) | A menu start after free space unpacks inside a sandbox. | ✅ |
| [`without_the_command_line_a_menu_start_refuses_to_unpack`](../crates/sam-jail-cli/tests/unpack.rs#L127) | Without the command line a menu start refuses to unpack. | ✅ |
| [`sams_programs_never_unpack_without_a_sandbox`](../crates/sam-runner/src/ops/overview.rs#L518) | Sams programs never unpack without a sandbox. | ✅ |
| [`a_hostile_unpacking_tool_cannot_plant_links_in_sams_app_folder`](../crates/sam-intake/tests/hostile_extractor.rs#L32) | A hostile unpacking tool cannot plant links in sams app folder. | 🆕 new |
| [`files_sam_writes_never_go_through_a_planted_link`](../crates/sam-core/src/util.rs#L552) | SAM's own files in folders an untrusted program could have touched are written without following links: a planted link is replaced, the file it pointed to stays as it was, and a link in place of a folder becomes a real folder (audit I-F2). | 🆕 new |
| [`the_icon_is_cached_and_never_written_through_a_link`](../crates/sam-intake/src/metadata.rs#L325) | The app's icon is copied for SAM's menu entry and next to the unpacked app, replacing an older icon of another format, and never written through a link planted in the app's folder (audit I-F2). | 🆕 new |
| [`an_unpacking_limit_inside_the_sandbox_stops_unpacking`](../crates/sam-jail-cli/tests/unpack.rs#L169) ⟲ | Unpacking limits hold inside the unpack sandbox too. | 🆕 new |
| [`a_named_pipe_is_refused_without_waiting`](../crates/sam-core/src/util.rs#L525) | Reading a file from an untrusted app returns at once for anything that is not a regular file: a named pipe made SAM wait forever (audit I-F9, I-F15). | 🆕 new |
| [`the_entry_from_exec_stays_inside_the_app`](../crates/sam-runner/src/ops/add.rs#L505) | An app without AppRun starts the program its menu entry names, found inside the app; a name that points outside it is never used. | 🆕 new |
| [`a_shared_unpack_folder_keeps_everything_that_is_not_sams`](../crates/sam-runner/src/ops/maintain.rs#L1077) | The unpack location can be any folder, for example `~/Documents`. | 🆕 new |
| [`a_menu_start_unpacks_in_a_sandbox_with_the_cli_next_to_it`](../crates/sam-runner/src/ops/overview.rs#L490) | A menu start unpacks in a sandbox with the cli next to it. | ✅ |
| [`tests_and_benchmarks_may_unpack_in_their_own_process`](../crates/sam-runner/src/ops/overview.rs#L540) | Tests and benchmarks may unpack in their own process. | ✅ |
| [`two_unpacks_at_once_get_their_own_error_files`](../crates/sam-intake/src/extract.rs#L889) | Error files opened at the same moment in one process are separate files: an unpack running beside another no longer fails with "File exists" (it did on CI when two tests unpacked at once). | 🆕 new |

**Code:** [`sam-intake/src/extract.rs`](../crates/sam-intake/src/extract.rs), [`sam-intake/src/normalize.rs`](../crates/sam-intake/src/normalize.rs), [`sam-runner/src/progress.rs`](../crates/sam-runner/src/progress.rs)

<a id="4"></a>
### 4. SAM reads the name, icon, description and update source from the app itself, and removes markup or control characters before showing them.

| Test | Promise | Result |
|---|---|---|
| [`the_desktop_file_inside_an_appimage_is_read`](../crates/sam-intake/src/metadata.rs#L291) | The desktop file inside an AppImage is read with name, translations, categories and file types. | ✅ |
| [`reads_metadata_and_icon`](../crates/sam-intake/src/metadata.rs#L304) | Name, icon and categories are read from the unpacked app. | ✅ |
| [`a_readable_name_is_taken_from_the_file_name`](../crates/sam-intake/src/id.rs#L81) | A readable name is taken from an AppImage's file name, without version and architecture. | ✅ |
| [`icon_paths_cannot_climb_out_of_the_app`](../crates/sam-intake/src/peek.rs#L278) | Icon paths from the AppImage cannot climb out of the unpacked app. | ✅ |
| [`neutralizes_markup_and_controls`](../crates/sam-core/src/util.rs#L785) | Text from an app is shown without markup or control characters, and long text is shortened. | ✅ |
| [`markup_in_metadata_is_neutralized`](../crates/sam-runner/tests/adversarial.rs#L95) | H3: markup in an AppImage's name or comment is neutralized before it is stored or shown. | ✅ |
| [`only_icons_that_are_safe_to_decode_are_taken`](../crates/sam-core/src/icon.rs#L85) | Only icons that are safe to decode reach the desktop's image code: a PNG whose header announces more than 1024×1024 pixels (a decode bomb: a small file that asks for gigabytes) is refused before anything decodes it, and so are oversized files, large SVGs and XPM (audit G-F8, I-F18). | 🆕 new |
| [`preview_and_unpack_take_the_same_desktop_file`](../crates/sam-intake/src/metadata.rs#L265) | The preview and the unpacked app take the same desktop file: the top folder before `usr/share/applications`, each by name, and the first that leads to a file (audit I-F8: the preview gave up at a broken first one, the unpack took the next). | 🆕 new |
| [`changed_desktop_files_never_crash_the_reader`](../crates/sam-runner/tests/fuzz_targets.rs#L335) | Desktop files with a byte order mark, Windows line ends, odd sections and broken text are read without a panic, and the byte order mark and line ends do not hide the name. | 🆕 new |
| [`a_byte_order_mark_does_not_hide_the_desktop_entry`](../crates/sam-intake/src/metadata.rs#L254) | A desktop file that starts with a byte order mark keeps its keys (found by fuzzing: the mark hid the `[Desktop Entry]` line). | 🆕 new |

**Code:** [`sam-intake/src/metadata.rs`](../crates/sam-intake/src/metadata.rs), [`sam-intake/src/peek.rs`](../crates/sam-intake/src/peek.rs), [`sam-intake/src/id.rs`](../crates/sam-intake/src/id.rs), [`sam-core/src/util.rs`](../crates/sam-core/src/util.rs)

<a id="5"></a>
### 5. A damaged or hostile AppImage can't crash SAM or stop the list.

| Test | Promise | Result |
|---|---|---|
| [`reading_a_file_of_an_appimage_is_bounded`](../crates/sam-core/src/util.rs#L683) | A link to a device that never ends, or a file larger than the limit, cannot fill SAM's memory (regression: an AppImage whose AppRun links to /dev/zero made adding it grow without end). | ✅ |
| [`a_damaged_squashfs_image_gives_an_error_instead_of_a_crash`](../crates/sam-intake/tests/damaged.rs#L15) ⟲ | Regression: reading the name and icon of an AppImage whose SquashFS image makes the reader panic gives an error instead of crashing SAM. | ✅ |
| [`parsers_survive_garbage`](../crates/sam-runner/tests/adversarial.rs#L132) | Robustness: malformed desktop files and files that only look like AppImages must not crash the parsers (simple deterministic fuzzing). | ✅ |
| [`changed_appimages_never_crash_or_escape_the_unpacker`](../crates/sam-runner/tests/fuzz.rs#L141) | Changed AppImages are recognized or refused, and unpacked or refused, without a panic; unpacking writes only inside its own folder and keeps its time limit. | ✅ |
| [`changed_text_inputs_never_crash_the_parsers`](../crates/sam-runner/tests/fuzz.rs#L223) | Changed desktop files, zsync files and update information are parsed or refused without a panic. | ✅ |
| [`changed_programs_never_crash_the_analysis`](../crates/sam-runner/tests/fuzz.rs#L255) | Changed ELF programs inside an unpacked app are analyzed or skipped without a panic. | ✅ |
| [`one_damaged_appimage_does_not_stop_the_list`](../crates/sam-jail-cli/tests/interface.rs#L289) ⟲ | Regression (found by the fuzzer): one damaged AppImage in a searched folder made `sam-jail discover` crash, so the window's list stayed empty. | ✅ |
| [`changed_signature_and_update_sections_never_crash_the_readers`](../crates/sam-runner/tests/fuzz_targets.rs#L117) | Changed ELF section tables and signature, key and update sections are read or refused without a panic: inspect, the signature check and the update information. | 🆕 new |
| [`the_preview_reader_panics_only_inside_the_squashfs_library`](../crates/sam-runner/tests/fuzz_targets.rs#L391) | The preview reader without its guard: a changed image must not make SAM's own code panic. | 🆕 new |
| [`impossible_header_values_give_no_elf_end`](../crates/sam-detect/src/appimage.rs#L340) | Header values that point past the end of every file give no ELF end, never an overflow: with overflow checks in release builds (audit P16) that would end SAM (audit I-F14, found again by fuzzing). | 🆕 new |
| [`a_dwarfs_image_after_the_elf_part_is_dwarfs`](../crates/sam-detect/src/appimage.rs#L374) | A DwarFS image right after the ELF part is taken as DwarFS, not as SquashFS: the SquashFS check looks for its own magic there. | 🆕 new |

**Code:** [`sam-intake/src/peek.rs`](../crates/sam-intake/src/peek.rs), [`sam-intake/src/extract.rs`](../crates/sam-intake/src/extract.rs), [`sam-detect/src/elf.rs`](../crates/sam-detect/src/elf.rs)

## B. Choosing the right permissions

<a id="6"></a>
### 6. SAM recommends permissions from what the app is (window app, terminal tool, game, browser and so on), starting as strict as possible.

| Test | Promise | Result |
|---|---|---|
| [`a_development_tool_gets_no_project_folder_on_its_own_word`](../crates/sam-profile/src/lib.rs#L855) | An app that calls itself a development tool gets Documents, but no writable project folder: the category is the AppImage's own claim, and a project folder lets an app plant code that runs outside the sandbox (git hooks, .envrc). | ✅ |
| [`terminal_programs_get_no_display`](../crates/sam-profile/src/lib.rs#L828) | Terminal programs get no display, GPU or desktop bus access. | ✅ |
| [`the_app_category_is_recognized_from_its_desktop_categories`](../crates/sam-profile/src/lib.rs#L885) | The category of an app is recognized from its desktop categories. | ✅ |
| [`recommendations_fit_the_category`](../crates/sam-profile/src/lib.rs#L950) | Recommended permissions fit the category: a browser gets the network and Downloads, an editor no network. | ✅ |
| [`what_sam_finds_in_the_app_adjusts_the_recommendation`](../crates/sam-profile/src/lib.rs#L965) | What SAM finds in the app (GPU, X11-only toolkit) adjusts the recommendation. | ✅ |
| [`bundled_libraries_are_sorted_by_what_they_reach`](../crates/sam-detect/src/classify.rs#L262) | Bundled libraries are sorted into system, graphics, display-controlled and dangerous classes. | ✅ |
| [`programs_that_load_graphics_at_run_time`](../crates/sam-detect/src/elf.rs#L1221) | Programs that load graphics libraries only at run time are recognized as needing the GPU. | ✅ |
| [`missing_optional_libraries_name_the_feature`](../crates/sam-detect/src/elf.rs#L1247) | A missing optional library is reported with the feature it provides, not as a broken app. | ✅ |
| [`programs_that_choose_the_qt_platform`](../crates/sam-detect/src/elf.rs#L1334) | Programs that choose the Qt platform themselves (X11 or Wayland) are recognized. | ✅ |
| [`qt_wayland_plugin_needs_its_client_library`](../crates/sam-detect/src/elf.rs#L1355) | A bundled Qt Wayland plugin counts as usable only when its Wayland client library is present. | ✅ |
| [`start_scripts_that_force_x11`](../crates/sam-detect/src/elf.rs#L1369) | Start scripts that force X11 are recognized, so SAM grants X11 to those apps. | ✅ |
| [`the_program_behind_a_start_script_is_found`](../crates/sam-detect/src/elf.rs#L1439) | When the AppImage starts through a shell script, SAM finds the program the script starts. | ✅ |
| [`an_appimage_asking_for_admin_rights_is_unsafe_to_sandbox`](../crates/sam-detect/src/elf.rs#L1461) | An AppImage that asks for administrator rights (pkexec) is marked as unsafe to sandbox. | ✅ |
| [`electron_markers_and_bundled_symlinks`](../crates/sam-detect/src/elf.rs#L1469) | Electron apps are recognized by their markers, and bundled library symlinks are followed. | ✅ |
| [`origin_relative_needed_paths`](../crates/sam-detect/src/elf.rs#L1482) | Libraries an app finds relative to its own folder ($ORIGIN) are counted as bundled, not as missing. | ✅ |
| [`the_c_library_version_an_app_needs_is_read`](../crates/sam-detect/src/elf.rs#L1498) | The C library version an app needs is read from its symbol versions. | ✅ |

**Code:** [`sam-profile/src/lib.rs`](../crates/sam-profile/src/lib.rs), [`sam-detect/src/elf.rs`](../crates/sam-detect/src/elf.rs), [`sam-detect/src/classify.rs`](../crates/sam-detect/src/classify.rs)

**Also tried by:** [`tests/real-apps/run.sh`](../tests/real-apps/run.sh)

<a id="7"></a>
### 7. SAM explains every permission in plain language and shows how risky it is.

| Test | Promise | Result |
|---|---|---|
| [`the_strictest_window_profile_is_low_risk`](../crates/sam-core/src/risk.rs#L923) | SAM's strictest window profile counts as low risk. | ✅ |
| [`full_home_is_dangerous`](../crates/sam-core/src/risk.rs#L930) | Full home access counts as dangerous, and as think twice when it is read-only. | ✅ |
| [`network_and_x11_high`](../crates/sam-core/src/risk.rs#L940) | Full network together with X11 makes the settings think twice (high risk). | ✅ |
| [`each_dangerous_setting_produces_its_warning`](../crates/sam-core/src/warnings.rs#L303) | Dangerous settings (X11, full home, system bus, network an app does not need) each produce a warning. | ✅ |
| [`strict_has_no_danger`](../crates/sam-core/src/warnings.rs#L325) | SAM's strictest window profile produces no danger warning. | ✅ |
| [`x11_warning_can_be_disabled`](../crates/sam-core/src/warnings.rs#L332) | The X11 warning disappears when the user turns it off in the preferences. | ✅ |
| [`tags_and_the_risk_list_use_the_same_words`](../crates/sam-profile/src/tags.rs#L262) | One name per permission: where the risk list names a permission that also has a tag, both use the same words (regression: "Audio" vs "Sound", "GPU" vs "GPU acceleration", "Show in folder"). | ✅ |
| [`folder_explanations_name_the_path`](../crates/sam-gtk/src/all_perms.rs#L1494) | Personal folders explain where they are; other permissions keep their description unchanged. | ✅ |
| [`risk_has_the_same_three_words_everywhere`](../crates/sam-core/src/risk.rs#L764) | The command line and the window name risk with the same three words, and the command line's filter understands both names. | ✅ |
| [`the_full_session_bus_is_rated_dangerous`](../crates/sam-core/src/risk.rs#L911) | The full session bus reaches systemd, which can start programs outside the sandbox, so it is rated like allowing systemd by name. | ✅ |
| [`every_switch_has_one_risk_word`](../crates/sam-core/src/risk.rs#L700) | Every switch says the same risk word in the window (its catalogue entry) as in the risk assessment that decides the badges and which changes ask first (audit D-M12: raw ALSA was "Think twice" in one and "Dangerous" in the other, so the window did not ask). | 🆕 new |
| [`switching_a_protection_off_counts`](../crates/sam-core/src/risk.rs#L830) | Settings that take a protection away count in the risk word, and a secret passed through counts more than an ordinary variable (audit D-H4). | 🆕 new |
| [`reading_and_sending_together_is_dangerous`](../crates/sam-core/src/risk.rs#L876) | The network together with your home, keys or passwords is Dangerous: each alone is Think twice, but together the app can send what it reads (audit U-M10). | 🆕 new |
| [`the_catalogue_names_every_setting`](../crates/sam-core/src/permissions.rs#L1108) | The catalogue is the one list of permissions: it names every setting an app's permissions have, and every name in it can be read. | 🆕 new |
| [`the_documentation_names_every_permission`](../crates/sam-core/src/permissions.rs#L1151) | The permissions page of the documentation names every permission. | 🆕 new |
| [`the_editor_shows_every_permission`](../crates/sam-gtk/src/perms.rs#L1276) | The editor (the app's page and the Permission Manager for one app) shows every permission in the catalogue, the one list of permissions (audit G-F14: the lists drifted; a setting was missing here). | 🆕 new |
| [`info_shows_every_permission_with_its_value`](../crates/sam-jail-cli/src/output.rs#L313) | `info` shows every permission of the catalogue with its value, also the ones it left out before (audit G-F14). | 🆕 new |
| [`info_on_the_terminal_shows_every_permission_once`](../crates/sam-jail-cli/tests/exit_codes.rs#L167) | `sam-jail info` shows every permission with its value, each group of permissions under one heading (audit G-F14). | 🆕 new |

**Code:** [`sam-core/src/permissions.rs`](../crates/sam-core/src/permissions.rs), [`sam-core/src/risk.rs`](../crates/sam-core/src/risk.rs), [`sam-core/src/warnings.rs`](../crates/sam-core/src/warnings.rs), [`sam-gtk/src/all_perms.rs`](../crates/sam-gtk/src/all_perms.rs)

<a id="8"></a>
### 8. You can change permissions per app, for several apps at once, or through your own presets.

| Test | Promise | Result |
|---|---|---|
| [`set_and_get_keys`](../crates/sam-core/src/permissions.rs#L1256) | Permissions can be read and set by key, and unknown keys or values are refused. | ✅ |
| [`change_check_flags_removals_and_additions`](../crates/sam-profile/src/lib.rs#L1011) | The change check names what an app would lose that it needs, and the dangerous access it would gain. | ✅ |
| [`folders_are_not_breakage_but_lost_local_network_and_bus_are`](../crates/sam-profile/src/lib.rs#L1075) | A hidden folder is not a reason to warn that an app stops working: it is listed apart (regression for the group warning, which only interrupts for breakage). | ✅ |
| [`lost_sound_is_named_sound`](../crates/sam-profile/src/lib.rs#L1105) | An app that needs sound is warned about in the switch's word. | ✅ |
| [`preset_template_is_strict`](../crates/sam-profile/src/lib.rs#L1123) | A new preset starts without home, network or system bus access. | ✅ |
| [`user_changes_survive_better_recommendation`](../crates/sam-runner/src/ops/mod.rs#L531) | When SAM's recommendation improves, the user's own changes are kept. | ✅ |
| [`a_dry_run_changes_nothing_and_names_what_would_stop_working`](../crates/sam-runner/tests/groups.rs#L56) | A dry run of a group change saves nothing and names what each app would lose. | ✅ |
| [`only_changed_apps_are_saved_and_one_undo_restores_all_of_them`](../crates/sam-runner/tests/groups.rs#L82) | A group change saves only the apps whose value changes, and one undo restores all of them. | ✅ |
| [`an_invalid_value_or_unknown_app_changes_no_app`](../crates/sam-runner/tests/groups.rs#L118) | A group change with an invalid value or an unknown app changes no app. | ✅ |
| [`sam_ships_no_presets_and_old_built_in_names_are_free_for_the_user`](../crates/sam-runner/tests/groups.rs#L157) | SAM ships no presets; old built-in names are free for the user, and applying a preset asks before it removes something an app needs. | ✅ |
| [`saving_an_apps_settings_as_a_preset_keeps_them_exactly`](../crates/sam-runner/tests/groups.rs#L193) | Saving an app's settings as a preset keeps them exactly. | ✅ |
| [`reset_to_recommendation_brings_back_the_recommended_settings`](../crates/sam-runner/tests/settings.rs#L147) | "Reset to recommendation" brings back SAM's recommended settings and turns compatibility mode off. | ✅ |
| [`preset_names_cannot_place_files_outside_the_presets_folder`](../crates/sam-storage/src/lib.rs#L781) | A preset is always stored inside the presets folder, whatever its name: names like "../../evil" or "/etc/x" (typed, or from an imported file) cannot place a file elsewhere. | ✅ |
| [`a_saved_preset_loads_back_unchanged`](../crates/sam-storage/src/lib.rs#L920) | A saved preset loads back unchanged, found by its name in any letter case. | ✅ |
| [`group_list_set_and_restore_round_trip`](../crates/sam-jail-cli/tests/interface.rs#L79) | The JSON interface lists apps with their tags, changes a permission for several apps, and restores them with the returned "previous" object. | ✅ |
| [`group_set_refuses_bad_input_without_changing_anything`](../crates/sam-jail-cli/tests/interface.rs#L236) | A group change with an invalid value, an unknown key or no app is refused, and no app changes. | ✅ |
| [`presets_are_the_users_own_only`](../crates/sam-jail-cli/tests/interface.rs#L259) | The command line lists only the user's own presets; the template is strict, and saved presets carry no built-in flag. | ✅ |
| [`each_permission_adds_exactly_its_part_to_the_command`](../crates/sam-sandbox/src/lib.rs#L2678) | Each granted permission adds exactly its part to the Bubblewrap command. | ✅ |
| [`only_new_or_higher_serious_risks_ask`](../crates/sam-core/src/risk.rs#L778) | The one ask rule: a change asks when it adds something rated Think twice or Dangerous that was not there, or raises it; taking a risk away, keeping it, or adding something harmless does not ask (audit G-F2). | 🆕 new |
| [`a_change_from_an_old_copy_keeps_what_changed_meanwhile`](../crates/sam-profile/src/lib.rs#L790) | A change made on an old copy applies only what it changed: another setting changed meanwhile stays; the same setting changed elsewhere to another value is named, not overwritten (audit G-F4). | 🆕 new |
| [`a_change_from_the_window_keeps_changes_made_elsewhere`](../crates/sam-jail-cli/tests/interface.rs#L208) | `profile change` applies only what differs between "from" and "to", as the window sends it: a change made elsewhere since the window loaded the settings stays (audit G-F4). | 🆕 new |
| [`undo_takes_back_only_its_own_change`](../crates/sam-jail-cli/tests/interface.rs#L158) | Undo takes back only its own change: a change made to an app since stays, and a later change to the same setting refuses the whole undo instead of being overwritten (audit G-F4: the whole sets from before were written back). | 🆕 new |
| [`a_preset_not_applied_ends_with_not_passed`](../crates/sam-jail-cli/tests/exit_codes.rs#L210) | A preset that is not applied (it needs a confirmation) ends with 3 and still says what it would change; applied, it ends with 0. | 🆕 new |
| [`presets_keep_their_own_files_and_any_name`](../crates/sam-jail-cli/tests/odd_names.rs#L173) | Two presets whose names share a file ("My Preset" and "my-preset") never overwrite each other without a word (audit G-F19), and a preset called `-x` is a name like any other when it comes after `--`, as the window passes it (G-F20). | 🆕 new |

**Code:** [`sam-core/src/permissions.rs`](../crates/sam-core/src/permissions.rs), [`sam-profile/src/lib.rs`](../crates/sam-profile/src/lib.rs), [`sam-runner/src/ops/profiles.rs`](../crates/sam-runner/src/ops/profiles.rs), [`sam-storage/src/lib.rs`](../crates/sam-storage/src/lib.rs)

**Also tried by:** [`tests/gui/permissions-atspi.sh`](../tests/gui/permissions-atspi.sh)

<a id="9"></a>
### 9. Things an app printed can never grant it access on their own; SAM always asks.

| Test | Promise | Result |
|---|---|---|
| [`app_output_cannot_buy_dangerous_grants`](../crates/sam-runner/tests/adversarial.rs#L74) | H2/M4: suggestions derived from app output never grant escape-capable services or protected folders, and are always marked as app-derived. | ✅ |
| [`a_forged_trace_line_cannot_widen_a_low_risk_grant`](../crates/sam-runner/src/diagnose.rs#L534) | A forged trace line cannot widen a low-risk grant: paths with ".." are ignored, and a grant is only ever a real folder of shared system data, never a parent such as /usr. | ✅ |
| [`an_app_nobody_has_confirmed_does_not_start`](../crates/sam-jail-cli/tests/start_check.rs#L118) | An app added on the command line without `--accept` has settings nobody has confirmed: SAM chose them partly from what the app says about itself (its name and description pick its category, and with it the network). | 🆕 new |

**Code:** [`sam-runner/src/repair.rs`](../crates/sam-runner/src/repair.rs)

## C. The sandbox

<a id="10"></a>
### 10. The app sees only a private home folder and the folders you grant.

| Test | Promise | Result |
|---|---|---|
| [`links_in_etc_never_bring_sockets_or_devices`](../crates/sam-sandbox/src/lib.rs#L2327) | A link in /etc never brings a socket or a device into the sandbox, wherever it points; plain files and folders of the system's data and settings do, and in /run only plain files (regression: Debian's `/etc/alternatives/php-fpm.sock` showed the PHP server's socket). | 🆕 new |
| [`a_user_folder_that_shows_more_is_not_shown`](../crates/sam-sandbox/src/lib.rs#L3520) | A user folder set to the root, the folder above the home, a link to it, a key folder or SAM's folder is never shown; a usual one is, at its real place with a link where the app looks (audit S-F11). | 🆕 new |
| [`a_writable_folder_stays_writable_in_a_read_only_home`](../crates/sam-sandbox/src/lib.rs#L2294) | With the home read-only, a folder set to read/write stays writable; one set to read-only adds nothing (the home shows it read-only). | ✅ |
| [`the_strictest_profile_shares_nothing_and_keeps_the_app_read_only`](../crates/sam-sandbox/src/lib.rs#L2571) | The strictest profile builds a sandbox without network, environment or capabilities, with the app read-only. | ✅ |
| [`files_and_folders_named_on_the_command_line`](../crates/sam-sandbox/src/lib.rs#L2495) | Files and folders named when starting an app are passed in, but never sensitive folders like autostart. | ✅ |
| [`the_loaders_extra_library_folders_are_shown_read_only`](../crates/sam-sandbox/src/lib.rs#L2455) | Extra library folders of the system loader (for example CUDA) are visible to the app read-only. | ✅ |
| [`each_permission_adds_exactly_its_part_to_the_command`](../crates/sam-sandbox/src/lib.rs#L2678) | Each granted permission adds exactly its part to the Bubblewrap command. | ✅ |
| [`a_real_sandbox_shows_exactly_what_each_profile_allows`](../crates/sam-runner/tests/sandbox.rs#L63) | Inside a real sandbox, each profile shows exactly the files and services it allows. | ✅ |
| [`each_permission_grants_exactly_its_access_in_a_real_sandbox`](../crates/sam-runner/tests/matrix.rs#L102) | Inside a real sandbox, each permission grants exactly its access and nothing more. | ✅ |
| [`only_proper_variable_names_are_set`](../crates/sam-sandbox/src/lib.rs#L3734) | Only proper variable names are set inside the sandbox, and no value with a NUL byte. | ✅ |
| [`user_folders_come_from_user_dirs_dirs`](../crates/sam-core/src/host.rs#L754) | The user folders come from user-dirs.dirs, with the usual names as fallbacks; a folder set to $HOME is disabled (contract xdg-folders). | ✅ |

**Code:** [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs)

<a id="11"></a>
### 11. Keys, passwords and the files of your other apps stay hidden, even with full home access.

| Test | Promise | Result |
|---|---|---|
| [`a_grant_inside_sams_folder_does_not_show_it`](../crates/sam-sandbox/src/lib.rs#L3448) | SAM's folder is hidden also when a grant shows only something inside it (audit S-F13): the grant does not reach SAM's files. | 🆕 new |
| [`opened_files_are_judged_by_name_and_by_where_they_lead`](../crates/sam-sandbox/src/lib.rs#L3469) | Files named on the command line are judged with the home as named and as reached (a home under a link), by the name they are given (a file reached through `~/.config` is not shared), and a file a grant already shows is not added again. | 🆕 new |
| [`keys_start_places_and_sams_files_are_never_opened`](../crates/sam-sandbox/src/lib.rs#L3398) | Keys, credential stores, start places (also behind a link) and SAM's own files named on the command line are never shared, whatever the home is called; an ordinary file is, and so is a folder that only holds SAM's folder (SAM's folder is hidden inside it) (audit D-M2, S-F13). | 🆕 new |
| [`start_places_and_credential_stores_count_as_sensitive`](../crates/sam-core/src/risk.rs#L964) | Every start place and credential store the sandbox locks or hides counts as sensitive, under any home; a drive under /run/media does not, though /run does (audit D-M2, D-M3). | 🆕 new |
| [`grants_of_parts_of_the_home_never_reach_start_places_or_secrets`](../crates/sam-runner/tests/home_grants.rs#L62) | Grants of parts of the home never reach start places or secrets. | 🆕 new |
| [`sams_own_folders_stay_hidden_inside_an_opened_folder`](../crates/sam-sandbox/src/lib.rs#L3622) | SAM's own folders stay hidden inside a folder opened with the app, and inside a runner's bind, at the path the bind shows them under. | ✅ |
| [`key_and_system_folders_count_as_sensitive`](../crates/sam-core/src/risk.rs#L951) | Paths that hold keys or the whole system (~/.ssh, /etc, /) are recognized as sensitive; ordinary folders are not. | ✅ |
| [`every_breakout_attempt_from_a_real_sandbox_fails`](../crates/sam-runner/tests/breakout.rs#L152) | Every security promise holds inside a real sandbox: each breakout attempt fails. | ✅ |
| [`every_hostile_appimage_fails_to_escape`](../crates/sam-runner/tests/evil.rs#L159) | Every hostile AppImage, added and started like any other, fails to get out of its sandbox: it cannot read keys, SAM's settings or another app's files; cannot write autostart entries, shell startup files or host temporary files; cannot type into the terminal, reach the network when it has none, see host processes or change its own app folder; cannot reach systemd, the Flatpak spawn portal, the keyring or a launcher service, nor take over a portal's name on the desktop bus; and a symlink or setuid bit in its image gains it nothing. | ✅ |
| [`credential_files_and_folders_in_the_home_are_masked`](../crates/sam-sandbox/src/lib.rs#L3688) | With the whole home granted, credential files are replaced by an empty file and credential folders by an empty folder. | ✅ |
| [`home_protection_is_prepared_only_for_a_writable_home`](../crates/sam-sandbox/src/lib.rs#L3715) | Protected folders are created in the real home only before a start that can write the home, never otherwise. | ✅ |
| [`sams_own_folders_stay_hidden_inside_a_granted_folder`](../crates/sam-sandbox/src/lib.rs#L3326) | SAM's own folders stay hidden when a granted folder contains them, and nothing extra is added when no grant shows them. | ✅ |
| [`user_folder_locations_stay_read_only_with_a_writable_home`](../crates/sam-sandbox/src/lib.rs#L3656) | With the home writable, the file that says where the user folders are stays read-only, so an app cannot point other apps' Documents or Downloads grant at another folder. | ✅ |

**Code:** [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs), [`sam-core/src/risk.rs`](../crates/sam-core/src/risk.rs)

<a id="12"></a>
### 12. Network: none, "This computer only" (selected ports), or full.

| Test | Promise | Result |
|---|---|---|
| [`localhost_network_leaves_netns_to_pasta`](../crates/sam-sandbox/src/lib.rs#L2858) | With "this computer only", the network namespace is left to pasta. | ✅ |
| [`only_listed_host_ports`](../crates/sam-runner/src/netns.rs#L184) | With "this computer only", the app reaches only the ports on this computer the user lists. | ✅ |
| [`the_apps_ports_listen_on_loopback_only`](../crates/sam-runner/src/netns.rs#L204) | The app's ports are offered on this computer's loopback addresses only, for IPv4 and IPv6 alike, never on every address (audit L-F7). | 🆕 new |
| [`well_known_local_services_are_never_taken_over`](../crates/sam-runner/src/netns.rs#L232) | Local services whose clients would hand an app control or secrets are never taken over automatically. | 🆕 new |
| [`the_apps_ports_are_offered_on_this_computer_only`](../crates/sam-jail-cli/tests/local_network.rs#L106) | The apps ports are offered on this computer only. | 🆕 new |
| [`each_permission_grants_exactly_its_access_in_a_real_sandbox`](../crates/sam-runner/tests/matrix.rs#L102) | Inside a real sandbox, each permission grants exactly its access and nothing more. | ✅ |
| [`a_pasta_command_ending_in_the_separator_is_refused_not_a_panic`](../crates/sam-runner/src/launch.rs#L1885) | A pasta command ending in the separator is refused not a panic. | ✅ |
| [`the_status_shell_goes_between_the_separator_and_the_program`](../crates/sam-runner/src/launch.rs#L1892) | The status shell goes between the separator and the program. | ✅ |

**Code:** [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs), [`sam-runner/src/netns.rs`](../crates/sam-runner/src/netns.rs)

<a id="13"></a>
### 13. The app reaches only allowed desktop services (a filtered D-Bus) and can't start programs outside its sandbox.

| Test | Promise | Result |
|---|---|---|
| [`only_a_32_bit_start_program_switches_the_filter_off`](../crates/sam-profile/src/lib.rs#L985) | The syscall filter is switched off only for an app whose start program is 32-bit itself: 32-bit files next to a script that starts a 64-bit program do not switch it off (audit M5/I-F4). | 🆕 new |
| [`links_to_other_programs_ask_first`](../crates/sam-sandbox/src/lib.rs#L3351) | Links leave the sandbox through the portal: web and mail links go to the person's browser or mail program as asked; any other kind (`steam://`, `vscode://`, a program's own scheme) makes the portal ask first with its app chooser, so an app cannot start another program by a link (audit L-F14). | 🆕 new |
| [`the_link_portal_check_finds_the_ask_option`](../crates/sam-runner/src/contracts.rs#L670) | The link portal's ask option is found in its description, and its absence is reported (stand-in descriptions; the real one is checked by `sam-jail doctor --contracts` and on CI). | 🆕 new |
| [`function_and_signal_rules_count_in_the_risk_word`](../crates/sam-core/src/risk.rs#L738) | Single functions and signals of a service count in the risk word: a function of a service that can act outside the sandbox is Dangerous, any other function Think twice, a signal Harmless (audit D-H2: they counted for nothing). | 🆕 new |
| [`a_change_that_adds_a_service_function_asks_first`](../crates/sam-profile/src/lib.rs#L1049) | A preset (or any change) that adds a function of a service asks first, as one that adds the X11 display does (audit D-H2: a preset with "may call systemd" applied without a question). | 🆕 new |
| [`bus_names_follow_the_rules_of_the_bus`](../crates/sam-core/src/permissions.rs#L1184) | An app may not own a bus name of a desktop service or of a service that starts on demand; its own application names stay allowed. | 🆕 new |
| [`media_controls_talk_but_ask_for_no_wildcard_name`](../crates/sam-core/src/permissions.rs#L1207) | Media controls let the app talk to the screen saver and power services; they no longer ask for the media-player wildcard, which was always refused (audit L-Q1): the app's own player name is learned instead. | 🆕 new |
| [`wanted_names_are_kept_once_and_at_most_eight`](../crates/sam-runner/src/dbus_proxy.rs#L232) | A name is kept once, and no more than eight in all. | 🆕 new |
| [`an_app_gets_the_name_it_asks_for_only_when_nobody_uses_it`](../crates/sam-runner/tests/own_names.rs#L46) | An app gets the name it asks for only when nobody uses it. | 🆕 new |
| [`a_name_is_allowed_only_when_nobody_else_has_it`](../crates/sam-runner/src/own_names.rs#L190) | A name the app asks for is refused when it belongs to an installed app (audit D-M6: a terminal's name runs host commands), to a desktop protocol, to an on-demand service (also through a wildcard, L-F13), or to another app in SAM; its own name passes; a media player's name passes with the media switch (L-Q1). | 🆕 new |
| [`menu_ids_are_the_file_names`](../crates/sam-runner/src/own_names.rs#L232) | Menu entry ids come from file names, subfolders joined with `-`; only `.desktop` files count. | 🆕 new |
| [`the_proxy_record_names_what_the_app_wanted_to_own`](../crates/sam-runner/src/dbus_proxy.rs#L215) | Only the proxy's "wants to own" lines name a name to learn, and only a well-formed one (what the app printed never reaches this). | 🆕 new |
| [`the_apps_own_words_never_give_it_a_bus_name`](../crates/sam-runner/src/repair.rs#L904) | What the app prints never gets it a bus name, whatever name it claims it needs (a terminal's name runs host commands; audit D-M6): names come only from the D-Bus filter's record (`own_names`). | 🆕 new |
| [`the_filter_refuses_x32_odd_sockets_and_the_siblings`](../crates/sam-runner/src/kernel.rs#L613) | The filter, applied by the real kernel in a child process: every call through the x32 ABI is refused (audit S-F9; x32 `ptrace` has its own number), the siblings of blocked calls are blocked too (S-F10), and a socket opens only as local, internet or netlink, Bluetooth only with its switch (S-F7). | 🆕 new |
| [`the_filter_reaches_bubblewrap_as_whole_instructions`](../crates/sam-runner/src/kernel.rs#L674) | Bubblewrap reads the filter as eight bytes per instruction. | 🆕 new |
| [`an_app_cannot_open_the_kernels_rarely_used_doors`](../crates/sam-runner/tests/kernel_surface.rs#L104) | An app cannot open the kernels rarely used doors. | 🆕 new |
| [`own_names_that_are_refused`](../crates/sam-core/src/permissions.rs#L1228) | Own names that are refused. | ✅ |
| [`blocked_names_win_over_wildcards`](../crates/sam-core/src/permissions.rs#L1275) | A bus name the user blocks stays blocked even when a wildcard in the allowed list would match it. | ✅ |
| [`only_real_socket_paths_are_taken_from_a_dbus_address`](../crates/sam-core/src/host.rs#L797) | Only real socket paths are taken from a D-Bus address; abstract sockets are not. | ✅ |
| [`own_names_from_the_id_and_the_window_class`](../crates/sam-profile/src/lib.rs#L1146) | The bus names an app may own come from its application ID and window class, never from protocol or desktop-service names. | ✅ |
| [`filtered_dbus_uses_proxy`](../crates/sam-sandbox/src/lib.rs#L2729) | The filtered desktop bus reaches the app only through SAM's proxy. | ✅ |
| [`the_app_runs_as_the_user_and_host_tools_are_replaced_by_stand_ins`](../crates/sam-sandbox/src/lib.rs#L2813) | The app runs as the user and host tools are replaced by stand ins. | ✅ |
| [`without_nested_namespaces_user_namespaces_are_disabled`](../crates/sam-sandbox/src/lib.rs#L2891) | Without nested namespaces, the sandbox disables user namespaces and starts through SAM's helper. | ✅ |
| [`extra_sockets_must_be_sockets`](../crates/sam-sandbox/src/lib.rs#L2947) | Extra sockets are passed in only when they really are sockets. | ✅ |
| [`tray_names_follow_watcher_permission`](../crates/sam-runner/src/dbus_proxy.rs#L247) | An app may register a tray icon only while the tray service is allowed. | ✅ |
| [`the_syscall_filter_compiles_and_blocks_mount_and_io_uring`](../crates/sam-runner/src/kernel.rs#L685) | The syscall filter compiles in every variant and always blocks mount and io_uring. | ✅ |
| [`every_breakout_attempt_from_a_real_sandbox_fails`](../crates/sam-runner/tests/breakout.rs#L152) | Every security promise holds inside a real sandbox: each breakout attempt fails. | ✅ |
| [`every_hostile_appimage_fails_to_escape`](../crates/sam-runner/tests/evil.rs#L159) | Every hostile AppImage, added and started like any other, fails to get out of its sandbox: it cannot read keys, SAM's settings or another app's files; cannot write autostart entries, shell startup files or host temporary files; cannot type into the terminal, reach the network when it has none, see host processes or change its own app folder; cannot reach systemd, the Flatpak spawn portal, the keyring or a launcher service, nor take over a portal's name on the desktop bus; and a symlink or setuid bit in its image gains it nothing. | ✅ |
| [`a_socket_counts_as_ready_only_when_it_accepts`](../crates/sam-runner/src/dbus_proxy.rs#L269) | The proxy counts as ready only when its socket accepts connections, not when the file merely exists (regression: the sandbox check sometimes found the session bus refused right after the start). | ✅ |
| [`only_a_real_socket_counts_as_a_desktop_service`](../crates/sam-core/src/host.rs#L767) | Only a real socket counts as a desktop service. | ✅ |
| [`services_that_start_on_demand_are_recognized`](../crates/sam-core/src/host.rs#L739) | Services that start on demand are recognized from their folders, including the user's own (contract dbus-activatable). | ✅ |
| [`stand_ins_cover_the_real_tool_also_behind_a_link`](../crates/sam-sandbox/src/lib.rs#L2249) | The stand-in for a tool that would start programs outside the sandbox covers the real file, also where the tool is a link (audit S-F14); a tool that is not installed needs none. | 🆕 new |

**Code:** [`sam-runner/src/dbus_proxy.rs`](../crates/sam-runner/src/dbus_proxy.rs), [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs), [`sam-core/src/permissions.rs`](../crates/sam-core/src/permissions.rs), [`sam-runner/src/kernel.rs`](../crates/sam-runner/src/kernel.rs)

<a id="14"></a>
### 14. Display: Wayland with a security context; X11 only when allowed, with its cost explained.

| Test | Promise | Result |
|---|---|---|
| [`wayland_security_context_socket_is_used`](../crates/sam-sandbox/src/lib.rs#L2651) | With a Wayland security context, the app sees only that socket, not the desktop's own. | ✅ |
| [`xauthority_gets_the_sandbox_display_number`](../crates/sam-sandbox/src/lib.rs#L2621) | The X11 login cookie is rewritten for the display number inside the sandbox. | ✅ |
| [`the_x11_display_number_is_read_from_every_display_form`](../crates/sam-core/src/host.rs#L788) | The X11 display number is read from every common DISPLAY form, and remote displays are refused. | ✅ |
| [`the_x11_key_copy_is_private_and_follows_no_link`](../crates/sam-sandbox/src/lib.rs#L2755) | The app runs with the user's IDs, and host tools that could leave the sandbox (systemd-run) are replaced by harmless stand-ins. | 🆕 new |

**Code:** [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs), [`sam-runner/src/wayland_ctx.rs`](../crates/sam-runner/src/wayland_ctx.rs), [`sam-core/src/host.rs`](../crates/sam-core/src/host.rs)

<a id="15"></a>
### 15. Sound, GPU, camera and game controllers only when allowed.

| Test | Promise | Result |
|---|---|---|
| [`a_helper_sees_the_apps_system_and_nothing_else`](../crates/sam-sandbox/src/lib.rs#L2357) | A helper's sandbox (the sound relay) shows the same system as an app's (with the whole /usr), and nothing outside the system's own folders: no home, no runtime folder, no devices. | 🆕 new |
| [`a_hanging_relay_gives_up_and_a_finished_start_ends_its_relay`](../crates/sam-runner/src/sound_relay.rs#L260) | A relay that never opens its socket stops the start's sound within moments instead of holding the start; one that does is stopped, and its socket removed, when the start ends. | 🆕 new |
| [`the_sound_relay_check_needs_pipewire`](../crates/sam-runner/src/contracts.rs#L661) | The relay's quick check says "not here" on a computer without PipeWire, instead of reporting the contract broken. | 🆕 new |
| [`sound_comes_from_the_relay_or_only_when_allowed_from_the_server`](../crates/sam-sandbox/src/lib.rs#L2424) | Sound comes from SAM's relay, never from the sound server's own socket; that one only when the person allowed sound without the relay (audit S-F1). | 🆕 new |
| [`sound_never_loads_code_into_the_sound_server`](../crates/sam-runner/tests/sound_relay.rs#L98) | Sound never loads code into the sound server. | 🆕 new |
| [`the_relay_cannot_load_modules_and_listens_only_on_its_socket`](../crates/sam-runner/src/sound_relay.rs#L224) | The relay's settings switch module loading off, listen only on SAM's socket, take no D-Bus name and load no modules at start; a path cannot break out of its quotes. | 🆕 new |
| [`sound_reaches_the_app_through_the_relay_or_only_when_allowed`](../crates/sam-runner/src/sound_relay.rs#L300) | Sound reaches the app through the relay where PipeWire runs; without PipeWire only when the person allowed sound without the relay. | 🆕 new |
| [`sdl_gets_its_silent_driver_without_sound_access`](../crates/sam-sandbox/src/lib.rs#L2406) | Games built with SDL get a silent sound driver when they have no sound, so they start instead of failing: sound off, or on but with SAM's relay not running (audit S-F1); not when sound reaches them. | ✅ |
| [`gamepads_only_exposes_joysticks`](../crates/sam-sandbox/src/lib.rs#L2915) | "Game controllers" exposes only joysticks, never keyboards or mice. | ✅ |
| [`nvidia_modules_are_exposed_with_the_gpu`](../crates/sam-sandbox/src/lib.rs#L2933) | With the GPU, the NVIDIA driver modules are visible; other kernel modules are not. | ✅ |
| [`each_permission_grants_exactly_its_access_in_a_real_sandbox`](../crates/sam-runner/tests/matrix.rs#L102) | Inside a real sandbox, each permission grants exactly its access and nothing more. | ✅ |

**Code:** [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs)

<a id="16"></a>
### 16. The app can't make itself start later outside the sandbox (autostart, shell startup files, menu entries).

| Test | Promise | Result |
|---|---|---|
| [`grants_of_parts_of_the_home_never_reach_start_places_or_secrets`](../crates/sam-runner/tests/home_grants.rs#L62) | Grants of parts of the home never reach start places or secrets. | 🆕 new |
| [`a_writable_part_of_the_home_holding_start_places_is_watched`](../crates/sam-sandbox/src/lib.rs#L3579) | Only a start that shows a start place writable is watched and prepared: a writable `~/.config` is (audit D-M3), a writable `~/.config/myapp` or Documents folder is not. | 🆕 new |
| [`full_home_access_cannot_leave_anything_that_runs_later`](../crates/sam-runner/tests/full_home.rs#L54) | Full home access cannot leave anything that runs later. | ✅ |
| [`the_home_protections_hold_whatever_else_is_granted`](../crates/sam-runner/tests/home_guards.rs#L45) | The home protections hold whatever else is granted. | 🆕 new |
| [`a_new_start_file_never_stays_silently`](../crates/sam-sandbox/src/lib.rs#L3193) | A new start file is taken out of its place whatever happens, and never silently (audit L-F2): past 1000 earlier copies, into SAM's folder; when SAM's folder cannot take it, renamed in place to a name nothing reads; when nothing works, reported as still there. | 🆕 new |
| [`start_places_follow_other_config_and_data_folders`](../crates/sam-sandbox/src/lib.rs#L3242) | Start folders under another config or data folder in the home (`XDG_CONFIG_HOME`, `XDG_DATA_HOME`) are protected like the usual ones, and the new places are on the list (audit S-F6). | 🆕 new |
| [`a_folder_that_cannot_be_watched_is_reported`](../crates/sam-runner/src/home_live.rs#L232) | A folder Linux will not watch is said, not skipped silently (audit L-F4); what is in it is still moved aside when the app ends. | 🆕 new |
| [`paths_are_resolved_through_links_also_where_they_do_not_exist_yet`](../crates/sam-sandbox/src/lib.rs#L3274) | Paths are resolved through links also where they do not exist yet, the way Bubblewrap and the app see them (audit S-F3). | 🆕 new |
| [`a_path_through_a_link_into_a_grant_is_visible`](../crates/sam-sandbox/src/lib.rs#L3289) | A path that leads into a granted folder through a link counts as visible, and one outside every grant does not (audit S-F3). | 🆕 new |
| [`a_missing_home_folder_stops_the_start`](../crates/sam-sandbox/src/lib.rs#L3305) | Without a real home folder nothing starts: full home access would otherwise bind the whole computer (audit S-F12). | 🆕 new |
| [`only_what_would_run_later_is_moved_aside`](../crates/sam-sandbox/src/lib.rs#L3089) | After a start with a writable home, only what could make the computer run something is moved aside: a new startup file, a replaced link to a protected folder, a key folder the app was not given. | ✅ |
| [`a_new_startup_file_is_moved_aside_while_the_app_runs`](../crates/sam-runner/src/home_live.rs#L184) | A startup file created while the app runs is moved aside at once, not only when the app ends; a removed link is put back at once. | ✅ |
| [`protected_parents_are_locked_and_linked_keys_hidden`](../crates/sam-sandbox/src/lib.rs#L3141) | With a writable home, the folders above protected places are mount points of their own (so they cannot be renamed away), and a key folder that is a link is hidden where it points. | ✅ |
| [`landlock_allows_writing_exactly_in_granted_folders`](../crates/sam-runner/src/kernel.rs#L506) | The Landlock rules allow writing exactly in the folders the permissions grant. | ✅ |
| [`every_breakout_attempt_from_a_real_sandbox_fails`](../crates/sam-runner/tests/breakout.rs#L152) | Every security promise holds inside a real sandbox: each breakout attempt fails. | ✅ |
| [`every_hostile_appimage_fails_to_escape`](../crates/sam-runner/tests/evil.rs#L159) | Every hostile AppImage, added and started like any other, fails to get out of its sandbox: it cannot read keys, SAM's settings or another app's files; cannot write autostart entries, shell startup files or host temporary files; cannot type into the terminal, reach the network when it has none, see host processes or change its own app folder; cannot reach systemd, the Flatpak spawn portal, the keyring or a launcher service, nor take over a portal's name on the desktop bus; and a symlink or setuid bit in its image gains it nothing. | ✅ |
| [`every_known_syscall_has_been_reviewed`](../crates/sam-runner/tests/syscalls.rs#L67) | Every known syscall has been reviewed. | ✅ |
| [`the_review_list_matches_the_filter`](../crates/sam-runner/tests/syscalls.rs#L89) | The review list says what the filter does with each syscall; it must say exactly that, or the review describes a filter that does not exist. | ✅ |

**Code:** [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs), [`sam-runner/src/kernel.rs`](../crates/sam-runner/src/kernel.rs)

<a id="17"></a>
### 17. The app can't type into your terminal.

| Test | Promise | Result |
|---|---|---|
| [`output_shown_in_a_terminal_is_filtered_without_the_relay`](../crates/sam-runner/src/launch.rs#L1942) | With its input redirected an app has no terminal relay; its output shown in a terminal still loses clipboard codes and title reports, even split over two pieces. | ✅ |
| [`a_pipe_into_a_terminal_program_passes_through_unchanged`](../crates/sam-jail-cli/tests/pipes.rs#L28) | A pipe into a terminal program passes through unchanged: the tool reads the piped input, its output arrives byte for byte, and it has no terminal of its own. | 🆕 new |
| [`plain_text_survives_unfinished_and_odd_codes`](../crates/sam-runner/src/pty.rs#L649) | The log's plain text survives every unfinished or odd code: one cut off at the end of the data (no read past it), a title ended by ESC \\ with text after it, a backslash inside a title, and an ESC with intermediate bytes at the very end (found by mutation testing: no test reached these edges). | ✅ |
| [`the_terminal_connection_passes_typing_and_filtered_output`](../crates/sam-runner/tests/terminal_relay.rs#L166) | Typing reaches the app; its output reaches the user filtered (colours pass, a clipboard write does not); the window size is copied at the start and follows a resize; the log and the error head get the text without control codes; the user's terminal is raw while the app runs and gets its settings back afterwards. | 🆕 new |
| [`ctrl_c_reaches_the_app`](../crates/sam-runner/tests/terminal_relay.rs#L234) | Keys reach the app unchanged: Ctrl+C interrupts the app, not SAM. | 🆕 new |
| [`closing_the_users_terminal_hangs_up_the_app`](../crates/sam-runner/tests/terminal_relay.rs#L252) | When the user's terminal closes, SAM hangs up the app's terminal: the app ends, and the end says so. | 🆕 new |
| [`the_log_stays_within_its_limit`](../crates/sam-runner/tests/terminal_relay.rs#L269) | The log keeps at most its limit of terminal output and says so. | 🆕 new |
| [`something_left_on_the_apps_terminal_does_not_keep_sam_waiting`](../crates/sam-runner/tests/terminal_relay.rs#L293) | An app that leaves something running on its terminal (a helper in the background) does not keep SAM waiting once the app itself has ended. | 🆕 new |
| [`the_output_is_still_logged_when_the_terminal_cannot_show_it`](../crates/sam-runner/tests/terminal_relay.rs#L317) | When the user's terminal can no longer show anything (its output is gone), SAM stops writing there but keeps the log, and the app runs to its end. | 🆕 new |
| [`leading_zeros_do_not_smuggle_a_code`](../crates/sam-runner/src/pty.rs#L586) | Leading zeros do not smuggle a code past the filter: terminals read "0052" as 52 and "021" as 21, and so does SAM; a number too long for any real code is removed whole (regression: an 11-digit OSC 52 was cut to 5 and passed on). | ✅ |
| [`a_new_session_unless_the_app_is_on_sams_own_terminal`](../crates/sam-sandbox/src/lib.rs#L2466) | The app gets a new terminal session, unless it runs on SAM's terminal relay. | ✅ |
| [`ordinary_output_passes_unchanged`](../crates/sam-runner/src/pty.rs#L526) | Ordinary terminal output, colors and links pass through the relay unchanged. | ✅ |
| [`clipboard_codes_are_removed`](../crates/sam-runner/src/pty.rs#L564) | Escape codes that read or write the clipboard are removed from an app's terminal output. | ✅ |
| [`title_reports_and_tmux_passthrough_are_removed`](../crates/sam-runner/src/pty.rs#L610) | Escape codes that report the window title or pass through tmux are removed; setting the title stays allowed. | ✅ |
| [`an_escape_inside_a_removed_code_starts_a_new_sequence`](../crates/sam-runner/src/pty.rs#L627) | An escape code hidden inside a removed code cannot slip through. | ✅ |
| [`plain_text_for_the_log`](../crates/sam-runner/src/pty.rs#L636) | Logs get plain text without escape codes. | ✅ |
| [`terminal_apps_get_sams_terminal_relay`](../crates/sam-runner/src/pty.rs#L712) | Apps started from a terminal get SAM's terminal relay; with input from a pipe or a file they get none (input and output pass through), and a terminal program's test start gets a terminal of its own. | ✅ |
| [`typing_and_output_pass_and_leftover_replies_are_discarded`](../crates/sam-runner/src/pty.rs#L751) | A second pseudo-terminal stands in for the user's terminal: SAM's side of it is `Outer`, the test plays the terminal program. | ✅ |
| [`the_app_cannot_reach_the_outer_terminal`](../crates/sam-runner/src/pty.rs#L833) | An app on SAM's terminal relay cannot type into the user's real terminal. | ✅ |
| [`every_hostile_appimage_fails_to_escape`](../crates/sam-runner/tests/evil.rs#L159) | Every hostile AppImage, added and started like any other, fails to get out of its sandbox: it cannot read keys, SAM's settings or another app's files; cannot write autostart entries, shell startup files or host temporary files; cannot type into the terminal, reach the network when it has none, see host processes or change its own app folder; cannot reach systemd, the Flatpak spawn portal, the keyring or a launcher service, nor take over a portal's name on the desktop bus; and a symlink or setuid bit in its image gains it nothing. | ✅ |
| [`a_doubled_escape_does_not_smuggle_a_clipboard_code`](../crates/sam-runner/src/pty.rs#L538) | A doubled ESC in front of a clipboard code does not smuggle it past the filter: the terminal reads the second ESC as the start of the code, so the filter must too. | ✅ |
| [`only_tmux_itself_counts_as_tmux_passthrough`](../crates/sam-runner/src/pty.rs#L674) | Only "tmux;" itself is tmux passthrough: a device control string that merely starts with "t" is not named as one (it is removed as unknown; found by mutation testing). | ✅ |
| [`a_slow_terminals_late_replies_do_not_reach_the_shell`](../crates/sam-runner/src/pty.rs#L875) | A slow terminal that answers requests in a trickle after the app has ended: nothing of it reaches the shell (audit L-F10: one fixed wait of 60 ms let later replies through). | 🆕 new |
| [`limits_hold_at_their_edge`](../crates/sam-core/src/terminal.rs#L1025) | The limits hold exactly: a sequence at the limit is read, one byte more makes it malformed; numbers go up to 65535. | 🆕 new |
| [`malformed_pieces_are_recognized`](../crates/sam-core/src/terminal.rs#L1054) | Malformed strings and sequences: a parameter after an intermediate; BEL ends only title-type strings; control characters, 8-bit controls and invalid UTF-8 inside a string; an ESC inside a string starts a new code that is judged on its own. | 🆕 new |
| [`the_allowed_kinds_pass_unchanged`](../crates/sam-core/src/terminal.rs#L973) | Every kind of harmless sequence on the allow-list passes unchanged, also without the relay. | 🆕 new |
| [`unfinished_pieces_are_named_at_the_end`](../crates/sam-core/src/terminal.rs#L959) | A piece still unfinished when the output ends is removed and named. | 🆕 new |
| [`a_sandboxed_terminal_app_cannot_reach_past_the_terminal`](../crates/sam-jail-cli/tests/terminal.rs#L92) | A sandboxed terminal app cannot reach past the terminal. | 🆕 new |
| [`modes_left_on_are_switched_off_at_the_end`](../crates/sam-core/src/terminal.rs#L917) | Modes the app switched on that would stay on for the shell are switched off at the end (audit L-F11: mouse reporting and bracketed paste stayed on); nothing is added for an app that set none. | 🆕 new |
| [`nothing_past_the_filter_reaches_past_the_terminal`](../crates/sam-core/tests/terminal_fuzz.rs#L440) | Nothing past the filter reaches past the terminal. | 🆕 new |
| [`only_known_device_strings_pass`](../crates/sam-runner/src/pty.rs#L689) | Of the device control strings only the two that ask for the terminal's capabilities and settings pass; tmux passthrough, programmable keys and anything unknown are removed, the text around them stays. | 🆕 new |
| [`ordinary_output_passes_unchanged_at_every_split`](../crates/sam-core/src/terminal.rs#L843) | Ordinary output passes unchanged, also split at every point. | 🆕 new |
| [`requests_pass_only_on_the_relay`](../crates/sam-core/src/terminal.rs#L858) | Requests the terminal answers pass only on SAM's relay, where the answer goes to the app; without it the answer would land in the shell. | 🆕 new |
| [`the_known_ways_past_the_old_filter_are_closed`](../crates/sam-core/src/terminal.rs#L800) | Each way past the old filter that the audit found (L-F1 a–h): none of them brings a clipboard code or a title report to the terminal. | 🆕 new |
| [`the_log_keeps_only_text_across_reads`](../crates/sam-core/src/terminal.rs#L939) | The log keeps only the text, also when a sequence is split across reads (the old one was cut per read and could keep half a code). | 🆕 new |
| [`the_model_recognizes_the_known_attacks`](../crates/sam-core/tests/terminal_fuzz.rs#L514) | The model itself finds what it should: each known way past a filter, read without SAM's filter, counts as dangerous (so a passing fuzz run means something). | 🆕 new |
| [`what_reaches_past_the_terminal_is_removed`](../crates/sam-core/src/terminal.rs#L884) | What reaches past the terminal or changes it for good is removed; unknown codes are removed too (an allow-list). | 🆕 new |
| [`the_screen_keeps_only_text_and_sams_colours`](../crates/sam-core/src/terminal.rs#L1089) | What SAM prints keeps its own colours and loses everything else an app's text could bring: string sequences (clipboard, title), other control sequences (title reports, hidden text), the 8-bit forms, carriage returns that overwrite a line, and direction overrides. | 🆕 new |
| [`plain_text_has_no_hidden_characters`](../crates/sam-core/src/terminal.rs#L1115) | The log and the screen drop the same hidden characters as names do. | 🆕 new |
| [`json_for_the_screen_is_the_same_data`](../crates/sam-core/src/terminal.rs#L1126) | JSON for the terminal is the same data: hidden characters are written as escapes, which every JSON reader turns back into them. | 🆕 new |
| [`names_lose_direction_overrides_and_invisible_characters`](../crates/sam-core/src/util.rs#L796) | Names that would show other than they are lose the characters that do it (audit I-F12): a direction override (`invoice\u{202E}fdp.exe` shows as `invoiceexe.pdf`), invisible spaces and joiners between letters, tag characters, 8-bit control codes. | 🆕 new |
| [`what_sam_prints_about_an_app_cannot_reach_past_the_terminal`](../crates/sam-jail-cli/tests/terminal.rs#L297) | What SAM itself prints about an app (G-F5, L-F3, I-F11, I-F12): the name of its file, the failure summary taken from its error output, its log. | 🆕 new |
| [`every_printed_line_goes_through_the_screen_filter`](../crates/sam-jail-cli/tests/architecture.rs#L268) | Everything SAM prints goes through one place that removes escape codes and hidden characters from it (`sam_core::terminal::for_screen`, audit G-F5): the plain print macros are refused by the code check (clippy.toml), and in SAM's program code only that one file may allow them. | 🆕 new |
| [`an_old_log_shows_only_its_text`](../crates/sam-runner/src/launch.rs#L1780) | A log written before SAM kept only the text, or edited by hand, still shows only text (audit L-F3): `sam-jail logs` and bug reports read it through `tail`. | 🆕 new |

**Code:** [`sam-runner/src/pty.rs`](../crates/sam-runner/src/pty.rs), [`sam-runner/src/kernel.rs`](../crates/sam-runner/src/kernel.rs), [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs)

<a id="18"></a>
### 18. Optional: a writable app folder (changes go to a separate layer); where that's impossible, a read-only start with an explanation.

| Test | Promise | Result |
|---|---|---|
| [`writable_appdir_uses_overlay`](../crates/sam-sandbox/src/lib.rs#L2871) | A writable app folder uses an overlay; the unpacked app itself stays unchanged. | ✅ |
| [`an_app_starts_read_only_when_its_writable_app_folder_cannot_work`](../crates/sam-runner/tests/overlay_fallback.rs#L37) | When the folder for the writable app folder's changes cannot hold an overlay, the app still starts, with a read-only app folder and a warning that says why (regression: on Fedora in a container, SAM's data folder was on an overlay, and the app failed with a raw Bubblewrap error). | ✅ |
| [`a_writable_app_folder_is_offered_only_where_it_can_work`](../crates/sam-runner/src/repair.rs#L1226) | The repair steps offer a writable app folder only where an overlay can work: not where SAM's overlay folder cannot hold one (regression: the step was offered by Bubblewrap's version alone, and on such disks the app then started read-only anyway). | ✅ |
| [`the_app_folder_stays_read_only_unless_writable_is_granted`](../crates/sam-sandbox/src/lib.rs#L3065) | The app's own folder stays read-only unless "writable app folder" is granted, even when SAM has an overlay for it prepared. | ✅ |

**Code:** [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs), [`sam-runner/src/launch.rs`](../crates/sam-runner/src/launch.rs), [`sam-core/src/host.rs`](../crates/sam-core/src/host.rs)

## D. Starting and running

<a id="19"></a>
### 19. Starting from SAM's window, from the menu, or from the terminal always goes through the sandbox.

| Test | Promise | Result |
|---|---|---|
| [`sams_menu_entry_starts_the_app_only_through_sam`](../crates/sam-intake/src/desktop.rs#L417) | SAM's menu entry starts the app through sam-jail-run, never the AppImage directly. | ✅ |
| [`app_metadata_cannot_add_lines_to_sams_menu_entry`](../crates/sam-intake/src/desktop.rs#L319) | SAM's menu entry starts the app only through SAM's sandbox: no value taken from the app (name, comment, categories, file types, window class) can add a line such as a second "Exec=" to it, even from a record changed outside SAM. | ✅ |
| [`menu_entry_paths_are_quoted_against_spaces_and_dollar_signs`](../crates/sam-intake/src/desktop.rs#L354) | Program paths in menu entries are quoted so spaces and dollar signs cannot change the command. | ✅ |
| [`launcher_mime_types_drop_hijack_targets`](../crates/sam-intake/src/desktop.rs#L461) | Launcher mime types drop hijack targets. | ✅ |
| [`launcher_drops_hijack_mime_types`](../crates/sam-runner/tests/adversarial.rs#L114) | M1: a launcher never registers URL schemes, directories or executables. | ✅ |
| [`hide_and_restore_user_entry`](../crates/sam-intake/src/menu.rs#L309) | An unsandboxed menu entry in the user's folder is hidden on request and restored exactly as it was. | ✅ |
| [`system_entry_gets_override`](../crates/sam-intake/src/menu.rs#L353) | An unsandboxed menu entry in a system folder is hidden through an entry in the user's folder, without touching the system file. | ✅ |
| [`found_appimages_get_a_menu_entry_only_with_a_sandbox`](../crates/sam-runner/tests/overview.rs#L13) | AppImages are listed before they have a sandbox; only creating the sandbox adds SAM's menu entry and hides unsandboxed ones, and removing it puts them back. | ✅ |
| [`shell_quoting_keeps_spaces_and_quotes_intact`](../crates/sam-core/src/util.rs#L703) | Shell quoting keeps spaces, quotes and empty strings intact. | ✅ |
| [`the_window_id_matches_the_name_of_sams_menu_entry`](../crates/sam-core/src/paths.rs#L206) ⟲ | Regression: sandboxed windows carried the app's id as their app ID while SAM's menu entry is "sam-<id>.desktop", so the taskbar found no entry and showed a generic icon. | ✅ |
| [`sam_never_runs_a_helper_the_user_can_change`](../crates/sam-jail-cli/tests/trusted_helpers.rs#L61) | Sam never runs a helper the user can change. | 🆕 new |
| [`only_programs_the_user_cannot_change_may_run`](../crates/sam-core/src/util.rs#L734) | SAM runs only programs the user cannot change: one in a folder the user owns is refused, also behind a link, and a link there that leads to a system program is followed to it (audit L-F12). | 🆕 new |
| [`as_root_only_what_no_one_else_can_change_may_run`](../crates/sam-core/src/util.rs#L719) | Run as root, SAM takes a program only where root alone can change it: owned by root, not writable for others, and writable for a group only when that group is root's. | 🆕 new |
| [`menu_entries_name_sams_launcher_by_its_whole_path`](../crates/sam-intake/src/desktop.rs#L368) | A menu entry names SAM's launcher by its whole path, so the desktop never looks it up on a `$PATH` an app may have put a copy into (audit G-F10); an older entry that names it alone is reported, and the window rewrites it at its next start. | 🆕 new |
| [`an_installed_window_runs_only_the_tool_next_to_it`](../crates/sam-gtk/src/backend.rs#L379) | An installed (release) window runs only the command line tool next to it, never one in a neighbouring `debug` or `release` folder that an app with write access to the home could create (audit G-F10). | 🆕 new |
| [`a_file_name_that_is_not_text_is_refused_by_name`](../crates/sam-jail-cli/src/bin/sam-jail-run.rs#L263) | A file name with bytes that are not text is named in the message, never passed on changed and never a crash (audit S-F15). | 🆕 new |
| [`a_folder_name_that_is_not_text_stops_the_start`](../crates/sam-sandbox/src/lib.rs#L2795) | A folder whose name is not valid text (Linux allows any bytes) is never passed on with a replaced character, which would name another folder (audit S-F15): the start is refused with the folder named. | 🆕 new |
| [`an_appimage_never_covers_sams_own_files`](../crates/sam-core/src/sandbox.rs#L300) | An AppImage file named like one of SAM's own files in the sandbox gets a folder of its own instead of covering SAM's (audit S-F17). | 🆕 new |
| [`an_appimage_called_bin_starts_and_finds_itself`](../crates/sam-jail-cli/tests/odd_names.rs#L84) | An AppImage file called like one of SAM's own files in the sandbox (`bin`) starts, and finds itself at `$APPIMAGE`. | 🆕 new |
| [`a_percent_sign_in_sams_path_stays_a_percent_sign`](../crates/sam-intake/src/desktop.rs#L404) | A `%` in SAM's own path is written `%%` in the menu entry, where a single one would start a field code like `%F` (audit G-F17). | 🆕 new |
| [`blocked_file_types_hold_in_any_case_and_old_names`](../crates/sam-intake/src/desktop.rs#L444) | SAM's menu entry never claims links, folders or desktop files, so a sandboxed app cannot take over opening them. | 🆕 new |

**Code:** [`sam-intake/src/desktop.rs`](../crates/sam-intake/src/desktop.rs), [`sam-intake/src/menu.rs`](../crates/sam-intake/src/menu.rs), [`sam-runner/src/launch.rs`](../crates/sam-runner/src/launch.rs), [`sam-core/src/paths.rs`](../crates/sam-core/src/paths.rs)

**Also tried by:** [`tests/gui/flow-atspi.sh`](../tests/gui/flow-atspi.sh), [`tests/gui/taskbar-kwin.sh`](../tests/gui/taskbar-kwin.sh)

<a id="20"></a>
### 20. SAM checks from inside the sandbox that every setting applies (the sandbox check).

| Test | Promise | Result |
|---|---|---|
| [`a_check_reports_what_it_finds_not_what_it_hopes`](../crates/sam-runner/src/probe.rs#L580) | Each check reports what it finds, not what it hopes: run on facts that are the same on every computer, a check whose expectation is wrong fails, one whose expectation is right passes, and the report counts them (found by mutation testing: a check turning every failure into a pass went unnoticed). | ✅ |
| [`a_skipped_check_is_neither_passed_nor_failed`](../crates/sam-runner/src/probe.rs#L729) | A verdict is exactly pass, fail or "could not check": a skipped check counts neither as passed nor as failed. | ✅ |
| [`the_check_expects_each_folder_as_its_settings_show_it`](../crates/sam-runner/src/verify.rs#L795) | What the check expects of each folder: the folder's own setting, but never less than the home shows it (a read-only home shows Documents read-only even when Documents has no setting; a writable folder in a read-only home stays writable); keys only with full home and their own switch; extra folders like the home inside it. | ✅ |
| [`the_check_expects_each_desktop_service_as_the_filter_shows_it`](../crates/sam-runner/src/verify.rs#L1090) | What the check expects of each desktop service that exists on the computer: full access reaches all of them; the filter reaches the desktop portal and exactly the names its list allows (a whole name, or a family with `.*`); a denied name stays hidden even with full access; a service the computer does not have is not checked at all. | 🆕 new |
| [`the_check_expects_the_rest_where_setting_and_computer_allow_it`](../crates/sam-runner/src/verify.rs#L880) | Network, display, sound, the session bus, the SSH agent, variables and the security layers: the check expects each only where both the setting and this computer provide it. | ✅ |
| [`folder_check_tells_real_from_private`](../crates/sam-runner/src/probe.rs#L761) | The sandbox check tells a real folder of the user from a private stand-in. | ✅ |
| [`the_sandbox_check_passes_and_catches_mismatches`](../crates/sam-runner/tests/verify.rs#L23) | The sandbox check passes when the settings apply, and catches a setting that does not apply. | ✅ |
| [`a_wanted_layer_that_was_not_applied_is_reported_missing`](../crates/sam-runner/src/launch.rs#L1848) | A wanted layer that was not applied is reported missing. | ✅ |
| [`a_start_without_the_helper_reports_its_missing_layers`](../crates/sam-jail-cli/tests/layers.rs#L32) | A start without the helper reports its missing layers. | ✅ |
| [`a_start_without_a_wanted_protection_layer_is_marked`](../crates/sam-core/src/model.rs#L795) | A start without a wanted protection layer is marked. | ✅ |
| [`sam_jail_run_refuses_a_sandbox_whose_settings_do_not_apply`](../crates/sam-jail-cli/tests/start_check.rs#L49) | Sam jail run refuses a sandbox whose settings do not apply. | ✅ |
| [`the_wanted_layers_follow_the_apps_switches`](../crates/sam-runner/src/launch.rs#L1967) | Landlock is wanted only where the app's switch wants it and the kernel has it; the app's strict filter switch works by itself, without a global setting (audit D-M13). | 🆕 new |
| [`checks_that_do_not_pass_end_with_not_passed`](../crates/sam-jail-cli/tests/exit_codes.rs#L269) | In a real sandbox: `run --json` passes on the app's exit code, a `selftest` with a failing app ends with 3, and `verify` with a failed check ends with 3, so `sam-jail verify APP && sam-jail run APP` gates. | 🆕 new |

**Code:** [`sam-runner/src/verify.rs`](../crates/sam-runner/src/verify.rs), [`sam-runner/src/probe.rs`](../crates/sam-runner/src/probe.rs)

**Also tried by:** [`tests/real-apps/run.sh`](../tests/real-apps/run.sh)

<a id="21"></a>
### 21. A second start, closing, and stopping work cleanly and leave nothing behind.

| Test | Promise | Result |
|---|---|---|
| [`stop_closes_running_apps`](../crates/sam-runner/tests/stop.rs#L68) | Closing an app ends all of its running starts. | ✅ |
| [`removing_a_sandbox_while_its_app_runs_is_refused`](../crates/sam-runner/tests/settings.rs#L168) | A running app keeps its sandbox: removing it is refused until the app is closed (a launch holds a lock in the app's runtime folder). | ✅ |
| [`the_overlay_check_leaves_no_folder_behind`](../crates/sam-core/src/host.rs#L184) | The overlay check leaves nothing behind, even the work folder the overlay locks (a leftover folder per check piled up in SAM's data). | ✅ |
| [`leftovers_of_earlier_overlay_checks_are_removed`](../crates/sam-core/src/host.rs#L202) | Folders left by earlier checks whose process is gone are removed; one of a check still running stays. | ✅ |
| [`without_network_the_sandbox_dies_with_its_launcher`](../crates/sam-jail-cli/tests/teardown.rs#L161) | Without network the sandbox dies with its launcher. | ✅ |
| [`with_this_computer_only_the_sandbox_dies_with_its_launcher`](../crates/sam-jail-cli/tests/teardown.rs#L170) | With this computer only the sandbox dies with its launcher. | ✅ |
| [`logging_out_closes_a_menu_started_app_properly`](../crates/sam-jail-cli/tests/teardown.rs#L194) | Logging out sends SIGTERM to the launcher of an app started from the menu (audit L-F9). | 🆕 new |
| [`an_app_that_ignores_logout_is_ended_after_the_grace_time`](../crates/sam-jail-cli/tests/teardown.rs#L291) | An app that ignores the request to quit at logout does not keep the launcher waiting: after the grace time (10 s) its sandbox is ended, and the start is still recorded as closed. | 🆕 new |

**Code:** [`sam-runner/src/launch.rs`](../crates/sam-runner/src/launch.rs), [`sam-runner/src/ops/mod.rs`](../crates/sam-runner/src/ops/mod.rs), [`sam-core/src/host.rs`](../crates/sam-core/src/host.rs)

**Also tried by:** [`tests/real-apps/run.sh`](../tests/real-apps/run.sh)

<a id="22"></a>
### 22. Logs of every start are kept, with old ones removed automatically.

| Test | Promise | Result |
|---|---|---|
| [`the_newest_log_survives_pruning_within_one_second`](../crates/sam-storage/src/lib.rs#L658) | With more launches in one second than logs are kept, the newest log survives the pruning after its launch (regression: on a fast machine a pruned name was reused, sorted as the oldest and deleted at once). | ✅ |
| [`the_newest_log_is_found_even_within_one_second`](../crates/sam-storage/src/lib.rs#L840) | The newest log is found even when two logs start within the same second. | ✅ |
| [`a_launch_log_stops_growing_at_its_limit`](../crates/sam-runner/src/launch.rs#L1796) | An app that prints without end cannot fill the disk or SAM's memory: the launch log stops at its limit with a note, a line without an end is read in pieces, and the whole output is still read. | ✅ |

**Code:** [`sam-storage/src/lib.rs`](../crates/sam-storage/src/lib.rs), [`sam-runner/src/launch.rs`](../crates/sam-runner/src/launch.rs)

## E. Fixing apps that don't work

<a id="23"></a>
### 23. After a failed start, SAM says what went wrong and offers a fix with one click.

| Test | Promise | Result |
|---|---|---|
| [`a_step_from_the_apps_output_needs_yes`](../crates/sam-jail-cli/src/main.rs#L1710) | A step from the app's own output needs --yes; SAM's own steps do not (audit U-M2). | 🆕 new |
| [`the_apps_own_words_never_give_it_a_bus_name`](../crates/sam-runner/src/repair.rs#L904) | What the app prints never gets it a bus name, whatever name it claims it needs (a terminal's name runs host commands; audit D-M6): names come only from the D-Bus filter's record (`own_names`). | 🆕 new |
| [`a_start_without_bubblewrap_stops_before_anything_runs`](../crates/sam-runner/src/launch.rs#L2004) | Without Bubblewrap, starting an app stops while it is being prepared, before any process is started, and the error says what to install. | ✅ |
| [`sandbox_setup_errors_are_told_apart_from_app_errors`](../crates/sam-runner/src/launch.rs#L2043) | Bubblewrap setup errors are told apart from errors of the app itself. | ✅ |
| [`a_start_is_judged_by_whether_the_app_started`](../crates/sam-runner/src/launch.rs#L2064) | A start is judged by whether Bubblewrap announced the app, not by what the app printed. | ✅ |
| [`analyzer_maps_errors_to_fixes`](../crates/sam-runner/src/repair.rs#L923) | Analyzer maps errors to fixes. | ✅ |
| [`fake_bwrap_error_is_not_a_sandbox_failure`](../crates/sam-runner/tests/adversarial.rs#L21) | H1: an app printing a fake Bubblewrap error is not a sandbox failure. | ✅ |

**Code:** [`sam-runner/src/repair.rs`](../crates/sam-runner/src/repair.rs), [`sam-runner/src/launch.rs`](../crates/sam-runner/src/launch.rs), [`sam-gtk/src/app_page/render.rs`](../crates/sam-gtk/src/app_page/render.rs)

**Also tried by:** [`tests/gui/app-page-atspi.sh`](../tests/gui/app-page-atspi.sh), [`tests/real-apps/run.sh`](../tests/real-apps/run.sh)

<a id="24"></a>
### 24. Repair steps go from mild to strong, and each one can be undone.

| Test | Promise | Result |
|---|---|---|
| [`steps_that_add_are_undone_and_tried_steps_are_no_hints`](../crates/sam-runner/src/repair.rs#L1122) | Steps that add a list entry or an argument are undone by removing exactly that, and a tried step is not offered again as a first-run hint either. | 🆕 new |
| [`only_an_ordinary_start_judges_repair_steps`](../crates/sam-runner/src/launch.rs#L1914) | Only an ordinary start decides the repair steps on trial: not a traced or checking run, and not a start that failed for a bus name SAM just allowed. | 🆕 new |
| [`a_repair_step_is_kept_when_it_helps_and_undone_when_it_does_not`](../crates/sam-runner/tests/repair_trial.rs#L30) | A repair step is kept when it helps and undone when it does not. | 🆕 new |
| [`a_repair_step_that_did_not_help_is_undone`](../crates/sam-runner/src/repair.rs#L1065) | A step on trial is kept when the next start works and undone when it fails: exactly what it changed is put back, it is remembered as tried and not offered again; a step from before (not on trial) is never touched (owner decision of 2026-11-18; night run N3). | 🆕 new |
| [`the_ladder_offers_only_what_can_help_and_says_what_it_costs`](../crates/sam-runner/src/repair.rs#L1178) | Starting without Chromium's own sandbox is offered only where this computer blocks it (audit A1), compatibility mode is Dangerous and says it is a way out (D-H5), and "never offer compatibility mode" keeps it out (U-M9). | 🆕 new |
| [`compatibility_mode_needs_yes_and_says_why`](../crates/sam-jail-cli/src/main.rs#L1698) | Compatibility mode goes on only with --yes, and the refusal says why (audit D-H5); turning it off needs nothing. | 🆕 new |
| [`a_repair_step_says_what_it_changes_and_costs`](../crates/sam-runner/src/repair.rs#L863) | A repair step says in a sentence what it turns on or off, with the switch's own explanation of what that allows. | ✅ |
| [`ladder_skips_applied_and_noop_steps`](../crates/sam-runner/src/repair.rs#L1031) | The repair ladder leaves out steps already applied and steps that would change nothing. | ✅ |
| [`a_writable_app_folder_is_offered_only_where_it_can_work`](../crates/sam-runner/src/repair.rs#L1226) | The repair steps offer a writable app folder only where an overlay can work: not where SAM's overlay folder cannot hold one (regression: the step was offered by Bubblewrap's version alone, and on such disks the app then started read-only anyway). | ✅ |
| [`undoing_repair_steps_restores_the_settings_from_before_the_first_step`](../crates/sam-runner/tests/settings.rs#L59) | Undoing repair steps restores the settings from before the first step. | ✅ |
| [`switching_off_one_repair_step_keeps_the_others`](../crates/sam-runner/tests/settings.rs#L229) | A repair step can be switched off on its own: exactly what that step changed goes back, and the other applied steps stay. | ✅ |
| [`only_plain_library_names_are_accepted`](../crates/sam-core/src/permissions.rs#L1330) | Only plain shared-library file names are accepted as system libraries: no folders, no `..`, nothing that is not a library. | ✅ |
| [`system_copies_replace_only_bundled_libraries_by_plain_name`](../crates/sam-sandbox/src/lib.rs#L2974) | A bundled library listed in advanced.system_libraries is replaced by the system's copy at its place in the app folder; names with folders or `..`, libraries the app does not bundle and libraries the system does not have are ignored. | ✅ |
| [`undoing_repair_steps_keeps_what_the_person_changed_since`](../crates/sam-runner/tests/settings.rs#L86) | Undoing repair steps takes back only what the steps changed: a setting the person changed afterwards stays as they set it, also the one a step had changed (audit G-F4: the whole profile from before the first step came back). | 🆕 new |

**Code:** [`sam-runner/src/repair.rs`](../crates/sam-runner/src/repair.rs), [`sam-sandbox/src/lib.rs`](../crates/sam-sandbox/src/lib.rs)

<a id="25"></a>
### 25. The diagnose run finds missing files and suggests only what helps.

| Test | Promise | Result |
|---|---|---|
| [`failed_accesses_are_read_from_a_trace`](../crates/sam-runner/src/diagnose.rs#L497) | Failed file and socket accesses are read from a diagnostic trace. | ✅ |
| [`failed_accesses_map_to_the_permission_that_fixes_them`](../crates/sam-runner/src/diagnose.rs#L517) | Failed accesses are mapped to the permission that would fix them (X11 socket, GPU device), and unknown paths to none. | ✅ |
| [`a_failure_despite_the_permission_is_not_suggested_again`](../crates/sam-runner/src/diagnose.rs#L558) | A GPU device that fails to open while the GPU is already allowed is reported as "already granted", not as a suggestion to allow the GPU (regression: neovide on NVIDIA got "Enable GPU acceleration" twice). | ✅ |
| [`the_apps_own_folders_in_its_private_home_are_not_reported`](../crates/sam-runner/src/diagnose.rs#L580) | A missing cache, settings or data folder in the app's private home is the app's own and is not reported, while a missing document folder is (regression: ~/.cache/nvidia was suggested as a folder to grant). | ✅ |
| [`failed_changes_to_a_file_are_not_missing_access`](../crates/sam-runner/src/diagnose.rs#L597) | A failed attempt to change a file's mode is not missing access (regression: NVIDIA's driver chmods /dev/nvidia-modeset, which fails for every ordinary user, and diagnose reported it as a GPU problem). | ✅ |
| [`write_checks_on_system_folders_are_not_missing_access`](../crates/sam-runner/src/diagnose.rs#L609) | Checking whether a system file is writable is not missing access (regression: Zrythm and mpv ask access(W_OK) for files in /usr, which fails for every user, and diagnose suggested granting /usr/lib/lv2). | ✅ |
| [`files_in_etc_are_suggested_and_not_added_automatically`](../crates/sam-runner/src/diagnose.rs#L625) | A file in /etc is suggested, never added by itself, because it describes this computer (regression: /etc/fstab and /etc/pacman.conf were "low risk" and added automatically, although the apps ran without them). | ✅ |
| [`the_apps_own_settings_folder_is_not_reported_as_sensitive`](../crates/sam-runner/src/diagnose.rs#L657) | The apps own settings folder is not reported as sensitive. | ✅ |
| [`diagnostic_runs_obey_the_preference`](../crates/sam-runner/src/diagnose.rs#L640) | The app's own settings folder in its private home is not reported as a sensitive folder (regression: ~/.config was "dangerous"). | ✅ |

**Code:** [`sam-runner/src/diagnose.rs`](../crates/sam-runner/src/diagnose.rs)

<a id="26"></a>
### 26. Compatibility mode as a last resort, with its cost explained, and it can be undone.

| Test | Promise | Result |
|---|---|---|
| [`compatibility_mode_names_only_what_it_changes`](../crates/sam-runner/src/repair.rs#L845) | Compatibility mode lists only what it actually changes, in the words of the switches. | ✅ |
| [`turning_compatibility_mode_off_restores_exactly_the_settings_from_before`](../crates/sam-runner/tests/settings.rs#L42) | Turning compatibility mode off restores exactly the settings the user had before. | ✅ |
| [`compat_takes_on_and_off_in_any_case_and_nothing_else`](../crates/sam-jail-cli/tests/exit_codes.rs#L100) | `compat` takes on and off in any case and refuses anything else. | 🆕 new |

**Code:** [`sam-runner/src/repair.rs`](../crates/sam-runner/src/repair.rs), [`sam-runner/src/ops/profiles.rs`](../crates/sam-runner/src/ops/profiles.rs)

## F. Keeping things safe over time

<a id="27"></a>
### 27. SAM notices app settings that something else changed and asks before starting the app.

| Test | Promise | Result |
|---|---|---|
| [`records_changed_outside_sam_are_recognized`](../crates/sam-storage/src/lib.rs#L679) | A record SAM saved loads as unchanged; a record changed afterwards by something else is recognized as changed outside SAM, and stays marked through SAM's own saves until it is confirmed; a record without SAM's checksum (removed, or from before the checksum) is marked too. | ✅ |
| [`an_app_changed_outside_sam_starts_only_after_confirmation`](../crates/sam-runner/tests/tamper.rs#L107) | An app whose settings were changed outside SAM does not start until the user has confirmed them; changes SAM makes itself never count as such. | ✅ |
| [`a_changed_record_stays_blocked_until_it_is_confirmed`](../crates/sam-runner/tests/tamper.rs#L146) ⟲ | Regression (audit U-H1): the mark "changed outside SAM" was erased by the next save of the record. | 🆕 new |
| [`a_late_save_keeps_a_change_made_meanwhile`](../crates/sam-storage/src/lib.rs#L741) | `update` changes the record as it is on disk now, so work that took a while does not undo a change made meanwhile (audit U-M8: the update check turned a switch back on). | 🆕 new |

**Code:** [`sam-storage/src/lib.rs`](../crates/sam-storage/src/lib.rs), [`sam-runner/src/launch.rs`](../crates/sam-runner/src/launch.rs)

<a id="28"></a>
### 28. Updates use HTTPS only, keep the old version so it can be restored, and refuse a changed signing key until you accept it.

| Test | Promise | Result |
|---|---|---|
| [`both_forms_of_update_information_are_understood`](../crates/sam-detect/src/update_info.rs#L143) | Both forms of update information (a direct zsync address and GitHub releases) are understood. | ✅ |
| [`update_wildcards_match_only_the_right_build`](../crates/sam-detect/src/update_info.rs#L183) | Wildcards in update information match the right file name and not the build for another processor. | ✅ |
| [`signed_appimage_is_checked`](../crates/sam-detect/tests/signature.rs#L139) | The signature of a signed AppImage is checked with GnuPG: unsigned, valid with the signer's fingerprint and name, invalid after one changed byte. | ✅ |
| [`key_changes_are_noticed`](../crates/sam-runner/src/ops/mod.rs#L672) | An update signed with another key, or not signed at all, is noticed. | ✅ |
| [`sam_updates_itself_only_with_its_release_key`](../crates/sam-runner/src/release_key.rs#L105) | SAM accepts an update of itself only with a valid signature from one of its release keys; unsigned, changed, unchecked or otherwise signed updates are refused (regression: self-update installed any AppImage the update information pointed to). | ✅ |
| [`release_keys_are_full_fingerprints`](../crates/sam-runner/src/release_key.rs#L77) | Every built-in release key is a full fingerprint (40 hex characters), never a short key id that another key could share. | ✅ |
| [`signing_a_file_without_signature_sections_is_refused`](../crates/sam-jail-cli/tests/robustness.rs#L259) | Signing a file that has no AppImage signature sections is refused with a clear message, before GnuPG is asked anything, and the file stays as it was. | ✅ |
| [`without_a_release_key_sam_never_updates_itself`](../crates/sam-runner/src/release_key.rs#L141) | Without a built-in release key, SAM never updates itself, whatever the download looks like. | ✅ |
| [`the_zsync_header_is_read`](../crates/sam-runner/src/updates.rs#L555) | The header of a zsync file is read (file name, size, checksum). | ✅ |
| [`update_download_addresses_are_resolved_and_http_refused`](../crates/sam-runner/src/updates.rs#L579) | Download addresses in zsync files are resolved, and plain-HTTP addresses are refused. | ✅ |
| [`updates_are_downloaded_over_https_only`](../crates/sam-runner/src/updates.rs#L596) | Update downloads use HTTPS only; HTTP and file addresses are refused. | ✅ |
| [`an_update_is_rebuilt_from_the_old_version_and_changed_blocks`](../crates/sam-runner/src/zsync.rs#L436) | An update is rebuilt from the old version plus the changed blocks. | ✅ |
| [`the_rolling_checksum_matches_a_direct_computation`](../crates/sam-runner/src/zsync.rs#L490) | The rolling checksum of the update transfer matches a direct computation at every offset. | ✅ |
| [`refuses_compressed_and_broken_files`](../crates/sam-runner/src/zsync.rs#L506) | Compressed or incomplete zsync files are refused. | ✅ |
| [`undo_puts_the_previous_version_back`](../crates/sam-runner/tests/update.rs#L15) | Undoing an update puts the previous version back. | ✅ |
| [`undoing_an_update_never_moves_files_outside_sams_backup_folder`](../crates/sam-runner/tests/tamper.rs#L89) ⟲ | Regression (found in the test audit): "go back to the earlier version" moved the file a record named as the backup, wherever it was. | ✅ |
| [`block_checksums_match_the_zsync_definition`](../crates/sam-runner/src/zsync.rs#L384) | The block checksums are the ones zsync defines: MD4 of a block padded with zeros to the block size, and the weak sum cut to its last bytes. | ✅ |
| [`the_download_checksum_is_sha1_of_the_whole_file`](../crates/sam-runner/src/updates.rs#L535) | The checksum of a downloaded update is SHA-1 of the whole file, read in pieces; a file larger than one piece gives the same result. | ✅ |
| [`updates_download_only_changes_check_them_and_refuse_tampering`](../crates/sam-runner/tests/update_server.rs#L175) | Updates download only changes check them and refuse tampering. | ✅ |
| [`the_weak_hashes_stay_in_the_zsync_update_code`](../crates/sam-jail-cli/tests/architecture.rs#L206) | SHA-1 and MD4 are broken as protection against tampering. | ✅ |
| [`an_update_that_cannot_be_checked_needs_consent_after_a_valid_signature`](../crates/sam-runner/src/ops/mod.rs#L698) | A signed app whose update cannot be checked (GnuPG missing) is not waved through: SAM cannot tell whether the key changed. | ✅ |
| [`a_second_key_in_the_file_cannot_borrow_a_trusted_name`](../crates/sam-detect/tests/signature.rs#L174) | The attack of audit finding C1: a file carries a trusted key (here it stands for SAM's release key, which is public) first and the attacker's key second, and is signed with the attacker's key. | 🆕 new |
| [`a_signature_by_a_subkey_names_its_primary_key`](../crates/sam-detect/tests/signature.rs#L217) | A key whose signatures come from a signing subkey: SAM names the primary key (the fingerprint people publish and SAM compares), not the subkey. | 🆕 new |
| [`gnupg_names_the_real_signer`](../crates/sam-detect/tests/signature.rs#L240) | The contract with GnuPG (docs/contracts.toml, `signatures-gnupg`) holds with the GnuPG installed here: gpgv accepts a signature by any key in its keyring, and its status output names the key that really signed. | 🆕 new |
| [`sam_refuses_a_forged_update_that_carries_its_release_key`](../crates/sam-runner/tests/self_update_signature.rs#L78) | SAM installs an update of itself only when it was really signed with its release key. | 🆕 new |
| [`the_signer_is_what_gpgv_reports_and_nothing_unclear_counts`](../crates/sam-detect/src/signature.rs#L525) | The signer is read from gpgv's own report of the signature it checked: the primary key, or the signing key when no primary is given. | 🆕 new |
| [`primary_keys_are_counted_without_their_subkeys`](../crates/sam-detect/src/signature.rs#L586) | Primary keys are counted from GnuPG's listing; subkeys are not keys of their own (a signer with a signing subkey carries one key). | 🆕 new |
| [`the_contract_material_names_key_b`](../crates/sam-detect/src/signature.rs#L602) | The fixed test material of the GnuPG contract is what its comments say: key B's fingerprint is the one recorded. | 🆕 new |
| [`a_helper_program_is_stopped_at_its_time_limit`](../crates/sam-core/src/util.rs#L589) | A helper program that hangs is stopped at the time limit instead of hanging SAM (GnuPG reads keys from untrusted AppImages), and a program that prints more than SAM keeps neither blocks nor floods SAM's memory. | 🆕 new |
| [`an_update_writes_through_no_planted_link_and_keeps_the_sandbox`](../crates/sam-runner/tests/update_server.rs#L336) ⟲ | Regressions (audit U-H4, U-H3): updates were downloaded next to the AppImage under a guessable name (`.<name>.sam-download`) with tools that follow links, so an app with write access to that folder (often Downloads) could plant a link there and SAM wrote the update through it into any file of the person. | 🆕 new |
| [`going_back_with_an_unchanged_file_name_keeps_both_versions`](../crates/sam-runner/tests/update_server.rs#L431) ⟲ | Regression (audit U-H5): when the new version had the same file name as the old one, going back moved the current file onto the kept old version (destroying it), then "restored" the new file and reported that the app was back. | 🆕 new |
| [`a_download_folder_is_fresh_private_and_sams_own`](../crates/sam-runner/src/ops/maintain.rs#L1153) | Updates are downloaded into a fresh folder inside SAM's data folder that only SAM's user can enter (audit U-H4): never the AppImage's folder, never one with leftovers. | 🆕 new |
| [`a_move_across_drives_never_writes_through_a_link`](../crates/sam-runner/src/ops/maintain.rs#L1173) | Across file systems (a download in SAM's folder, the AppImage on another drive) a move is a copy: into a new file with the same permissions, never through a link planted at the target and never over a file that is there (audit U-H4: `fs::copy` followed links). | 🆕 new |
| [`an_older_signed_version_is_not_installed_as_an_update`](../crates/sam-runner/tests/update_server.rs#L490) ⟲ | Regression (audit U-M6): whoever controls the download could hand out an older, validly signed release (with holes fixed since) as the update: any file other than the installed one counted as newer. | 🆕 new |
| [`an_older_signed_version_is_recognized`](../crates/sam-runner/src/ops/mod.rs#L631) | An update signed with the same key but earlier than the installed version is an older version; later, equal, another key, unsigned or without a time is not judged here. | 🆕 new |
| [`the_signing_time_is_read_from_the_one_good_signature`](../crates/sam-detect/src/signature.rs#L568) | The signing time is the one good signature's own (seconds since 1970); nothing unclear gives a time. | 🆕 new |
| [`a_hostile_update_description_cannot_crash_or_stall_sam`](../crates/sam-runner/src/zsync.rs#L521) | A description from a hostile server cannot crash SAM or keep it busy (audit U-M7): an absurd length is refused, a block count that would overflow the size computation is refused instead of wrapping, and thousands of blocks whose quick checksum matches a stretch of identical bytes end at the time limit, with those blocks left for downloading. | 🆕 new |
| [`kept_data_goes_back_only_to_its_own_appimage`](../crates/sam-runner/tests/tamper.rs#L199) ⟲ | Regression (audit I-F5): an id is the app's name plus four hex digits of its file's checksum, so a crafted AppImage can get the id of a removed app whose data was kept, and it inherited that private home. | 🆕 new |
| [`changed_zsync_controls_never_crash_planning_or_assembly`](../crates/sam-runner/tests/fuzz_targets.rs#L224) | Changed zsync control files are refused, or planned and assembled within their limits, without a panic: the parser, the block plan, the missing ranges and the assembly all see them. | 🆕 new |

**Code:** [`sam-runner/src/updates.rs`](../crates/sam-runner/src/updates.rs), [`sam-runner/src/zsync.rs`](../crates/sam-runner/src/zsync.rs), [`sam-runner/src/release_key.rs`](../crates/sam-runner/src/release_key.rs), [`sam-detect/src/update_info.rs`](../crates/sam-detect/src/update_info.rs), [`sam-detect/src/signature.rs`](../crates/sam-detect/src/signature.rs)

<a id="29"></a>
### 29. SAM notices AppImages that were moved or changed.

| Test | Promise | Result |
|---|---|---|
| [`a_swapped_appimage_does_not_start_until_it_is_confirmed`](../crates/sam-runner/tests/changed_appimage.rs#L13) | A swapped appimage does not start until it is confirmed. | ✅ |
| [`a_swapped_appimage_stays_marked_when_a_switch_changes`](../crates/sam-runner/tests/changed_appimage.rs#L71) ⟲ | Regression (audit U-H1, Part 5): changing any switch cleared the mark of a swapped AppImage file, so it started without the person looking at it. | 🆕 new |
| [`a_swapped_appimage_is_marked_also_after_the_change_check`](../crates/sam-runner/tests/changed_appimage.rs#L111) ⟲ | Regression (audit U-H2): "Check all AppImages for changes" (or moving the file with relocate) recorded the swapped file's checksum, so the following "Unpack Again" compared the file with itself: the swapped content ran with the old app's permissions, unmarked, and its signature was not checked again. | 🆕 new |
| [`a_swapped_appimage_file_is_marked_and_old_records_stay_unchanged`](../crates/sam-core/src/model.rs#L730) | An AppImage file swapped outside SAM shows as changed outside SAM; while the mark is off it is not written, so every record saved before it existed keeps its checksum (no app looks changed after an update). | ✅ |
| [`a_changed_appimage_file_is_noticed`](../crates/sam-intake/src/fingerprint.rs#L107) | A changed AppImage file is noticed by its fingerprint. | ✅ |
| [`a_moved_appimage_is_recognized_by_its_content`](../crates/sam-runner/tests/settings.rs#L208) | When a sandboxed app's AppImage is moved to another searched folder, SAM recognizes it by its content and offers to follow it. | ✅ |

**Code:** [`sam-intake/src/fingerprint.rs`](../crates/sam-intake/src/fingerprint.rs), [`sam-runner/src/ops/maintain.rs`](../crates/sam-runner/src/ops/maintain.rs)

## G. Managing

<a id="30"></a>
### 30. Removing an app deletes only SAM's own folders, never your files.

| Test | Promise | Result |
|---|---|---|
| [`removing_a_sandbox_never_deletes_outside_sams_unpack_folder`](../crates/sam-runner/tests/tamper.rs#L34) ⟲ | Regression: the unpack folder in a record was only checked with Path::starts_with, which does not resolve "..": "extracted/../../victim" passed, and removing the sandbox deleted the victim folder. | ✅ |
| [`a_record_with_a_climbing_id_reaches_nothing`](../crates/sam-runner/tests/tamper.rs#L66) | A record whose id climbs out of SAM's folders cannot be loaded, so no operation can reach the folders that id would name. | ✅ |
| [`records_with_unsafe_or_mismatched_ids_are_not_loaded`](../crates/sam-storage/src/lib.rs#L810) ⟲ | Regression (found in the test audit): a record changed outside SAM with an id like "../../.ssh" would have pointed the folders SAM deletes on removal (private home, logs) outside SAM's own folders. | ✅ |
| [`removing_with_keep_my_data_keeps_the_private_home_and_without_deletes_it`](../crates/sam-runner/tests/settings.rs#L189) | Removing a sandbox with "keep my data" keeps the app's private home; without it, the home is deleted. | ✅ |
| [`removing_a_sandbox_while_its_app_runs_is_refused`](../crates/sam-runner/tests/settings.rs#L168) | A running app keeps its sandbox: removing it is refused until the app is closed (a launch holds a lock in the app's runtime folder). | ✅ |
| [`names_become_safe_identifiers`](../crates/sam-core/src/util.rs#L696) | Names become safe identifiers made of lowercase letters, digits and dashes. | ✅ |

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
| [`disabled_user_namespaces_are_explained_not_called_missing`](../crates/sam-runner/src/bwrap.rs#L69) | When the system forbids user namespaces, the message explains that and never claims Bubblewrap is missing: the user already has it, and an "install bubblewrap" hint would send them the wrong way. | ✅ |
| [`setuid_bubblewrap_works_without_user_namespaces`](../crates/sam-runner/src/bwrap.rs#L96) | A setuid Bubblewrap works without unprivileged user namespaces, so SAM does not refuse it. | ✅ |
| [`reaches_the_session_bus`](../crates/sam-runner/src/dbus_check.rs#L275) | SAM's own bus check reaches a session bus. | ✅ |
| [`the_bus_check_message_has_the_correct_wire_format`](../crates/sam-runner/src/dbus_check.rs#L325) | SAM's own D-Bus message for the bus check has the correct wire format. | ✅ |
| [`bubblewrap_versions_are_compared_correctly`](../crates/sam-core/src/host.rs#L230) | Bubblewrap versions are compared correctly, including missing or malformed version text. | ✅ |
| [`the_built_in_contract_map_parses`](../crates/sam-runner/src/contracts.rs#L653) | The built in contract map parses. | ✅ |
| [`every_contract_probe_is_known`](../crates/sam-runner/src/contracts.rs#L685) | Every contract probe is known. | ✅ |
| [`a_missing_portal_interface_breaks_the_portal_contract`](../crates/sam-runner/src/contracts.rs#L781) | A missing portal interface breaks the portal contract. | ✅ |
| [`the_quick_checks_notice_a_broken_or_missing_tool`](../crates/sam-jail-cli/tests/contracts.rs#L48) | The quick checks notice a broken or missing tool. | ✅ |
| [`a_broken_contract_fails_a_test_with_its_name_and_playbook`](../crates/sam-runner/src/contracts.rs#L697) | A broken contract fails a test with its name and playbook. | ✅ |
| [`a_broken_contract_ends_with_not_passed`](../crates/sam-jail-cli/tests/exit_codes.rs#L239) | A broken contract (here a Bubblewrap that cannot build a sandbox) ends `doctor --contracts` with 3. | 🆕 new |
| [`doctor_ends_with_what_it_reports`](../crates/sam-jail-cli/tests/exit_codes.rs#L134) | `doctor` and `doctor --contracts` end with 3 exactly when they report a failed check or a broken contract, and with 0 otherwise. | 🆕 new |
| [`the_install_hint_fits_the_distribution`](../crates/sam-core/src/host.rs#L830) | The install hint names this distribution's package manager, also on derivatives (by `ID_LIKE`), and none where SAM does not know it (audit T2). | 🆕 new |
| [`the_apparmor_advice_keeps_the_restriction_for_other_programs`](../crates/sam-core/src/host.rs#L815) | Where AppArmor restricts user namespaces, the advice names the restricted profile for Bubblewrap alone and what it costs, and warns against the ways that lift the restriction for every program (audit A3). | 🆕 new |

**Code:** [`sam-runner/src/doctor.rs`](../crates/sam-runner/src/doctor.rs), [`sam-runner/src/bwrap.rs`](../crates/sam-runner/src/bwrap.rs), [`sam-runner/src/dbus_check.rs`](../crates/sam-runner/src/dbus_check.rs), [`sam-core/src/host.rs`](../crates/sam-core/src/host.rs)

<a id="34"></a>
### 34. Privacy: SAM sends nothing on its own, and a bug report never contains your name, home path, addresses or secrets.

| Test | Promise | Result |
|---|---|---|
| [`given_environment_values_are_hidden_in_the_shown_command`](../crates/sam-core/src/sandbox.rs#L254) | Values of variables a person gave the app never reach the shown command; the names and SAM's own variables stay. | ✅ |
| [`bug_reports_hide_the_user_name_and_home_path`](../crates/sam-runner/src/doctor.rs#L976) | A bug report never contains the user's name or home path: both are replaced before the text is shown for copying. | ✅ |
| [`bug_reports_hide_names_addresses_and_secrets`](../crates/sam-runner/src/doctor.rs#L1018) | Bug reports hide everything that identifies the user or gives access: a home folder with spaces, other users' folders, short user names, the computer's name, email addresses, logins and tokens in links, IP addresses, and the values of environment variables given to the app. | ✅ |
| [`a_bug_report_is_complete_and_redacted`](../crates/sam-runner/src/doctor.rs#L994) | A whole bug report (the system part) is produced and redacted: it names SAM's version and never the home folder or user name. | ✅ |
| [`update_checks_stay_off_unless_switched_on`](../crates/sam-core/src/config.rs#L451) | SAM contacts no update source on its own: the daily check when the window opens is off until the user switches it on. | ✅ |
| [`the_machine_id_reaches_only_apps_with_dbus`](../crates/sam-sandbox/src/lib.rs#L2476) | The machine ID identifies this computer; an app sees it only with D-Bus, which needs it, never without. | ✅ |
| [`bug_reports_hide_tokens_in_every_shape`](../crates/sam-runner/src/doctor.rs#L1094) | Bug reports also hide what gives access in other shapes (audit U-L5): a token after `#` or inside a link's path, `Authorization` and cookie lines, and named secrets in settings and logs. | 🆕 new |
| [`a_log_cannot_break_out_of_its_code_block`](../crates/sam-runner/src/doctor.rs#L1166) | An app's log cannot end the report's code block and add text of its own after it: the fence is always longer than any run of backticks inside. | 🆕 new |

**Code:** [`sam-runner/src/doctor.rs`](../crates/sam-runner/src/doctor.rs)

## H. The window

<a id="35"></a>
### 35. The overview of all apps, with clear status badges.

| Test | Promise | Result |
|---|---|---|
| [`profile_change_clears_broken_launch`](../crates/sam-core/src/model.rs#L712) | Changing an app's settings clears the record of a failed start, so the app is no longer shown as broken. | ✅ |
| [`apps_with_compatibility_risk_are_marked_until_they_start`](../crates/sam-core/src/model.rs#L757) | An app with compatibility risk carries a warning badge until it has started successfully once. | ✅ |
| [`apps_are_found_by_name_or_id_and_ambiguous_names_are_refused`](../crates/sam-storage/src/lib.rs#L863) | Apps are found by name or ID, and an ambiguous name is refused. | ✅ |
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
| [`the_overview_lists_every_sandboxed_app_with_tags_and_states`](../crates/sam-runner/tests/groups.rs#L139) | The Permissions overview lists every sandboxed app with its tags and states. | ✅ |
| [`group_switches_offer_only_valid_values`](../crates/sam-gtk/src/all_perms.rs#L1388) | The group switches offer only permissions and values SAM accepts (`sam-jail group set` would refuse anything else), and each value of a permission appears once. | ✅ |
| [`shift_click_selects_the_apps_between_two_clicks`](../crates/sam-gtk/src/all_perms.rs#L1421) | Shift-click selects every app between the app clicked before and the app clicked now, in either direction; without an earlier click, only the app clicked now. | ✅ |
| [`a_tag_filter_cycles_through_has_has_not_and_off`](../crates/sam-gtk/src/all_perms.rs#L1436) | A tag filter cycles through three states with each click: only apps with the permission, only apps without it, and off. | ✅ |
| [`the_list_shows_only_apps_that_pass_every_filter`](../crates/sam-gtk/src/all_perms.rs#L1445) | The list shows an app only when it passes every filter at once: the search text, each state filter, and each tag filter in its state. | ✅ |
| [`the_style_sheet_handler_is_connected_before_register`](../crates/sam-gtk/src/main.rs#L601) ⟲ | Regression: the "startup" handler that loads SAM's style sheet was connected after `register()`, which emits "startup" for the first instance at once. | ✅ |
| [`a_new_icon_marks_its_folders_as_changed`](../crates/sam-gtk/src/main.rs#L549) | A new icon is noticed by the desktop's icon caches: the folders from the icon up to the theme are marked as changed, also when an earlier version had replaced the icon in place; once they are newer than the icon, nothing is touched again (regression: the taskbar kept SAM's old icon). | ✅ |
| [`every_color_in_use_has_a_style_rule`](../crates/sam-gtk/src/main.rs#L615) | Every color SAM's window uses has a style rule: the badge tones in the code, the three risk levels of tags and badges, and the outline. | ✅ |

**Code:** [`sam-gtk/src/all_perms.rs`](../crates/sam-gtk/src/all_perms.rs), [`sam-gtk/src/perms.rs`](../crates/sam-gtk/src/perms.rs), [`sam-profile/src/tags.rs`](../crates/sam-profile/src/tags.rs), [`sam-gtk/src/main.rs`](../crates/sam-gtk/src/main.rs)

**Also tried by:** [`tests/gui/permissions-atspi.sh`](../tests/gui/permissions-atspi.sh)

<a id="37"></a>
### 37. SAM speaks English, German, Spanish and French: every text in the window and every message from SAM's core. You can choose SAM's language in the main menu; apps keep the system's.

| Test | Promise | Result |
|---|---|---|
| [`texts_without_a_translation_come_back_with_their_values`](../crates/sam-core/src/i18n.rs#L193) | Texts without a translation come back with their values. | ✅ |
| [`the_command_line_speaks_german_when_asked`](../crates/sam-jail-cli/tests/language.rs#L18) | The command line speaks german when asked. | ✅ |
| [`every_translated_language_can_be_chosen`](../crates/sam-core/src/i18n.rs#L179) | Without a translation, texts come back as written, placeholders are filled in by name (so a translation may reorder them), and the plural form follows the number. | ✅ |
| [`the_language_is_the_system_or_one_sam_speaks`](../crates/sam-core/src/config.rs#L464) | The window's language is empty (follow the system) or one of the languages SAM speaks; anything else is refused, and a wrong value in the file is reset to the system's language. | ✅ |
| [`the_chosen_language_and_the_systems_are_kept_apart`](../crates/sam-gtk/src/i18n.rs#L90) | Choosing a language sets it for the window and remembers the system's; going back to the system restores exactly what it had, also after several restarts. | ✅ |
| [`apps_keep_the_system_language_whatever_sams_window_shows`](../crates/sam-sandbox/src/lib.rs#L3019) | An app started from SAM's window keeps the system's language, even when the window itself shows another one. | ✅ |

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
| [`a_complete_configuration_file_loads_every_setting`](../crates/sam-core/src/config.rs#L411) | A complete configuration file with every section loads without loss. | ✅ |
| [`settings_change_by_key_and_old_theme_names_are_migrated`](../crates/sam-core/src/config.rs#L490) | Settings can be changed by key, and old theme names are migrated to Light, Dark or System. | ✅ |
| [`files_from_a_newer_sam_are_never_overwritten`](../crates/sam-core/src/format.rs#L102) | SAM refuses to overwrite a file written by a newer SAM and reads files without a format number as format 0. | ✅ |
| [`access_from_bool_and_str`](../crates/sam-core/src/permissions.rs#L1243) | Folder access is read from both the old form (true/false) and the current form ("ro", "rw"). | ✅ |
| [`old_profiles_with_removed_options_still_load`](../crates/sam-core/src/permissions.rs#L1293) | Settings saved with options SAM no longer has still load, with the removed options mapped to their safe meaning. | ✅ |
| [`permissions_saved_as_toml_load_back_unchanged`](../crates/sam-core/src/permissions.rs#L1308) | Permissions saved as TOML load back unchanged. | ✅ |
| [`old_extra_backend_args_still_load`](../crates/sam-core/src/permissions.rs#L1321) | Raw sandbox arguments saved under their old name still load. | ✅ |
| [`presets_in_the_older_flat_format_still_load`](../crates/sam-storage/src/lib.rs#L891) | Presets in the older flat format still load. | ✅ |
| [`old_formats_are_migrated_and_kept`](../crates/sam-jail-cli/tests/robustness.rs#L65) | Files from older SAM versions are migrated to the current format, and the originals are kept. | ✅ |
| [`newer_formats_are_left_untouched`](../crates/sam-jail-cli/tests/robustness.rs#L106) | Files from a newer SAM are never changed by an older one. | ✅ |
| [`damaged_files_are_moved_aside_and_reported`](../crates/sam-jail-cli/tests/robustness.rs#L151) | Damaged files are moved aside and reported, and SAM carries on. | ✅ |
| [`mangled_files_never_crash`](../crates/sam-jail-cli/tests/robustness.rs#L202) | Mangled files never make SAM crash. | ✅ |
| [`empty_or_relative_folder_settings_are_ignored`](../crates/sam-jail-cli/tests/odd_names.rs#L217) | An empty or relative folder setting is ignored (as the XDG rules say) instead of putting SAM's files into whatever folder SAM was started in (audit G-F20). | 🆕 new |

**Code:** [`sam-core/src/format.rs`](../crates/sam-core/src/format.rs), [`sam-core/src/config.rs`](../crates/sam-core/src/config.rs), [`sam-core/src/permissions.rs`](../crates/sam-core/src/permissions.rs), [`sam-storage/src/lib.rs`](../crates/sam-storage/src/lib.rs)

**Also tried by:** [`tests/upgrade/run.sh`](../tests/upgrade/run.sh)

<a id="39"></a>
### 39. SAM's parts stay cleanly separated: the window reaches the core only through the command line and decides by codes, never by reading messages, and the parts that handle untrusted content never depend on the higher ones.

*An internal guarantee: it keeps SAM maintainable and is not a feature users see.*

| Test | Promise | Result |
|---|---|---|
| [`times_are_shown_without_a_date_library`](../crates/sam-core/src/util.rs#L656) | Times are shown without a date library: UTC dates exactly, local times in the computer's own zone and shape (chrono was dropped when it became unmaintained, RUSTSEC-2026-0543). | ✅ |
| [`the_permission_model_depends_on_no_other_part`](../crates/sam-jail-cli/tests/architecture.rs#L59) | The permission model is the base: it depends on no other SAM part, so every other part can use it without creating a cycle. | ✅ |
| [`the_window_reaches_sam_only_through_the_command_line`](../crates/sam-jail-cli/tests/architecture.rs#L67) | The window contains no sandbox logic: it depends only on the permission model and reaches everything else through `sam-jail --json`, so the window and the command line always behave the same. | ✅ |
| [`lower_parts_never_depend_on_higher_ones`](../crates/sam-jail-cli/tests/architecture.rs#L75) | The parts that handle untrusted AppImage content or build the sandbox depend only on the parts below them, never on the operations layer, the command line or the window. | ✅ |
| [`the_sandbox_builder_depends_only_on_the_permission_model`](../crates/sam-jail-cli/tests/architecture.rs#L98) | The sandbox command builder depends only on the permission model, so what it builds follows from the permissions alone. | ✅ |
| [`the_component_diagram_shows_the_real_dependencies`](../crates/sam-jail-cli/tests/architecture.rs#L105) | The component diagram in docs/architecture.md shows exactly the real dependencies between the parts: no arrow is missing and none is invented. | ✅ |
| [`diagram_labels_are_quoted_so_github_draws_them`](../crates/sam-jail-cli/tests/architecture.rs#L155) | Every box and arrow label in the documents' diagrams is quoted, so GitHub draws them: unquoted brackets or semicolons inside a label are a parse error there (the component diagram once failed that way). | ✅ |
| [`version_reports_the_json_interface`](../crates/sam-jail-cli/tests/robustness.rs#L241) | `sam-jail version` answers with the JSON interface version even when the configuration cannot be read. | ✅ |
| [`an_error_code_survives_added_context`](../crates/sam-core/src/error.rs#L137) | An error code survives added context. | ✅ |
| [`a_required_run_does_not_skip`](../crates/sam-runner/src/contracts.rs#L769) | Where a run must prove everything (CI), a skip is an error; locally it is a note. | ✅ |
| [`a_failing_section_is_named_and_the_next_still_runs`](../crates/sam-runner/src/contracts.rs#L748) | A failing section is named and the next still runs. | ✅ |
| [`a_skipped_test_is_recorded_with_its_reason`](../crates/sam-runner/src/contracts.rs#L640) | A skipped test is written to the skip log with its name and reason, one line each, so a run can report it instead of passing it silently. | ✅ |
| [`tests_find_the_helper_of_their_own_build`](../crates/sam-runner/src/lib.rs#L123) | A test program inside Cargo's build folder finds the helper of its own build, so tests that need it run instead of skipping; an installed program never looks above its own folder. | ✅ |
| [`a_build_never_takes_a_helper_from_path`](../crates/sam-runner/src/lib.rs#L99) | A program of a Cargo build whose helper is not built gets none, even when one is on PATH (an installed SAM or another build): the test then says it cannot run, instead of checking a different version. | ✅ |
| [`rooted_paths_have_a_runtime_folder_of_their_own`](../crates/sam-core/src/paths.rs#L169) | Rooted paths (tests) keep their runtime folders apart from SAM's real one and from every other root, and short enough for SAM's sockets. | ✅ |
| [`an_error_names_its_sam_function_and_keeps_its_message`](../crates/sam-core/src/error.rs#L113) | The code of an error survives being wrapped in context, so the window recognizes it whatever language the message is in. | ✅ |
| [`json_run_keeps_its_reply_alone_on_standard_output`](../crates/sam-jail-cli/tests/odd_names.rs#L112) | With `--json`, SAM's standard output is its reply and nothing else: an app that prints a line looking like the reply cannot be read as SAM's. | 🆕 new |
| [`preset_names_are_never_read_as_options`](../crates/sam-gtk/src/backend.rs#L363) | Preset names reach SAM after `--`, so one that starts with `-` is not read as an option (audit G-F20). | 🆕 new |

**Code:** [`sam-jail-cli/tests/architecture.rs`](../crates/sam-jail-cli/tests/architecture.rs), [`docs/architecture.md`](../docs/architecture.md)

✅ passed in the newest version report · ❌ failed there · 🆕 new: added after that report, so it has no result yet (every test passes before it is committed; the next report fills it in) · ⟲ a regression test: it guards against a bug that really happened.
