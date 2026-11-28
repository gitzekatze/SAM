# JSON interface

Every `sam-jail` command accepts `--json`. The window of SAM - Sandboxed
AppImage Manager uses nothing else: the command line is SAM's API. Scripts
can rely on it in the same way.

---

## Envelope

A command prints exactly one JSON object on the last line of stdout:

```json
{"ok": true, "data": …}
{"ok": false, "error": "a message in the user's language"}
{"ok": false, "error": "…", "code": "signing-key-changed", "function": 28}
```

The exit status says how it went, the same with and without `--json`:

| Status | Meaning |
|---|---|
| 0 | done, and every check passed |
| 1 | an error (`ok: false`) |
| 2 | a wrong command line (an unknown option, a missing argument) |
| 3 | it ran, but a check did not pass or it did not do what was asked: `verify` with a failed check, `selftest` with an app that failed, `doctor` with a failed check or `doctor --contracts` with a broken contract, `preset apply` not applied (it needs `--yes`). The reply is `ok: true` and says what failed. |

`run` ends with the app's own exit code when the app ended with one, and
with at least 1 when the start failed. So `sam-jail verify APP && sam-jail
run APP` starts the app only when the sandbox check passed.

Text on stderr is for people, not for parsing.

`error` is translated into the user's language, so a program must never
decide anything by its wording. Errors a program may need to recognize carry
a `code`, which stays the same in every language:

| Code | Meaning |
|---|---|
| `signing-key-changed` | `update`: the new file is signed with another key; it waits in SAM's folder, and running again with `--accept-key-change` installs exactly that file (only if you trust it). Another file published meanwhile is asked about again with the same code |
| `extraction-limit` | unpacking stopped at a size, file-count or time limit; the message says which one |
| `unpack-needs-sandbox` | SAM unpacks only inside a sandbox, and none can be built here (no Bubblewrap, or SAM's `sam-jail` is not next to the program) |
| `signature-unchecked` | `update`: the installed version was signed and checked, but the new file's signature cannot be checked (GnuPG missing); `--accept-key-change` installs exactly that file anyway |
| `signing-time-unknown` | `update`: both versions are signed with the same key, but when one of them was signed cannot be read, so SAM cannot tell whether the update is an older version; `--accept-key-change` installs exactly that file anyway |

Every error also names the **SAM function** it happened in, as `function`:
the number in [SAM's functions](functions.md), so a script or a bug report
knows which promise, which code and which tests to look at. It is the most
precise one known: recognizing a file is function 2, unpacking it function 3,
starting function 19. On the terminal it ends the message, for example
`(SAM function 3)`.

Commands that take a whole object (a profile, a preset, the configuration)
read it as JSON on stdin; the flag or subcommand is named in the table below.

### Progress

`add --progress` also reports while it works, on **stderr**, one JSON object
per line (at most about ten per second), before the envelope on stdout:

```json
{"progress": {"step": 2, "steps": 5, "title": "Unpacking", "detail": "1.2 GB unpacked", "fraction": 0.31}}
```

`fraction` is the whole operation (0..1). The unpacking step estimates it
from the file size (AppImages unpack to about 2.5 times their size) and
waits at 95 % of the step if the app turns out bigger; `detail` always has
the real figure. Other stderr lines are messages, not progress.

## Versions

```sh
sam-jail --json version
{"ok": true, "data": {"version": "0.1.0", "interface": 2}}
```

- `interface` is the level of this interface (`sam_core::JSON_INTERFACE`).
  It goes up whenever a command's output or input changes in a way that an
  older or newer reader would misread. Adding a field does not change it,
  so readers must ignore fields they do not know.
- The window checks the level at start and says so clearly when its command
  line tool reports another one.
- Before 1.0, a minor version (0.x) may change the interface; see the
  [changelog](../CHANGELOG.md).

---

## Common objects

**App summary** (`list`, `review`, `compat`, `relocate`, `profile set`, …)

| Field | Meaning |
|---|---|
| `id` | app id, e.g. `appimage-krita-1a2b` |
| `name`, `comment` | from the AppImage's desktop file, cleaned |
| `icon_path`, `source_path` | cached icon, the AppImage file |
| `state`, `badge`, `badge_label` | lifecycle state, status badge and its label; `badge` is `ready`, `needs-review`, `compatibility-mode`, `compatibility-risk`, `stale`, `broken`, `unsafe`, `missing`, `changed-outside` or `protection-missing` (`changed-outside` also when the AppImage file was replaced outside SAM; then `info`'s `entry.content_changed_outside` is `true`) |
| `category` | `browser`, `game`, `utility`, … |
| `risk` | `{level, score, items}`: the level, the weighted score, and the permissions that raise it |
| `added_at`, `last_launched` | Unix seconds (`last_launched` may be `null`) |
| `last_problem` | short text of the last failed start, or `null` |
| `terminal` | a terminal program (no window) |

**Discovered AppImage** (`discover`)

| Field | Meaning |
|---|---|
| `path`, `size` | the file and its size in bytes |
| `name`, `comment`, `version`, `categories` | read from the image without unpacking |
| `category`, `category_label` | SAM's category |
| `icon` | cached preview icon, or `null` |
| `sandboxed` | app id when a sandbox exists, else `null` |
| `moved_from` | the old path when a sandboxed AppImage was moved |
| `menu_entries` | other tools' menu entries that start this file |
| `from_menu`, `manual` | found through a menu entry; added as a single file |

**Permissions** are the profile object described in
[permissions.md](permissions.md). Keys in `set`, `get` and repair steps use the
dotted form shown there (`network.mode`, `audio.pipewire`, …).

---

## Commands

| Command | `data` |
|---|---|
| `version` | `{version, interface}` |
| `discover` | `{apps: [discovered AppImage]}` |
| `scan [DIR…] [--add]` | `{found, added}` |
| `list [filters]` | `[app summary]` |
| `info APP` | the full app record: profile, detection, warnings, logs, … |
| `preview PATH [--permissions-stdin]` | recommendation for an AppImage without a sandbox |
| `add PATH [--permissions-stdin] [--progress] […]` | `{app, entry, relocated, needs_fallback_consent, warnings}`; settings (or a preset) that give the app `/tmp` or a known socket folder in it (tmux, SSH, the X server …, see [security](security.md)) are refused with the code `tmp-grant-refused`, and an extra folder written relative (without a leading `/` or `~`) with the code `relative-grant-refused`, before anything is unpacked or added |
| `remove APP [--keep-data] [--stop]` | `{removed, warnings}` |
| `stop APP` | `{stopped}` (number of processes) |
| `run APP [ARGS]` | the launch record; an app whose settings nobody has confirmed yet (added without `--accept`) is refused until `review APP`; a start stops with the code `own-tmp-folder-unsafe` when the app's folder of its own in `/tmp` is a link, belongs to another account or others can open it, or `/tmp` does not belong to root with the sticky bit. The app's own output goes to stderr, so stdout holds the envelope alone |
| `command APP` | the generated Bubblewrap command (preview) |
| `set APP KEY VALUE [--yes]` | `{key, value, risk, warnings}`; a change that adds anything rated *Think twice* or *Dangerous* is refused with the code `change-needs-yes` unless `--yes` is given. A new grant of `/tmp` or of a known socket folder in it (tmux, SSH, the X server …, see [security](security.md)) is refused with the code `tmp-grant-refused`, also with `--yes`, and nothing changes; the refusal names the folder of the app's own (`/tmp/sam-<app id>`) and the command that grants it, which carries `--yes` for a writable folder (rated *Think twice*). A new extra folder written relative (without a leading `/` or `~`) is refused the same way with the code `relative-grant-refused` |
| `get APP [KEY]` | the value, or the whole profile |
| `profile change APP [--yes]` | reads `{"from": permissions, "to": permissions}` on stdin and applies only what differs between the two to what the app has now, so changes made elsewhere in the meantime stay; a setting changed elsewhere to another value is refused with the code `changed-meanwhile` and nothing changes; `--yes` and `tmp-grant-refused` and `relative-grant-refused` as for `set` |
| `profile get/set/reset APP` | profile; `set` reads it on stdin and, like `set`, needs `--yes` for a change that adds anything rated *Think twice* or *Dangerous* (code `change-needs-yes`); `tmp-grant-refused` and `relative-grant-refused` as for `set` |
| `evaluate APP` | risk and warnings for a profile on stdin |
| `compat APP on --yes / off` | app summary (`on`/`off` in any case; another word is refused); `on` without `--yes` is refused with the code `compat-needs-yes` (the whole session bus is a way out) |
| `args APP --stdin` | the launch arguments (JSON array on stdin) |
| `review APP` | app summary |
| `verify APP` or `verify PATH --permissions-stdin` | `{report, record}`: every check with expected and observed result |
| `hints APP [--apply ID] [--yes]` | `{hints}`; a hint rated *Think twice* or *Dangerous*, or one that turns on compatibility mode, is refused with the code `hint-needs-yes` unless `--yes` is given. A hint's `action` has a `kind`: `set`, `add`, `compat`, `add-arg`, `none`, or `replace` (`{key, from, to}`: replaces `from` with `to` in a list; the hint `tmp-own-folder` replaces an older grant of `/tmp` with the folder of the app's own) |
| `repair APP [--next/--undo/--apply ID]` | `{applied, findings, steps, applied_steps, can_undo}` |
| `selftest [APP…]` | `{results}` |
| `menu list/hide/restore APP` | `{visible, hidden}` |
| `reextract`, `redetect`, `refresh`, `relocate` | app summary plus what changed |
| `desktop APP install/remove` | `{desktop_entry}`; `desktop all refresh` → `{refreshed}` |
| `diagnose APP` | the diagnostic run (`strace`) result |
| `logs APP [--list/--file/--kind]` | file list, or `{file, kind, text}` |
| `doctor [APP]` | `{checks: [{id, label, status, detail, hint}], …}` |
| `doctor --contracts` | `{contracts: [{id, component, state, detail, on_break, assumes, playbook}], components: [{id, name, version}]}`; `state` is `holds`, `broken`, `absent` or `not-here` ([contracts](contracts.md)) |
| `report APP` | `{report}`: redacted text for a bug report |
| `preset list/show/template/apply/save/delete/duplicate/import/export/put` | the user's preset objects; `put` reads one on stdin; `import` never replaces a preset of the same name: the object it returns carries the name it got (`NAME (imported)`); a preset that holds `/tmp` or a known socket folder in it (tmux, SSH, the X server …, see [security](security.md)) is neither saved nor imported (code `tmp-grant-refused`), nor one that holds an extra folder written relative (code `relative-grant-refused`) |
| `preset apply NAME APP [--yes] [--expect FINGERPRINT]` | `{preset, check, applied, fingerprint}`; `fingerprint` names the preset's permissions as checked, and `--expect` applies only that preset: one changed since is refused and nothing is applied; `tmp-grant-refused` and `relative-grant-refused` as for `set`, also with `--yes` |
| `info APP` | the app's record; its `last_launch` has `missing_layers` (protection layers the last start lacked, for example `["Landlock"]`) and `moved_aside` (what the app left in places that would run something later, and where SAM moved it); also `repair_effects` (step id → what the step changes and costs) and `compat_changes` (the switches compatibility mode turns on, or turned on) |
| `repair APP [--apply ID / --next / --undo / --undo-step ID] [--yes]` | `--undo-step` switches off one applied step and keeps the others; a step suggested by what the app printed is refused with the code `repair-needs-yes` unless `--yes` is given; any other step rated *Think twice* or *Dangerous*, or one that turns on compatibility mode (also with `--next`), is refused with the code `step-needs-yes` unless `--yes` is given; a first-run hint applied here (same id, also a step reached with `--next` whose id matches a hint offered for the app, such as `x11`) is refused like `hints --apply`, with the code `hint-needs-yes`; the hint `tmp-own-folder` applied here is never on trial, so a failed start does not undo it |
| `group list` | every sandboxed app: the app summary plus `permissions`, `tags: [{key, label, family, level, read_only}]`, `running`, `needs_review`, `may_not_start` |
| `group set KEY VALUE APP… [--dry-run] [--yes]` | `{key, value, applied, apps: [{id, name, check, running, changed}], previous: {id: permissions}, undo: {id: {from, to}}}`; without `--yes` a change that adds anything rated *Think twice* or *Dangerous* to any of the apps is refused with the code `change-needs-yes` (`check.adds_dangerous` of a dry run lists it); a new grant of `/tmp` or of a known socket folder in it (tmux, SSH, the X server …, see [security](security.md)) is refused with the code `tmp-grant-refused` (an extra folder written relative with `relative-grant-refused`), also with `--yes` and in a dry run, and no app is changed |
| `group restore [--yes]` | reads `undo` on stdin and takes back only that change → `{restored}`; a later change to the same setting refuses the whole undo (code `changed-meanwhile`); an undo that adds something rated *Think twice* or *Dangerous* back needs `--yes` (code `change-needs-yes`); an undo that gives an app `/tmp` back is refused (code `tmp-grant-refused`) |
| `config show/get/set/put/path` | configuration; `put` reads it on stdin; `set` and `put` refuse a change that turns off Landlock or the syscall filter for every app (`security.experimental_landlock` or `security.baseline_seccomp` from `true` to `false`) with the code `config-needs-yes` unless `--yes` is given, and save nothing; turning them on and every other setting need no `--yes` |
| `permissions` | the catalogue: every key with title, explanation, risk |
| `updates [APP] [--if-due]` | `{apps: [{id, update: {state, latest, download_page, detail, checked_at}}]}`; `state` is `available`, `current`, `failed` or `unsupported` |
| `update APP [--undo] [--accept-key-change \| --decline-key-change]` | app summary; the error code `signing-key-changed` means the new file is signed with another key. With `--decline-key-change`: the app summary and `deleted` (whether a download waited for the answer and was deleted) |
| `self-update [--check]` | `{state, latest, path, detail, page}`; `state` is `current`, `available` or `updated` (only from SAM's AppImage) |
| `space [APP]` | `{apps: [{id, name, unpacked, home, overlay, logs, previous, total, can_free}], total}` (bytes) |
| `free-space APP` | `{freed}` (bytes) |
| `cleanup [--data] [--list]` | data left behind, or what was removed |
| `onboarding [done]` | `{done}` |
| `uninstall [--keep-data] [--yes]` | `{done, apps, files, dirs, problems}` |

`sam-jail <command> --help` and `man sam-jail-<command>` describe the
arguments.
