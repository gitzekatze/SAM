# JSON interface

Every `sam-jail` command accepts `--json`. The window of SAM - Sandboxed
AppImage Manager uses nothing else: the command line is SAM's API. Scripts
can rely on it in the same way.

---

## Envelope

A command prints exactly one JSON object on the last line of stdout:

```json
{"ok": true, "data": …}
{"ok": false, "error": "human readable message"}
```

The exit status is 0 for `ok: true` and 1 otherwise. Text on stderr is for
people, not for parsing.

Commands that take a whole object (a profile, a preset, the configuration)
read it as JSON on stdin; the flag or subcommand is named in the table below.

## Versions

```sh
sam-jail --json version
{"ok": true, "data": {"version": "0.1.0", "interface": 1}}
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
| `state`, `badge`, `badge_label` | lifecycle state, status badge and its label |
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
[profiles.md](profiles.md). Keys in `set`, `get` and repair steps use the
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
| `add PATH [--permissions-stdin] […]` | `{app, entry, relocated, needs_fallback_consent, warnings}` |
| `remove APP [--keep-data] [--stop]` | `{removed, warnings}` |
| `stop APP` | `{stopped}` (number of processes) |
| `run APP [ARGS]` | the launch record |
| `command APP` | the generated Bubblewrap command (preview) |
| `set APP KEY VALUE` | `{key, value, risk, warnings}` |
| `get APP [KEY]` | the value, or the whole profile |
| `profile get/set/reset APP` | profile; `set` reads it on stdin |
| `evaluate APP` | risk and warnings for a profile on stdin |
| `compat APP on/off` | app summary |
| `args APP --stdin` | the launch arguments (JSON array on stdin) |
| `review APP` | app summary |
| `verify APP` or `verify PATH --permissions-stdin` | `{report, record}`: every check with expected and observed result |
| `hints APP [--apply ID]` | `{hints}` |
| `repair APP [--next/--undo/--apply ID]` | `{applied, findings, steps, applied_steps, can_undo}` |
| `selftest [APP…]` | `{results}` |
| `menu list/hide/restore APP` | `{visible, hidden}` |
| `reextract`, `redetect`, `refresh`, `relocate` | app summary plus what changed |
| `desktop APP create/remove/refresh` | `{desktop_entry}`; `desktop all refresh` → `{refreshed}` |
| `diagnose APP` | the diagnostic run (`strace`) result |
| `logs APP [--list/--file/--kind]` | file list, or `{file, kind, text}` |
| `doctor [APP]` | `{checks: [{id, label, status, detail, hint}], …}` |
| `report APP` | `{report}`: redacted text for a bug report |
| `preset list/show/apply/check/save/delete/duplicate/import/export/put` | preset objects; `put` reads one on stdin |
| `config show/get/set/put/path` | configuration; `put` reads it on stdin |
| `permissions` | the catalogue: every key with title, explanation, risk |
| `updates [APP] [--if-due]` | `{apps: [{id, update: {state, latest, download_page, detail, checked_at}}]}`; `state` is `available`, `current`, `failed` or `unsupported` |
| `update APP [--undo] [--accept-key-change]` | app summary; an error starting with `signing key changed` means the new file is signed with another key |
| `space [APP]` | `{apps: [{id, name, unpacked, home, overlay, logs, previous, total, can_free}], total}` (bytes) |
| `free-space APP` | `{freed}` (bytes) |
| `cleanup [--data] [--list]` | data left behind, or what was removed |
| `onboarding [done]` | `{done}` |
| `uninstall [--keep-data] [--yes]` | `{done, apps, files, dirs, problems}` |

`sam-jail <command> --help` and `man sam-jail-<command>` describe the
arguments.
