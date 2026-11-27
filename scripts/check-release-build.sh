#!/bin/sh
# Checks that a freshly built sam-jail ignores SAM's developer variables, as
# a release build must:
#
#   scripts/check-release-build.sh path/to/sam-jail
#
# SAM's developer variables (SAM_CONFIG_DIR, SAM_DATA_DIR, SAM_CLI,
# SAM_TRUST_TOOLS_IN, ...) all work only where debug assertions are on
# (DeveloperVars in crates/sam-core/src/util.rs). The repository's own build
# settings never turn them on for a release build
# (crates/sam-jail-cli/tests/automation.rs), but Cargo also takes profile
# settings and compiler flags from outside the repository: from variables
# in the builder's environment (CARGO_PROFILE_RELEASE_*, RUSTFLAGS) and from
# Cargo configuration files in CARGO_HOME or in a folder above the source.
# So this asks the built program itself. Started with SAM's folder switches
# pointing at a folder of their own, it must name the standard folders below
# a fresh home folder; a program that follows the switches would follow
# every other developer variable too, and the build is refused.
#
# The other programs of a release (sam-jail-run, sam-jail-gui) come from the
# same build and share the crate that reads the variables (sam-core), so
# the answer holds for them, unless a Cargo configuration changes the
# release profile of one package only.
#
# The check cannot reach the real home folder or the real SAM folders, even
# when the built program is wrong: the program starts with an empty
# environment (env -i) inside the temporary folder, with HOME, every XDG
# folder, TMPDIR and SAM's own folder switches pointing into it, and the
# temporary folder is removed afterwards, also when the check is stopped.
# The check fails closed: a missing program, a program that fails, and an
# answer that is missing a folder, names another folder or names any path
# outside the temporary folder all stop the build.
set -eu
die() { echo "check-release-build: $*" >&2; exit 1; }
sam=${1:-}
[ -n "$sam" ] || die "usage: scripts/check-release-build.sh path/to/sam-jail"
[ -f "$sam" ] && [ -x "$sam" ] || die "no program at $sam"
# The program starts inside the temporary folder, so a relative path is
# made absolute first.
case "$sam" in /*) ;; *) sam="$PWD/$sam" ;; esac
work=$(mktemp -d "${TMPDIR:-/tmp}/sam-release-check.XXXXXX") || die "no temporary folder"
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM
home="$work/home"
switched="$work/switched"
mkdir -p "$home" "$switched" "$work/tmp" "$work/runtime" "$work/system-config" "$work/system-data"
chmod 0700 "$work/runtime"
# Only what the check needs: every folder below the temporary folder, no
# other SAM variables, and no language setting from the caller (the answer
# is read in English). XDG_CONFIG_HOME and XDG_DATA_HOME name the standard
# folders below the fresh home folder, so the expected answer stays the same
# whether the program reads them or HOME.
out=$( (cd "$work" && exec env -i PATH="${PATH:-/usr/bin:/bin}" HOME="$home" LC_ALL=C \
    TMPDIR="$work/tmp" \
    XDG_CONFIG_HOME="$home/.config" \
    XDG_DATA_HOME="$home/.local/share" \
    XDG_CACHE_HOME="$home/.cache" \
    XDG_STATE_HOME="$home/.local/state" \
    XDG_RUNTIME_DIR="$work/runtime" \
    XDG_CONFIG_DIRS="$work/system-config" \
    XDG_DATA_DIRS="$work/system-data" \
    SAM_CONFIG_DIR="$switched/config" \
    SAM_DATA_DIR="$switched/data" \
    SAM_APPLICATIONS_DIR="$switched/applications" \
    SAM_RUNTIME_DIR="$switched/runtime" \
    "$sam" config path) 2>&1) || die "$sam config path failed: $out"
case "$out" in
    *"$switched"*)
        die "$sam follows SAM's developer variables, like a developer build: debug assertions are on in this release build. Look for Cargo profile settings in the environment (CARGO_PROFILE_RELEASE_*), compiler flags (RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS) and Cargo configuration files in CARGO_HOME or above the source folder. It answered:
$out" ;;
esac
# Every line of the answer is `KEY   /path`, with the path below the fresh
# home folder: anything else is an answer this check does not understand.
printf '%s\n' "$out" | while IFS= read -r line; do
    path=$(printf '%s\n' "$line" | sed -n 's/^[a-z_][a-z_]*  *//p')
    case "$path" in
        *"/../"* | *"/.." | "") bad=1 ;;
        "$home"/*) bad= ;;
        *) bad=1 ;;
    esac
    [ -z "$bad" ] || die "$sam answered a line this check does not expect: '$line'. It answered:
$out"
done || exit 1
# The folder named after KEY in the answer (`KEY   /path`).
folder() { printf '%s\n' "$out" | sed -n "s/^$1  *//p"; }
for expect in \
    "config_file=$home/.config/sam/config.toml" \
    "data_dir=$home/.local/share/sam" \
    "applications=$home/.local/share/applications"; do
    key=${expect%%=*}
    want=${expect#*=}
    got=$(folder "$key")
    [ "$got" = "$want" ] || die "$sam names $key '$got', expected '$want'. It answered:
$out"
done
echo "check-release-build: $sam ignores SAM's developer variables"
