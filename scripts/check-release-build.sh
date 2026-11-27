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
# Everything the program writes stays in a temporary folder, which is
# removed afterwards.
set -eu
die() { echo "check-release-build: $*" >&2; exit 1; }
sam=${1:-}
[ -n "$sam" ] || die "usage: scripts/check-release-build.sh path/to/sam-jail"
[ -f "$sam" ] && [ -x "$sam" ] || die "no program at $sam"
work=$(mktemp -d "${TMPDIR:-/tmp}/sam-release-check.XXXXXX")
trap 'rm -rf "$work"' EXIT
home="$work/home"
switched="$work/switched"
mkdir -p "$home" "$switched"
# Only what the check needs: no XDG folders, no other SAM variables, and no
# language setting from the caller (the answer is read in English).
out=$(env -i PATH="${PATH:-/usr/bin:/bin}" HOME="$home" LC_ALL=C \
    SAM_CONFIG_DIR="$switched/config" \
    SAM_DATA_DIR="$switched/data" \
    SAM_APPLICATIONS_DIR="$switched/applications" \
    "$sam" config path 2>&1) || die "$sam config path failed: $out"
case "$out" in
    *"$switched"*)
        die "$sam follows SAM's developer variables, like a developer build: debug assertions are on in this release build. Look for Cargo profile settings in the environment (CARGO_PROFILE_RELEASE_*), compiler flags (RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS) and Cargo configuration files in CARGO_HOME or above the source folder. It answered:
$out" ;;
esac
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
