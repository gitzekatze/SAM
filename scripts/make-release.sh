#!/bin/sh
# Builds release tarballs for distribution packaging.
#
#   scripts/make-release.sh [OUTDIR]
#
# Writes to OUTDIR (default: ./dist):
#   sam-VERSION.tar.gz           the source of the tag vVERSION (or HEAD)
#   sam-VERSION-vendor.tar.xz    every Rust crate (vendor/) plus the Cargo
#                                config that builds offline from it
#   SHA256SUMS
#
# Distribution builders (COPR, OBS, Launchpad) have no network access:
# unpack both tarballs into one folder and build with `cargo build --frozen`.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
[ -n "$version" ] || { echo "no version in Cargo.toml" >&2; exit 1; }
out=$(mkdir -p "${1:-dist}" && cd "${1:-dist}" && pwd)
name="sam-$version"

if git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
    ref="v$version"
else
    ref=HEAD
    echo "note: no tag v$version, using HEAD" >&2
fi
if [ -n "$(git status --porcelain)" ]; then
    echo "note: uncommitted changes are not included" >&2
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/sam-release.XXXXXX")
trap 'rm -rf "$work"' EXIT

# Source: exactly what git has for the ref.
git archive --format=tar --prefix="$name/" "$ref" | gzip -9n > "$out/$name.tar.gz"

# Vendored crates, from the same Cargo.lock.
mkdir -p "$work/$name/.cargo"
git archive --format=tar "$ref" Cargo.toml Cargo.lock crates | tar -x -C "$work/$name"
(cd "$work/$name" && cargo vendor --locked --versioned-dirs vendor > .cargo/config.toml)
tar -C "$work" -cJf "$out/$name-vendor.tar.xz" "$name/vendor" "$name/.cargo/config.toml"

(cd "$out" && sha256sum "$name.tar.gz" "$name-vendor.tar.xz" > SHA256SUMS)
echo "Wrote $out/$name.tar.gz, $out/$name-vendor.tar.xz and SHA256SUMS ($ref)"
