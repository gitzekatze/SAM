#!/bin/sh
# Signs the AppImages of a draft release with SAM's release key, on this
# computer (the key never goes to GitHub):
#
#   SIGN_KEY=<fingerprint> scripts/sign-release.sh vX.Y.Z
#
# The Release workflow builds and tests the AppImages and makes a draft
# release. This script downloads its AppImages, checks that each is the file
# the build job made (GitHub's build provenance: a draft can be edited, and
# the release key must never sign anything else; audit P1), checks that the
# source files match the checksums in the PKGBUILD (P13), writes the signature into
# each (SAM's self-update accepts only that), checks it, writes the .zsync
# and .sha256 files again (both depend on the signed file), adds a detached
# .asc signature for every file, and replaces the draft's files with these.
# GnuPG asks for the passphrase. Publishing the draft stays a manual step.
set -eu
die() { echo "sign-release: $*" >&2; exit 1; }
tag=${1:-}
echo "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || die "usage: SIGN_KEY=<fingerprint> scripts/sign-release.sh vX.Y.Z"
: "${SIGN_KEY:?set SIGN_KEY to the fingerprint of the release key}"
root=$(cd "$(dirname "$0")/.." && pwd)
sam="$root/target/debug/sam-jail"
[ -x "$sam" ] || sam="$root/target/release/sam-jail"
[ -x "$sam" ] || die "build SAM first (cargo build)"
gpg --batch --list-secret-keys "$SIGN_KEY" >/dev/null 2>&1 || die "no secret GPG key '$SIGN_KEY'"
[ "$(gh release view "$tag" --json isDraft --jq .isDraft)" = true ] || die "$tag is not a draft release"

dir="$root/dist/signed-$tag"
rm -rf "$dir"; mkdir -p "$dir"
gh release download "$tag" --dir "$dir" --pattern '*'
cd "$dir"
rm -f ./*.asc
set -- ./*.AppImage
[ -e "$1" ] || die "the draft has no AppImages"
for a in ./*.AppImage; do
    gh attestation verify "$a" --repo gitzekatze/SAM \
        --signer-workflow gitzekatze/SAM/.github/workflows/release.yml >/dev/null \
        || die "$(basename "$a") is not the file the release build made; not signed"
done
# The package recipes carry checksums of the source files from the local
# build (scripts/release.sh); the draft's must be the same files.
for f in ./sam-*.tar.gz ./sam-*-vendor.tar.xz; do
    [ -e "$f" ] || die "the draft has no $f"
    sum=$(sha256sum "$f" | cut -d' ' -f1)
    grep -q "$sum" "$root/packaging/arch/PKGBUILD" \
        || die "$(basename "$f") differs from the local build (PKGBUILD checksum); compare dist/SHA256SUMS"
done
for a in ./*.AppImage; do
    name=$(basename "$a")
    "$sam" dev sign-appimage "$a" --key "$SIGN_KEY"
    "$sam" dev make-zsync "$a" >/dev/null
    sha256sum "$name" > "$name.sha256"
done
for f in ./*; do
    case "$f" in *.asc) ;; *) gpg --batch --yes -u "$SIGN_KEY" --armor --detach-sign "$f" ;; esac
done
ls -l
gh release upload "$tag" ./* --clobber
echo "Signed and uploaded. Check the draft on GitHub, then publish it."
