#!/bin/sh
# Signs the AppImages of a draft release with SAM's release key, on this
# computer (the key never goes to GitHub):
#
#   SIGN_KEY=<fingerprint> scripts/sign-release.sh vX.Y.Z
#
# The Release workflow builds and tests the AppImages and makes a draft
# release. This script downloads its AppImages, writes the signature into
# each (SAM's self-update accepts only that), checks it, writes the .zsync
# and .sha256 files again (both depend on the signed file), adds a detached
# .asc signature for every file, and replaces the draft's files with these.
# GnuPG asks for the passphrase. Publishing the draft stays a manual step.
set -eu
die() { echo "sign-release: $*" >&2; exit 1; }
tag=${1:-}
echo "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || die "usage: SIGN_KEY=<fingerprint> scripts/sign-release.sh vX.Y.Z"
: "${SIGN_KEY:?set SIGN_KEY to the release key's fingerprint}"
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
