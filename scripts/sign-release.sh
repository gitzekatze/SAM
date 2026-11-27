#!/bin/sh
# Signs the AppImages of a draft release with SAM's release key, on this
# computer (the key never goes to GitHub):
#
#   SIGN_KEY=<fingerprint> scripts/sign-release.sh vX.Y.Z
#
# The Release workflow builds and tests the AppImages and makes a draft
# release. This script downloads the draft's files and checks every one
# before the release key touches any (a draft can be edited, and the release
# key must never sign anything else; audit P1):
#   - each AppImage, and every file this script does not write itself (the
#     SBOM, for example), must be the file the release build of this very
#     tag made (GitHub's build provenance, bound to refs/tags/vX.Y.Z: a file
#     from an older release's build is refused too);
#   - the source tarballs must match the checksums in the PKGBUILD (P13);
#   - SHA256SUMS and each AppImage's .zsync and .sha256 are written again
#     here from the checked files, never taken from the draft.
# A file that passes none of these stops the script before anything is
# signed. Then it writes the signature into each AppImage (SAM's
# self-update accepts only that), adds a detached .asc signature for every
# file, and replaces the draft's files with these. GnuPG asks for the
# passphrase. Publishing the draft stays a manual step.
set -eu
die() { echo "sign-release: $*" >&2; exit 1; }
tag=${1:-}
echo "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || die "usage: SIGN_KEY=<fingerprint> scripts/sign-release.sh vX.Y.Z"
: "${SIGN_KEY:?set SIGN_KEY to the fingerprint of the release key}"
root=$(cd "$(dirname "$0")/.." && pwd)
# The signing tool is a release build with SAM's release tools switched
# on, so it runs like the shipped program (developer variables off; owner
# decision 2026-11-27). A plain release build no longer has the tools.
sam="$root/target/sign-tools/release/sam-jail"
[ -x "$sam" ] || die "build the signing tool first: cargo build --release --locked --target-dir target/sign-tools -p sam-jail-cli --features dev-tools"
gpg --batch --list-secret-keys "$SIGN_KEY" >/dev/null 2>&1 || die "no secret GPG key '$SIGN_KEY'"
[ "$(gh release view "$tag" --json isDraft --jq .isDraft)" = true ] || die "$tag is not a draft release"

dir="$root/dist/signed-$tag"
rm -rf "$dir"; mkdir -p "$dir"
gh release download "$tag" --dir "$dir" --pattern '*'
cd "$dir"
rm -f ./*.asc
set -- ./*.AppImage
[ -e "$1" ] || die "the draft has no AppImages"
# GitHub's build provenance: built by release.yml from this tag, not from an
# older one (a replayed older AppImage would otherwise pass).
made_by_release() {
    gh attestation verify "$1" --repo gitzekatze/SAM \
        --signer-workflow gitzekatze/SAM/.github/workflows/release.yml \
        --source-ref "refs/tags/$tag" >/dev/null
}
for f in ./*; do
    case "$f" in
        *.asc) ;;
        # Written again below from the checked files.
        ./SHA256SUMS) ;;
        *.AppImage.zsync | *.AppImage.sha256)
            [ -e "${f%.*}" ] || die "$(basename "$f") belongs to no AppImage of the draft; nothing signed" ;;
        # The package recipes carry checksums of the source files from the
        # local build (scripts/release.sh); the draft's must be the same files.
        ./sam-*-vendor.tar.xz | ./sam-*.tar.gz)
            sum=$(sha256sum "$f" | cut -d' ' -f1)
            grep -q "$sum" "$root/packaging/arch/PKGBUILD" \
                || die "$(basename "$f") differs from the local build (PKGBUILD checksum); compare dist/SHA256SUMS" ;;
        *)
            made_by_release "$f" \
                || die "$(basename "$f") is not a file the release build of $tag made; nothing signed" ;;
    esac
done
for f in ./sam-*.tar.gz ./sam-*-vendor.tar.xz; do
    [ -e "$f" ] || die "the draft has no $f"
done
# The list of the source files' checksums, as make-release.sh writes it.
sha256sum sam-*.tar.gz sam-*-vendor.tar.xz > SHA256SUMS
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
