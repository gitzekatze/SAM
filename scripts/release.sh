#!/bin/sh
# Makes a release in one go:
#
#   scripts/release.sh X.Y.Z
#
# 1. Checks: clean tree, a new version, notes under "## Unreleased" in
#    CHANGELOG.md.
# 2. Sets the version everywhere (Cargo.toml/Cargo.lock, metainfo, Fedora
#    spec, PKGBUILD), dates the changelog section, regenerates man pages.
# 3. Runs clippy (warnings are errors). Never runs the tests itself: it
#    hands the whole test suite to the program SAM_RELEASE_TEST_COMMAND
#    names, which should run it in a container or under a separate account.
# 4. Commits "Release X.Y.Z".
# 5. Builds the release files (make dist) and, with RUNTIME set, the
#    AppImage; puts the checksums into the PKGBUILD and .SRCINFO and commits.
# 6. Tags the release commit vX.Y.Z (annotated, with the notes), only after
#    everything was built: a failed build leaves no tag behind (audit P14).
#
# Nothing is pushed or uploaded; the script prints what to do next.
#
# Required:
#   SIGN_KEY=<gpg key id>             sign the tag and the release files
#                                     (UNSIGNED=1 for an unsigned test release)
# Tests, one of the two:
#   SAM_RELEASE_TEST_COMMAND=<program> runs the whole test suite, and
#                                     should run it in a container or under
#                                     a separate account (this script does
#                                     not check where); it gets this
#                                     checkout's path as its one argument
#                                     and fails when a test fails
#   SKIP_TESTS=1                      skip clippy and tests, after the tests
#                                     passed elsewhere on this commit
# Optional:
#   RUNTIME=/path/to/runtime-ARCH     also build the AppImage (this computer's architecture)
set -eu

die() { echo "release: $*" >&2; exit 1; }

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
new=${1:-}
echo "$new" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "usage: scripts/release.sh X.Y.Z"
old=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
[ "$new" != "$old" ] || die "version $new is the current one"
[ "$(printf '%s\n%s\n' "$old" "$new" | sort -V | tail -n1)" = "$new" ] || die "$new is not newer than $old"
git rev-parse -q --verify "refs/tags/v$new" >/dev/null && die "tag v$new exists"
# Releases are signed, so packagers (AUR, COPR) can check the files.
if [ -n "${SIGN_KEY:-}" ]; then
    gpg --batch --list-secret-keys "$SIGN_KEY" >/dev/null 2>&1 || die "no secret GPG key '$SIGN_KEY'"
elif [ "${UNSIGNED:-}" != 1 ]; then
    die "set SIGN_KEY=<gpg key id> to sign the release (or UNSIGNED=1 for an unsigned test release)"
fi
# The test suite starts real sandboxes and SAM's own programs, so this
# script never runs it itself: it hands it to a program you name, which
# should run it in a container or under a separate account. This script
# does not check where that program runs the tests. Checked before
# anything is changed.
test_command=${SAM_RELEASE_TEST_COMMAND:-}
if [ "${SKIP_TESTS:-}" != 1 ] && [ -z "$test_command" ]; then
    die "this script does not run the test suite itself: set SAM_RELEASE_TEST_COMMAND=<program> to name the program that runs it (it gets this checkout's path; run the tests in a container or under a separate account), or SKIP_TESTS=1 after the tests passed elsewhere"
fi
[ -z "$(git status --porcelain)" ] || die "uncommitted changes; commit or stash them first"

# Release notes: the Unreleased section, with the note files of changes/
# moved into it first (one file per change, see changes/README.md).
python3 scripts/changes.py collect
notes=$(awk '/^## Unreleased/{f=1; next} /^## /{f=0} f' CHANGELOG.md | sed -e '/./,$!d')
[ -n "$(echo "$notes" | tr -d '[:space:]')" ] || die "CHANGELOG.md has no notes under '## Unreleased'"

date=$(date +%Y-%m-%d)
rpmdate=$(LC_ALL=C date '+%a %b %d %Y')
who="$(git config user.name) <$(git config user.email)>"
echo "== SAM $old -> $new ($date)"

# 2. Version everywhere.
sed -i "0,/^version = \"$old\"/s//version = \"$new\"/" Cargo.toml
cargo update --workspace --offline >/dev/null 2>&1 || cargo update --workspace >/dev/null
sed -i "s/^## Unreleased$/## Unreleased\n\n## $new - $date/" CHANGELOG.md
sed -i "s|<releases>|<releases>\n    <release version=\"$new\" date=\"$date\"/>|" data/io.github.gitzekatze.SAM.metainfo.xml
sed -i -e "s/^Version: .*/Version:        $new/" -e "s/^Release: .*/Release:        1%{?dist}/" \
    -e "s/^%changelog$/%changelog\n* $rpmdate $who - $new-1\n- SAM $new, see CHANGELOG.md.\n/" packaging/fedora/sam-jail.spec
sed -i -e "s/^pkgver=.*/pkgver=$new/" -e "s/^pkgrel=.*/pkgrel=1/" packaging/arch/PKGBUILD
cargo build --release --locked -p sam-jail-cli >/dev/null
sh scripts/check-release-build.sh target/release/sam-jail >/dev/null
SAM_MAN_DATE=$date target/release/sam-jail man data/man >/dev/null
sed -i "s/^\.TH \(sam-jail-[a-z]*\) 1 \"[0-9-]*\"/.TH \1 1 \"$date\"/" data/man/sam-jail-run.1 data/man/sam-jail-gui.1
appstreamcli validate --no-net data/io.github.gitzekatze.SAM.metainfo.xml >/dev/null 2>&1 || die "metainfo does not validate"

# 3. Checks.
if [ "${SKIP_TESTS:-}" != 1 ]; then
    echo "== clippy and tests"
    cargo clippy --workspace --all-targets --locked -- -D warnings
    # A sandbox test that cannot build its sandbox fails instead of passing
    # without testing: a release is tested with its sandbox. The program
    # gets this setting and must pass it on to the tests.
    SAM_REQUIRE_SANDBOX=1 "$test_command" "$root" || {
        status=$?
        die "the test program SAM_RELEASE_TEST_COMMAND=$test_command failed (exit status $status); the release stopped before its commit"
    }
fi

# 4. Commit. The tag comes last, after the build (step 6).
git add -A
git commit -q -m "Release $new" -m "$notes"
release_commit=$(git rev-parse HEAD)
trap 'echo "release: stopped before the tag; start again with: git reset --hard $release_commit~1" >&2' EXIT

# 5. Release files, AppImage, PKGBUILD checksums (built from the release
# commit; make-release.sh notes that there is no tag yet).
echo "== release files"
make dist >/dev/null
if [ -n "${RUNTIME:-}" ]; then
    RUNTIME="$RUNTIME" make appimage >/dev/null
fi
src=$(sha256sum "dist/sam-$new.tar.gz" | cut -d' ' -f1)
vendor=$(sha256sum "dist/sam-$new-vendor.tar.xz" | cut -d' ' -f1)
awk -v a="$src" -v b="$vendor" '
    /^sha256sums=\(/ { print "sha256sums=('"'"'" a "'"'"'"; print "            '"'"'" b "'"'"')"; skip=1; next }
    skip && /\)/ { skip=0; next }
    skip { next }
    { print }' packaging/arch/PKGBUILD > packaging/arch/PKGBUILD.new
mv packaging/arch/PKGBUILD.new packaging/arch/PKGBUILD
(cd packaging/arch && makepkg --printsrcinfo > .SRCINFO)
git add packaging/arch/PKGBUILD packaging/arch/.SRCINFO
git commit -q -m "PKGBUILD: checksums for the $new release files"

# 6. Tag the release commit.
if [ -n "${SIGN_KEY:-}" ]; then
    git tag -s -u "$SIGN_KEY" "v$new" -m "SAM $new" -m "$notes" "$release_commit"
else
    git tag -a "v$new" -m "SAM $new" -m "$notes" "$release_commit"
fi
trap - EXIT
if [ -n "${SIGN_KEY:-}" ]; then
    for f in dist/sam-$new.tar.gz dist/sam-$new-vendor.tar.xz dist/SAM-$new-*.AppImage dist/SHA256SUMS; do
        [ -f "$f" ] && gpg --batch --yes -u "$SIGN_KEY" --armor --detach-sign "$f"
    done
fi

echo
echo "SAM $new is ready (not pushed). Next:"
echo "  git push -u origin $(git branch --show-current) v$new, then a pull request into main, merged with a merge commit"
echo "  GitHub release v$new with the files in dist/ (the CI draft has them; add the .asc signatures):"
for f in dist/*"$new"*; do [ -e "$f" ] && echo "    ${f#dist/}"; done
echo "  AUR: copy packaging/arch/PKGBUILD and .SRCINFO into the AUR repository and push"
