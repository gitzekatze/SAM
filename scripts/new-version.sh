#!/bin/sh
# Publishes a new version of SAM in one go, up to the last click:
#
#   scripts/new-version.sh X.Y.Z            do it
#   scripts/new-version.sh X.Y.Z --dry-run  only check that everything is ready
#
# 1. Checks: the version is new, the tree is clean, a program to run the
#    tests is named (SAM_RELEASE_TEST_COMMAND, or SKIP_TESTS=1 after they
#    passed elsewhere), main matches GitHub, the last CI run on it passed,
#    the release key is here, gh is signed in, and data made by the last
#    released version still works (tests/upgrade/run.sh).
# 2. Asks once for the release key's passphrase and keeps GnuPG from
#    forgetting it while the release runs (GnuPG forgets after 10 minutes
#    without use; a tiny signature every 5 minutes keeps it).
# 3. scripts/release.sh, on a branch release-X.Y.Z (main is protected and
#    takes changes only through pull requests): version everywhere, all
#    tests through the program SAM_RELEASE_TEST_COMMAND names (release.sh
#    runs none on this computer), signed tag.
# 4. Pushes the branch and the tag and opens the pull request "Release
#    X.Y.Z". GitHub builds and tests the AppImages from the tag and makes a
#    draft release (about 45 minutes); waits for it and shows a spinner with
#    the minutes and the jobs done meanwhile.
# 5. scripts/sign-release.sh: seals the draft's AppImages with the key.
# 6. Waits for the pull request's checks and merges it with a merge commit,
#    so the tagged commit is part of main's history (a squash merge would
#    leave the tag outside main, and the next release's upgrade test could
#    not find it).
#
# Then it prints the draft's address: publishing it is your click.
# If anything fails, it stops and says what; nothing is published.
set -eu

die() { echo; echo "new-version: $*" >&2; exit 1; }
step() { echo; echo "== $*"; }

# Waits for a GitHub Actions run and shows that it is still going: a
# spinner with the minutes and the jobs done, updated in place (a line every
# 5 minutes when the output is not a terminal). Fails if the run fails.
wait_for_run() {
    run=$1 what=$2
    start=$(date +%s) i=0 info="starting"
    while :; do
        state=$(gh run view "$run" --json status,conclusion,jobs \
            --jq '[.status, (if (.conclusion // "") == "" then "-" else .conclusion end), ([.jobs[]|select(.status=="completed")]|length), (.jobs|length)] | map(tostring) | join(" ")' 2>/dev/null || echo "unknown")
        set -- $state
        status=${1:-unknown} conclusion=${2:-} done_jobs=${3:-0} all_jobs=${4:-0}
        if [ "$status" = completed ]; then
            [ -t 1 ] && printf '\r\033[K'
            mins=$(( ($(date +%s) - start) / 60 ))
            if [ "$conclusion" = success ]; then
                echo "✓ $what: finished after $mins min."
                return 0
            fi
            echo "✗ $what: $conclusion after $mins min."
            return 1
        fi
        [ "$all_jobs" -gt 0 ] && info="$done_jobs of $all_jobs jobs done" || info="starting"
        # Show the spinner for 30 seconds, then ask GitHub again.
        for _ in $(seq 30); do
            mins=$(( ($(date +%s) - start) / 60 ))
            if [ -t 1 ]; then
                i=$(( (i + 1) % 10 ))
                case $i in 0) f=⠋ ;; 1) f=⠙ ;; 2) f=⠹ ;; 3) f=⠸ ;; 4) f=⠼ ;; 5) f=⠴ ;; 6) f=⠦ ;; 7) f=⠧ ;; 8) f=⠇ ;; *) f=⠏ ;; esac
                printf '\r\033[K%s %s: %s min, %s' "$f" "$what" "$mins" "$info"
            elif [ $(( ($(date +%s) - start) % 300 )) -lt 1 ]; then
                echo "  still running: $mins min, $info"
            fi
            sleep 1
        done
    done
}

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
new=${1:-}
dry=${2:-}
echo "$new" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "usage: scripts/new-version.sh X.Y.Z [--dry-run]"
[ -z "$dry" ] || [ "$dry" = --dry-run ] || die "unknown option '$dry'"
tag="v$new"
branch="release-$new"

# The release key: the first fingerprint built into SAM.
key=$(sed -n 's/^ *"\([0-9A-F]\{40\}\)",.*/\1/p' crates/sam-runner/src/release_key.rs | head -n1)
[ -n "$key" ] || die "no release key in crates/sam-runner/src/release_key.rs"

step "Checking that everything is ready"
old=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
[ "$(printf '%s\n%s\n' "$old" "$new" | sort -V | tail -n1)" = "$new" ] && [ "$new" != "$old" ] || die "$new is not newer than the current version $old"
git rev-parse -q --verify "refs/tags/$tag" >/dev/null && die "the tag $tag exists already"
git rev-parse -q --verify "refs/heads/$branch" >/dev/null && die "the branch $branch exists already; delete it if it is left over from a failed try (git branch -D $branch)"
[ "$(git branch --show-current)" = main ] || die "switch to the main branch first"
[ -z "$(git status --porcelain)" ] || die "there are uncommitted changes; commit or stash them first"
# scripts/release.sh runs no tests on this computer and stops without a
# program that runs them elsewhere; checked here, so the dry run says so and
# the real run stops before it makes the branch.
if [ "${SKIP_TESTS:-}" != 1 ] && [ -z "${SAM_RELEASE_TEST_COMMAND:-}" ]; then
    die "the test suite does not run on this computer: set SAM_RELEASE_TEST_COMMAND=<program> to run it elsewhere (for example in a container; it gets this checkout's path), or SKIP_TESTS=1 after the tests passed elsewhere"
fi
command -v gh >/dev/null || die "the GitHub command line (gh) is not installed"
gh auth status >/dev/null 2>&1 || die "gh is not signed in: run 'gh auth login'"
git fetch -q origin main
git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1 && die "the branch $branch exists on GitHub already; delete it there if it is left over from a failed try"
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || die "main differs from GitHub: push or pull first"
ci=$(gh run list --workflow ci.yml --branch main --commit "$(git rev-parse HEAD)" --json conclusion --jq '.[0].conclusion' 2>/dev/null || true)
[ "$ci" = success ] || die "the CI run for the current commit has not passed (status: ${ci:-none yet}); wait for it or fix it first"
gpg --batch --list-secret-keys "$key" >/dev/null 2>&1 || die "the release key $key is not on this computer (import it from your backup: gpg --import; see docs/handbook/care.md)"
python3 scripts/changes.py has-notes || die "nothing to release: no notes in changes/ and none under '## Unreleased' in CHANGELOG.md"
# Data made by the last released version must still work.
last=$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || true)
if [ -n "$last" ]; then
    step "Checking that data from SAM $last still works (a few minutes)"
    cargo build -q --locked -p sam-jail-cli
    mkdir -p "$root/target"
    if ! sh tests/upgrade/run.sh "$last" "$root/target/upgrade-test" >"$root/target/upgrade-test.log" 2>&1; then
        grep -E '^(FAIL|RESULT)' "$root/target/upgrade-test.log" || tail -n 20 "$root/target/upgrade-test.log"
        die "data from SAM $last does not work with this version (target/upgrade-test.log); tell Claude"
    fi
    grep -c '^ok' "$root/target/upgrade-test.log" | sed 's/^/upgrade checks passed: /'
fi
echo "Version $old -> $new, release key $key: ready."
if [ "$dry" = --dry-run ]; then
    echo "Dry run: nothing was changed."
    exit 0
fi

step "Unlocking the release key (GnuPG asks for the passphrase)"
work=$(mktemp -d "${TMPDIR:-/tmp}/sam-new-version.XXXXXX")
keepalive=
cleanup() {
    [ -z "$keepalive" ] || kill "$keepalive" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM
echo "unlock" > "$work/unlock"
gpg --yes -u "$key" --detach-sign -o "$work/unlock.sig" "$work/unlock" || die "the key could not be unlocked"
# Keep GnuPG from forgetting the passphrase while the release runs.
( while sleep 300; do gpg --batch --yes -u "$key" --detach-sign -o "$work/alive.sig" "$work/unlock" 2>/dev/null || true; done ) &
keepalive=$!

step "Tagging $tag on the branch $branch (the tests run first, through SAM_RELEASE_TEST_COMMAND; this takes a while)"
git switch -q -c "$branch"
SIGN_KEY="$key" scripts/release.sh "$new"

step "Pushing to GitHub and opening the pull request"
git push -q -u origin "$branch"
git push -q origin "$tag"
notes=$(awk '/^## \[?'"$new"'/{f=1; next} /^## /{f=0} f' CHANGELOG.md | sed -e '/./,$!d')
gh pr create --base main --head "$branch" --title "Release $new" \
    --body "$(printf 'SAM %s. Made by scripts/new-version.sh; merge it with a merge commit (the script does).\n\n%s' "$new" "$notes")" >/dev/null \
    || die "the pull request could not be opened; open it for the branch $branch on GitHub and tell Claude"

step "Waiting for GitHub to build and test the AppImages (about 45 minutes)"
run=
for _ in $(seq 60); do
    run=$(gh run list --workflow release.yml --branch "$tag" --json databaseId --jq '.[0].databaseId' 2>/dev/null || true)
    [ -n "$run" ] && break
    sleep 10
done
[ -n "$run" ] || die "GitHub did not start the release build for $tag; look at the Actions tab and tell Claude"
wait_for_run "$run" "GitHub is building and testing" || die "GitHub's release build failed: nothing was published. Tell Claude (run $run)"
[ "$(gh release view "$tag" --json isDraft --jq .isDraft 2>/dev/null)" = true ] || die "the build passed but no draft release $tag exists; tell Claude"

step "Sealing the AppImages with the release key"
SIGN_KEY="$key" scripts/sign-release.sh "$tag"

step "Waiting for the pull request's checks, then merging it into main"
sleep 20
gh pr checks "$branch" --watch --fail-fast --interval 60 >/dev/null 2>&1 \
    || die "the checks of the pull request 'Release $new' failed; the draft release is ready but main does not have the release yet. Tell Claude"
gh pr merge "$branch" --merge --delete-branch >/dev/null \
    || die "the pull request 'Release $new' could not be merged; merge it on GitHub with 'Create a merge commit'"
git switch -q main
git pull -q --ff-only origin main

url=$(gh release view "$tag" --json url --jq .url)
step "Done: SAM $new is ready to publish"
echo "Open $url"
echo "check the files and notes, then click 'Publish release'."
