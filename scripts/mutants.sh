#!/bin/sh
# Mutation testing with the settings that make its result true:
#   scripts/mutants.sh [-o OUTDIR] FILE...         these files
#   scripts/mutants.sh [-o OUTDIR] --diff BASE     the code changed since BASE
# then the result by SAM function (scripts/mutants-report.py).
#
# Why each setting (each was learned the hard way, 2026-11-16/17):
# - the whole workspace is tested for every change (--test-workspace=true,
#   never -p): the sandbox tests need sam-jail-run from sam-jail-cli;
# - our own baseline instead of cargo-mutants' (which tests only the mutated
#   packages, where the helper is not built, so it fails): the whole suite
#   must pass on the unchanged code first. A test that always fails would
#   count every change as caught (2026-11-17: 231 of 357 "caught" changes);
#   the report also refuses a run with a test that never passed;
# - SAM_REQUIRE_SANDBOX=1: a test that cannot run fails instead of passing
#   silently (tests find the helper of their own build, find_helper);
# - SAM_TEST_GPG=1 when GnuPG is here, as in CI;
# - its own runtime folder, short and under /run/user (a socket path may be
#   at most 108 characters): changes that break SAM's cleanup leave folders
#   behind there, never in the real runtime folder;
# - two changes at a time (JOBS=2): each runs the whole suite, and more at
#   once ran out of memory on a 64 GB computer;
# - the copies outside /tmp (TMPDIR for cargo-mutants, which copies the tree
#   there), the tests' own temporary folders in /tmp as always (Cargo's env
#   setting): a test that must not run below /tmp (the breakout test) failed
#   in every copy and made 257 of 695 changes look caught (2026-11-22), and
#   a longer temporary path breaks socket tests (108 characters at most);
# - ten minutes per change (--timeout 600): with six changes at once the
#   whole suite took about 240 s, so changes that make no difference were
#   cut off and counted as caught (2026-11-23).
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
out="$here/target/mutants"
if [ "${1:-}" = "-o" ]; then out=$2; shift 2; fi
[ $# -gt 0 ] || { sed -n '2,5p' "$0"; exit 2; }
run="$out/run"
if [ -d "/run/user/$(id -u)" ]; then run="/run/user/$(id -u)/sam-mutants-$$"; fi
mkdir -p "$out" "$run" "$out/copies"
chmod 700 "$run"
tests_tmp=${TMPDIR:-/tmp}
export TMPDIR="$out/copies"
case "$out" in
    /tmp/* | /var/tmp/*) echo "the output folder must not be below /tmp or /var/tmp: $out" >&2; exit 2 ;;
esac
export XDG_RUNTIME_DIR="$run" SAM_REQUIRE_SANDBOX=1
if command -v gpg >/dev/null && command -v gpgv >/dev/null; then export SAM_TEST_GPG=1; fi
if [ "$1" = "--diff" ]; then
    git -C "$here" diff "${2:-origin/main}" -- 'crates/*.rs' 'crates/**/*.rs' > "$out/changes.diff"
    if [ ! -s "$out/changes.diff" ]; then
        echo "No Rust code changed since ${2:-origin/main}: nothing to test."
        exit 0
    fi
    sel="--in-diff $out/changes.diff"
else
    sel=$(for f in "$@"; do printf -- '--file %s ' "$f"; done)
fi
cd "$here"
echo "Baseline: the whole suite on the unchanged code (log: $out/baseline.log)"
if ! cargo test --workspace --no-fail-fast --config "env.TMPDIR.value=\"$tests_tmp\"" \
    --config 'env.TMPDIR.force=true' > "$out/baseline.log" 2>&1; then
    echo "The unchanged code fails here, so no change could be judged:"
    grep -E '^test .* FAILED$|panicked at' -A1 "$out/baseline.log" | head -20
    exit 1
fi
# shellcheck disable=SC2086 # $sel is a list of options on purpose
cargo mutants $sel --test-workspace=true --baseline=skip --timeout 600 --build-timeout 600 \
    --cargo-arg=--config --cargo-arg="env.TMPDIR.value=\"$tests_tmp\"" \
    --cargo-arg=--config --cargo-arg='env.TMPDIR.force=true' \
    -j "${JOBS:-2}" -o "$out" || true
python3 "$here/scripts/mutants-report.py" "$out"
