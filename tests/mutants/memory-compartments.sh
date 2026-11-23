#!/bin/sh
# Checks scripts/mutants-cgroup.sh on this computer: inside a run limited
# to 2G, a test program that keeps taking memory is ended alone at its own
# limit (here 300M), and the run around it goes on. Needs a delegated
# systemd user scope (as scripts/mutants.sh does); says so and fails where
# there is none, never passes silently.
#   tests/mutants/memory-compartments.sh
set -u
here=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d "$here/target/memory-compartments.XXXXXX")
trap 'rm -rf "$work"' EXIT
copy="$work/cargo-mutants-check-1.tmp"
mkdir -p "$copy"
if ! systemd-run --user --scope -q -p Delegate=yes true 2>/dev/null; then
    echo "FAIL: no delegated systemd user scope here, so no memory compartments can be checked"
    exit 1
fi
# The "test program": takes 800M at once, more than its compartment's 300M
# but less than the run's 2G, then says it is still there.
cat > "$work/hog.py" <<'PY'
b = bytearray(b"x") * (800 * 1024 * 1024)
print("SURVIVED", len(b))
PY
out=$(cd "$copy" && systemd-run --user --scope -q -p Delegate=yes -p MemoryMax=2G -p MemorySwapMax=0 \
    "$here/scripts/mutants-cgroup.sh" start sh -c '
        MUTANTS_TEST_MEMORY=300M "$1" test python3 "$2"
        echo "test-exit=$?"
        echo run-goes-on' sh "$here/scripts/mutants-cgroup.sh" "$work/hog.py" </dev/null 2>&1)
echo "$out"
case "$out" in
    *SURVIVED*) echo "FAIL: the test program got more memory than its compartment allows"; exit 1 ;;
esac
case "$out" in
    *test-exit=137*run-goes-on*) echo "ok: the test program was ended alone at its limit, the run went on" ;;
    *) echo "FAIL: unexpected result"; exit 1 ;;
esac
