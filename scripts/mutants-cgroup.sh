#!/bin/sh
# Memory compartments for a mutation run (used by scripts/mutants.sh):
#   mutants-cgroup.sh start COMMAND...   inside a delegated systemd scope:
#       moves itself into a "main" compartment, lets the scope's children
#       have memory limits, then runs COMMAND (cargo mutants);
#   mutants-cgroup.sh test PROGRAM...    Cargo's test runner: each copy's
#       test programs run in their own compartment with
#       MUTANTS_TEST_MEMORY (6G), then PROGRAM.
#
# Why: a change can make a test use memory without end. Without
# compartments that test filled the whole run's memory limit and
# systemd-oomd ended the whole run (2026-11-23: after 358 of 2307 changes).
# In its own compartment only that test is ended: the change counts as
# caught, and the run goes on.
set -eu
mode=${1:-}
[ $# -gt 1 ] || { sed -n '2,7p' "$0"; exit 2; }
shift
case $mode in
start)
    cg=/sys/fs/cgroup$(sed -n 's/^0:://p' /proc/self/cgroup)
    mkdir -p "$cg/main"
    echo $$ > "$cg/main/cgroup.procs"
    echo +memory > "$cg/cgroup.subtree_control"
    SAM_MUTANTS_CGROUP=$cg
    export SAM_MUTANTS_CGROUP
    exec "$@"
    ;;
test)
    if [ -n "${SAM_MUTANTS_CGROUP:-}" ]; then
        # One compartment per copy of the tree: its test programs run one
        # after the other, so the compartment holds one at a time.
        copy=$(pwd | sed -n 's#.*/\(cargo-mutants-[^/]*\.tmp\).*#\1#p')
        leaf="$SAM_MUTANTS_CGROUP/t-${copy:-other}"
        mkdir -p "$leaf"
        echo "${MUTANTS_TEST_MEMORY:-6G}" > "$leaf/memory.max"
        echo 0 > "$leaf/memory.swap.max" 2>/dev/null || true
        echo $$ > "$leaf/cgroup.procs"
    fi
    exec "$@"
    ;;
*)
    sed -n '2,7p' "$0"
    exit 2
    ;;
esac
