#!/bin/sh
# Early warning: SAM's contracts with the outside world, checked on the
# distributions that come next (Fedora Rawhide, Debian testing, Ubuntu's
# development release, Arch, openSUSE Tumbleweed). Changes reach them weeks
# or months before they reach most users, so a contract that breaks here is
# a warning in time.
#
# Runs as root inside a fresh, privileged container with the repository at
# /src (read-only) and a folder for the results at /out:
#   /out/setup.txt       "failed" when the distribution itself could not be
#                        set up (a broken mirror or package), not SAM's fault
#   /out/contracts.json  sam-jail --json doctor --contracts
#   /out/tests.txt       one line per test group: "ok NAME" or "FAIL NAME"
#   /out/tests.log       the output of the tests
# The workflow (.github/workflows/canary.yml) turns these into issues.
set -u
# A test that cannot build its sandbox fails instead of skipping: a broken
# Bubblewrap on a distribution is what this run is for (audit D-M11).
export SAM_REQUIRE_SANDBOX=1
. /etc/os-release
echo "== $PRETTY_NAME"
mkdir -p /out
echo "ok" > /out/setup.txt

setup() {
    case "$ID" in
        fedora)
            dnf install -y -q --setopt=install_weak_deps=False \
                gcc pkgconf-pkg-config curl ca-certificates kernel-headers \
                bubblewrap xdg-dbus-proxy passt bsdtar squashfs-tools gnupg2 strace \
                python3 python3-gobject glib2 dbus-daemon util-linux shadow-utils ;;
        debian|ubuntu)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq && apt-get install -y -qq --no-install-recommends \
                gcc libc6-dev pkg-config curl ca-certificates linux-libc-dev \
                bubblewrap xdg-dbus-proxy passt libarchive-tools squashfs-tools gnupg strace \
                python3 python3-gi libglib2.0-bin dbus-daemon util-linux passwd ;;
        arch)
            pacman -Syu --noconfirm --needed -q \
                gcc pkgconf curl ca-certificates linux-api-headers \
                bubblewrap xdg-dbus-proxy passt libarchive squashfs-tools gnupg strace \
                python python-gobject glib2 dbus util-linux shadow ;;
        opensuse-tumbleweed)
            zypper -q -n install --no-recommends \
                gcc pkgconf curl ca-certificates linux-glibc-devel \
                bubblewrap xdg-dbus-proxy passt bsdtar squashfs gpg2 strace \
                python3 python3-gobject glib2-tools dbus-1 util-linux shadow ;;
        *) echo "unknown distribution $ID"; return 1 ;;
    esac
}
if ! setup >/out/setup.log 2>&1; then
    echo "failed" > /out/setup.txt
    tail -n 30 /out/setup.log
    exit 0   # the distribution's problem; reported separately, not as a contract
fi

# SAM is built as an ordinary user, with Rust from rustup (the distribution's
# Rust may be older than SAM needs); the sandbox tests must run as one.
useradd -m tester
cp -a /src /home/tester/sam && chown -R tester /home/tester/sam
as_tester() { su tester -c "cd ~/sam && . ~/.cargo/env 2>/dev/null; $1"; }
if ! su tester -c "curl -fsSL https://sh.rustup.rs | sh -s -- -y -q --profile minimal" >>/out/setup.log 2>&1 \
    || ! as_tester "cargo build -q --locked -p sam-jail-cli" >>/out/setup.log 2>&1; then
    echo "failed" > /out/setup.txt
    tail -n 30 /out/setup.log
    exit 0
fi
su tester -c "mkdir -p -m 700 /tmp/run-tester"

as_tester "XDG_RUNTIME_DIR=/tmp/run-tester target/debug/sam-jail --json doctor --contracts" \
    | tail -n 1 > /out/contracts.json

# Each group runs twice before it counts as failed: a fluke on a busy
# machine is not an early warning.
: > /out/tests.txt
: > /out/tests.log
run() {
    name=$1; shift
    for try in 1 2; do
        if as_tester "XDG_RUNTIME_DIR=/tmp/run-tester PATH=\$HOME/sam/target/debug:\$PATH $*" >>/out/tests.log 2>&1; then
            echo "ok $name" >> /out/tests.txt
            return
        fi
        echo "-- $name failed (try $try)" >> /out/tests.log
    done
    echo "FAIL $name" >> /out/tests.txt
}
run syscalls "cargo test -q --locked -p sam-runner --test syscalls"
run sandbox "cargo test -q --locked -p sam-runner --test sandbox --test matrix --test breakout"
run hostile "cargo test -q --locked -p sam-runner --test evil"
run teardown "cargo test -q --locked -p sam-jail-cli --test teardown --test contracts"
cat /out/tests.txt
