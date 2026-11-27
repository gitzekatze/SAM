#!/bin/sh
# Tests SAM's finished AppImage on a fresh system, as a new user would get
# it: only the packages SAM's README asks for are installed, then an
# ordinary user starts the AppImage, creates a sandbox for a test app,
# starts it and checks it, and the window program must find GTK 4 and
# libadwaita.
#
# Runs as root inside a fresh, privileged container of the distribution
# (scripts/test-shipped.sh starts it), with the AppImage at /shipped/SAM.AppImage
# and the test app, made before with SAM's test tools (which the AppImage
# does not contain), at /shipped/Hello-1.0.AppImage.
#
#   EXPECT=works        everything above must pass (the default)
#   EXPECT=too-old      the system is older than SAM supports: the AppImage
#                       must refuse with its plain message, not a loader error
set -eu
EXPECT=${EXPECT:-works}
. /etc/os-release
echo "== $PRETTY_NAME (expect: $EXPECT)"

# What SAM's README asks for, per distribution, plus what the test needs
# (useradd, su). An unsupported system needs nothing: SAM must refuse before
# it uses any of it (and older releases lack some packages, such as passt).
[ "$EXPECT" = too-old ] || case "$ID" in
    ubuntu|debian)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends bubblewrap xdg-dbus-proxy passt libgtk-4-1 libadwaita-1-0 ca-certificates passwd util-linux >/dev/null ;;
    fedora)
        dnf install -y -q --setopt=install_weak_deps=False bubblewrap xdg-dbus-proxy passt gtk4 libadwaita shadow-utils util-linux >/dev/null ;;
    arch)
        pacman -Syu --noconfirm --needed -q bubblewrap xdg-dbus-proxy passt gtk4 libadwaita >/dev/null ;;
    opensuse-tumbleweed)
        zypper -q -n install --no-recommends bubblewrap xdg-dbus-proxy passt libgtk-4-1 libadwaita-1-0 shadow util-linux >/dev/null ;;
    *) echo "unknown distribution $ID" >&2; exit 2 ;;
esac

useradd -m tester
install -o tester -m 755 /shipped/SAM.AppImage /home/tester/SAM.AppImage
# A container has no FUSE: the AppImage unpacks itself to a temporary folder.
as_tester() { su tester -c "cd ~ && APPIMAGE_EXTRACT_AND_RUN=1 XDG_RUNTIME_DIR=/tmp/run-tester $1"; }
su tester -c "mkdir -p -m 700 /tmp/run-tester"

if [ "$EXPECT" = too-old ]; then
    out=$(as_tester "./SAM.AppImage cli version" 2>&1) && { echo "FAIL: SAM started on a system it does not support"; exit 1; }
    echo "$out" | grep -q "SAM needs a newer system" || { echo "FAIL: no plain message, got: $out"; exit 1; }
    echo "PASS: refused with: $(echo "$out" | head -n1)"
    exit 0
fi

step() { echo "-- $1"; }
step "version"
as_tester "./SAM.AppImage cli version"
step "doctor"
as_tester "./SAM.AppImage cli doctor" || true   # reports, does not decide
step "Bubblewrap works for this user"
as_tester "bwrap --ro-bind / / --dev /dev --proc /proc --unshare-all true"
step "the shipped command line has no test or release tools"
# `dev peek` stays (SAM runs it inside its unpack sandbox); the others are
# only in development builds.
as_tester "./SAM.AppImage cli dev peek --help" >/dev/null
for tool in make-fixture bench set-update-info make-zsync sign-appimage; do
    if out=$(as_tester "./SAM.AppImage cli dev $tool --help" 2>&1); then
        echo "FAIL: the shipped sam-jail offers dev $tool"; exit 1
    fi
    echo "$out" | grep -q "unrecognized subcommand" || { echo "FAIL: dev $tool: unexpected answer: $out"; exit 1; }
done
step "a test app gets a sandbox"
install -o tester -m 755 /shipped/Hello-1.0.AppImage /home/tester/Hello-1.0.AppImage
as_tester "./SAM.AppImage cli add Hello-1.0.AppImage --no-launcher"
id=$(as_tester "./SAM.AppImage cli --json list" | grep -o '"id":"appimage-hello-[0-9a-f]*"' | head -n1 | cut -d'"' -f4)
[ -n "$id" ] || { echo "FAIL: no sandbox was created"; exit 1; }
step "the app starts in its sandbox"
as_tester "./SAM.AppImage cli run $id" | tee /tmp/run.out
grep -q . /tmp/run.out || { echo "FAIL: the app printed nothing"; exit 1; }
step "the sandbox check passes"
as_tester "./SAM.AppImage cli verify $id"
step "the window program finds GTK 4 and libadwaita"
dir=$(mktemp -d)
(cd "$dir" && /shipped/SAM.AppImage --appimage-extract >/dev/null)
missing=$(ldd "$dir/squashfs-root/usr/bin/sam-jail-gui" | grep "not found" || true)
[ -z "$missing" ] || { echo "FAIL: libraries missing for the window: $missing"; exit 1; }
"$dir/squashfs-root/usr/bin/sam-jail-gui" --version
step "the shipped window program has no screenshot options"
# Each of them takes a value, so a program that reads one would take the
# following --version as that value and not print its version.
for opt in --screenshot --size --delay; do
    out=$(timeout 60 "$dir/squashfs-root/usr/bin/sam-jail-gui" "$opt" --version 2>&1 || true)
    echo "$out" | grep -q "^sam-jail-gui [0-9]" || { echo "FAIL: the shipped sam-jail-gui reads $opt: $out"; exit 1; }
done
echo "PASS: $PRETTY_NAME"
