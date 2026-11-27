#!/bin/sh
# Tests a finished SAM AppImage in fresh containers of the distributions SAM
# supports, and checks that older ones get a plain refusal ("test what you
# ship": every other test runs SAM built from source).
#
#   scripts/test-shipped.sh dist/SAM-0.1.0-x86_64.AppImage [IMAGE=EXPECT ...]
#
# Without IMAGE=EXPECT pairs, the list below is used. EXPECT is "works" or
# "too-old" (see tests/shipped/in-container.sh). Uses podman, or docker when
# podman is missing. The containers are privileged because SAM's sandboxes
# need user namespaces inside them; on Ubuntu hosts AppArmor must allow
# unprivileged user namespaces (CI lifts the restriction first).
#
# The test app is a synthetic AppImage made here, before the containers
# start, by a release build of sam-jail with the dev-tools feature (needs
# cargo):
# the shipped AppImage has no test tools, and the containers no Rust.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
appimage=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
shift
[ -f "$appimage" ] || { echo "no such AppImage: $appimage" >&2; exit 2; }
engine=$(command -v podman || command -v docker) || { echo "podman or docker is needed" >&2; exit 2; }
command -v cargo >/dev/null || { echo "cargo is needed to make the test app" >&2; exit 2; }
work=$(mktemp -d "${TMPDIR:-/tmp}/sam-shipped.XXXXXX")
trap 'rm -rf "$work"' EXIT
fixture="$work/Hello-1.0.AppImage"
cargo build -q --release --locked --manifest-path "$here/Cargo.toml" --target-dir "$here/target/shipped-tools" \
    -p sam-jail-cli --features dev-tools
"$here/target/shipped-tools/release/sam-jail" dev make-fixture "$fixture" >/dev/null

if [ $# -eq 0 ]; then
    set -- \
        docker.io/library/ubuntu:24.04=works \
        docker.io/library/debian:13=works \
        registry.fedoraproject.org/fedora:latest=works \
        docker.io/library/archlinux:latest=works \
        registry.opensuse.org/opensuse/tumbleweed:latest=works \
        docker.io/library/debian:12=too-old \
        docker.io/library/ubuntu:22.04=too-old
fi

failed=""
for pair in "$@"; do
    image=${pair%=*}
    expect=${pair##*=}
    if "$engine" run --rm --privileged -e EXPECT="$expect" \
        -v "$appimage:/shipped/SAM.AppImage:ro" \
        -v "$fixture:/shipped/Hello-1.0.AppImage:ro" \
        -v "$here/tests/shipped/in-container.sh:/shipped/in-container.sh:ro" \
        "$image" sh /shipped/in-container.sh; then
        :
    else
        failed="$failed $image"
    fi
done
if [ -n "$failed" ]; then
    echo "FAILED on:$failed" >&2
    exit 1
fi
echo "The AppImage passed on every system."
