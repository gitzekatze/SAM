#!/bin/sh
# Installs Ubuntu packages on a throwaway CI machine:
#
#     scripts/ci-packages.sh PACKAGE...
#
# Package servers fail in two ways, and each has hit SAM's CI:
# - GitHub's own mirror was unreachable for hours (2026-11-11).
# - Ubuntu's main server answered so slowly that the package lists alone
#   took the whole 10 minutes (2026-11-19).
# So the lists come from GitHub's mirror first, within a time limit, and
# from Ubuntu's main server only when that fails. Translations and
# "command-not-found" lists are left out: CI needs neither, and on a slow
# server each one waited a minute before it was given up.
set -eu

if [ "$#" -eq 0 ]; then
    echo "usage: $0 PACKAGE..." >&2
    exit 2
fi

FIRST_TRY_SECONDS=${FIRST_TRY_SECONDS:-150}
SOURCES=${SOURCES:-/etc/apt/sources.list.d/ubuntu.sources}

# Any list that fails to download fails the update, so the fallback is
# not skipped over a half-updated list (APT::Update::Error-Mode).
OPTS="-q -o Acquire::Retries=3 -o Acquire::http::Timeout=30
    -o Acquire::Languages=none
    -o Acquire::IndexTargets::deb::CNF::DefaultEnabled=false
    -o APT::Update::Error-Mode=any"

# shellcheck disable=SC2086 # OPTS is split into words on purpose.
if ! sudo timeout "$FIRST_TRY_SECONDS" apt-get update $OPTS; then
    echo "GitHub's package mirror did not answer in time; using Ubuntu's main server." >&2
    sudo sed -i \
        -e 's|mirror+file:/etc/apt/apt-mirrors.txt|http://archive.ubuntu.com/ubuntu/|g' \
        -e 's|http://azure.archive.ubuntu.com|http://archive.ubuntu.com|g' \
        "$SOURCES"
    # shellcheck disable=SC2086
    sudo apt-get update $OPTS
fi

# shellcheck disable=SC2086
sudo apt-get install -y --no-install-recommends $OPTS "$@"
