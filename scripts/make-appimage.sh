#!/bin/sh
# Builds SAM as an AppImage.
#
#   RUNTIME=/path/to/runtime-ARCH scripts/make-appimage.sh [OUTDIR]
#
# Writes OUTDIR/SAM-VERSION-ARCH.AppImage and its .zsync update description
# (default OUTDIR: ./dist), ARCH being this computer's (x86_64 or aarch64).
#
# The AppImage holds sam-jail, sam-jail-run and sam-jail-gui, and uses the
# GTK 4 and libadwaita (1.5 or newer) installed on the computer, like
# Bubblewrap, which SAM needs anyway. Nothing else is bundled.
#
# Needs: cargo, mksquashfs (squashfs-tools), objdump (binutils) and the AppImage type 2 runtime
# from https://github.com/AppImage/type2-runtime/releases (runtime-ARCH).
# The runtime's SHA-256 is checked against RUNTIME_SHA256 (defaults: the
# pinned runtimes below); set it to the digest GitHub shows for a newer one.
# With SIGN_KEY=<fingerprint> the AppImage is signed before its .zsync and
# checksum are written (GnuPG asks for the passphrase).
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
out=$(mkdir -p "${1:-dist}" && cd "${1:-dist}" && pwd)
arch=$(uname -m)
: "${RUNTIME:?set RUNTIME to the AppImage runtime (runtime-$arch)}"
case "$arch" in
    x86_64)  : "${RUNTIME_SHA256:=617aa77314d57c8b8e4fae9c3f0b35af7b30d5529cb69e98f64f92510ed98a46}" ;;
    aarch64) : "${RUNTIME_SHA256:=9a72a744d221576c9347ec074243acc5c3c7568896b12714e0e82e9f0bf47900}" ;;
    *) echo "unsupported architecture $arch" >&2; exit 1 ;;
esac
command -v mksquashfs >/dev/null || { echo "mksquashfs not found (install squashfs-tools)" >&2; exit 1; }
echo "$RUNTIME_SHA256  $RUNTIME" | sha256sum -c --quiet - || { echo "runtime checksum mismatch" >&2; exit 1; }

# The release steps below (update information, signature, .zsync) use
# SAM's release tools, which the shipped programs do not contain: a build of
# sam-jail with the dev-tools feature, in a folder of its own. It never goes
# into the AppImage.
tools="$root/target/appimage-tools/debug/sam-jail"
cargo build --locked --target-dir "$root/target/appimage-tools" -p sam-jail-cli --features dev-tools

# Keep this computer's folder names out of the binaries (panic messages
# carry source paths), in a build folder of its own.
# The crate cache may live anywhere (CARGO_HOME), so everything under the
# home folder is rewritten; the later, more specific rule wins for the source.
cargo_home=${CARGO_HOME:-$HOME/.cargo}
sep=$(printf '\037')
CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$HOME=/build/home$sep--remap-path-prefix=$cargo_home=/cargo$sep--remap-path-prefix=$root=/build/sam"
export CARGO_ENCODED_RUSTFLAGS
bin="$root/target/appimage/release"
cargo build --release --locked --target-dir "$root/target/appimage" -p sam-jail-cli -p sam-gtk
if grep -q -a -e "$HOME" -e "$root" -e "$cargo_home" "$bin/sam-jail" "$bin/sam-jail-run" "$bin/sam-jail-gui"; then
    echo "build paths left in the binaries" >&2
    exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/sam-appimage.XXXXXX")
trap 'rm -rf "$work"' EXIT
app="$work/AppDir"
id=io.github.gitzekatze.SAM

install -Dm755 "$bin/sam-jail"     "$app/usr/bin/sam-jail"
install -Dm755 "$bin/sam-jail-run" "$app/usr/bin/sam-jail-run"
install -Dm755 "$bin/sam-jail-gui" "$app/usr/bin/sam-jail-gui"
install -Dm644 "data/$id.svg"              "$app/usr/share/icons/hicolor/scalable/apps/$id.svg"
install -Dm644 "data/$id.desktop"          "$app/usr/share/applications/$id.desktop"
install -Dm644 "data/$id.metainfo.xml"     "$app/usr/share/metainfo/$id.appdata.xml"
install -Dm644 LICENSE                     "$app/usr/share/licenses/sam/LICENSE"
install -Dm644 THIRD-PARTY-LICENSES.md     "$app/usr/share/licenses/sam/THIRD-PARTY-LICENSES.md"
make -s mo
for f in target/locale/*/LC_MESSAGES/sam.mo; do
    [ -f "$f" ] && install -Dm644 "$f" "$app/usr/share/locale/${f#target/locale/}"
done
cp "data/$id.desktop" "$app/$id.desktop"
cp "data/$id.svg" "$app/$id.svg"
ln -s "$id.svg" "$app/.DirIcon"

cat > "$app/AppRun" <<'EOF'
#!/bin/sh
# SAM's AppImage entry point.
#   SAM.AppImage                  the window (files given are added)
#   SAM.AppImage --app-id ID ...  start a sandboxed app (used by menu entries)
#   SAM.AppImage --start-anyway --app-id ID ...  the same, once without a
#                                 protection that is missing (its notice)
#   SAM.AppImage cli ARGS...      the command line, like `sam-jail ARGS`
HERE=$(dirname "$(readlink -f "$0")")
# SAM's programs need this C library (glibc) or newer. On an older system
# they would fail with a loader error, so say plainly what is missing.
need="@GLIBC_NEEDED@"
have=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')
if [ -n "$have" ] && [ "$(printf '%s\n%s\n' "$need" "$have" | sort -V | head -n1)" != "$need" ]; then
    msg="SAM needs a newer system: its programs need the C library glibc $need or newer, and this system has glibc $have (for example Debian 12 or Ubuntu 22.04). Use a newer release of your distribution, or a SAM package built for it."
    echo "$msg" >&2
    if [ "${1:-}" != cli ] && [ "${1:-}" != --app-id ] && [ "${1:-}" != --start-anyway ]; then
        if command -v kdialog >/dev/null; then kdialog --title SAM --error "$msg"
        elif command -v zenity >/dev/null; then zenity --error --title=SAM --text="$msg"
        elif command -v notify-send >/dev/null; then notify-send --app-name=SAM "SAM cannot start" "$msg"
        fi
    fi
    exit 1
fi
case "${1:-}" in
    --app-id|--start-anyway) exec "$HERE/usr/bin/sam-jail-run" "$@" ;;
    cli) shift; exec "$HERE/usr/bin/sam-jail" "$@" ;;
esac
# The window needs GTK 4 and libadwaita from the system: say so plainly
# instead of failing with a loader error.
if ! "$HERE/usr/bin/sam-jail-gui" --version >/dev/null 2>&1; then
    msg="SAM needs GTK 4 and libadwaita 1.5 or newer. Install them with your package manager (Arch: gtk4 libadwaita; Fedora: gtk4 libadwaita; Debian/Ubuntu: libgtk-4-1 libadwaita-1-0), then start SAM again."
    echo "$msg" >&2
    if command -v kdialog >/dev/null; then kdialog --title SAM --error "$msg"
    elif command -v zenity >/dev/null; then zenity --error --title=SAM --text="$msg"
    elif command -v notify-send >/dev/null; then notify-send --app-name=SAM "SAM cannot start" "$msg"
    fi
    exit 1
fi
exec "$HERE/usr/bin/sam-jail-gui" "$@"
EOF
# The newest glibc symbol version any of SAM's programs uses.
glibc=$(objdump -T "$app"/usr/bin/* | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -n1)
[ -n "$glibc" ] || { echo "could not read the glibc version the programs need (objdump)" >&2; exit 1; }
sed -i "s/@GLIBC_NEEDED@/$glibc/" "$app/AppRun"
chmod 755 "$app/AppRun"

# Reproducible image: fixed owner and times.
epoch=$(git log -1 --format=%ct "v$version" 2>/dev/null || git log -1 --format=%ct 2>/dev/null || echo 0)
mksquashfs "$app" "$work/fs.squashfs" -root-owned -noappend -no-xattrs -all-time "$epoch" -mkfs-time "$epoch" \
    -comp zstd -Xcompression-level 19 -quiet
target="$out/SAM-$version-$arch.AppImage"
# Where updates of SAM itself are published: GitHub releases of SAM, with a
# .zsync file next to each AppImage (sam-jail self-update uses both).
cp "$RUNTIME" "$work/runtime"
"$tools" dev set-update-info "$work/runtime" "gh-releases-zsync|gitzekatze|SAM|latest|SAM-*-$arch.AppImage.zsync" >/dev/null
cat "$work/runtime" "$work/fs.squashfs" > "$target"
chmod 755 "$target"
if [ -n "${SIGN_KEY:-}" ]; then
    "$tools" dev sign-appimage "$target" --key "$SIGN_KEY" >/dev/null
fi
"$tools" dev make-zsync "$target" >/dev/null
(cd "$out" && sha256sum "$(basename "$target")" > "$(basename "$target").sha256")
echo "Wrote $target"
