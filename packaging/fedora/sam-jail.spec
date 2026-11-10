# SAM, the Sandboxed AppImage Manager. Split package, same as on Arch:
#   sam-jail-cli   command line tools and sandbox runner (sam-jail, sam-jail-run)
#   sam-jail       the GTK 4 / libadwaita window (sam-jail-gui)
#
# Builds offline (COPR/mock have no network) from the two release files made
# by scripts/make-release.sh: the source and the vendored Rust crates.

# Fedora's Rust flags keep debug info; rpm strips the binaries and puts it
# into the -debuginfo/-debugsource packages, as Fedora expects.

Name:           sam-jail
Version:        0.1.0
Release:        1%{?dist}
Summary:        Flatseal-style sandbox manager for AppImages, using Bubblewrap

# SAM itself; the vendored Rust crates are MIT, Apache-2.0, Unicode-3.0 and
# similar permissive licenses (see vendor/*/LICENSE*).
License:        GPL-3.0-or-later
URL:            https://github.com/gitzekatze/SAM
Source0:        %{url}/releases/download/v%{version}/sam-%{version}.tar.gz
Source1:        %{url}/releases/download/v%{version}/sam-%{version}-vendor.tar.xz

ExclusiveArch:  x86_64 aarch64

BuildRequires:  cargo
BuildRequires:  rust >= 1.92
BuildRequires:  pkgconfig(gtk4) >= 4.12
BuildRequires:  pkgconfig(libadwaita-1) >= 1.5
BuildRequires:  desktop-file-utils
BuildRequires:  libappstream-glib
# For the end-to-end tests (they skip themselves where Bubblewrap cannot run).
BuildRequires:  bubblewrap

Requires:       sam-jail-cli%{?_isa} = %{version}-%{release}
Requires:       hicolor-icon-theme

%description
SAM lists the AppImages on your computer and runs them in a Bubblewrap
sandbox. Like Flatseal, it shows every permission of an app as a switch:
files, network, devices, desktop services and more. Recommended settings are
derived from the AppImage itself, without running it.

This package contains the GTK 4 / libadwaita window (sam-jail-gui).

%package -n sam-jail-cli
Summary:        Command line tools and sandbox runner for SAM
Requires:       bubblewrap
Requires:       bsdtar
Recommends:     xdg-dbus-proxy
Recommends:     passt
Suggests:       strace
Suggests:       squashfs-tools

%description -n sam-jail-cli
Command line tools of SAM, the Sandboxed AppImage Manager: sam-jail creates
and manages sandboxes for AppImages, sam-jail-run starts an app in its
sandbox (also used by SAM's menu entries).

%prep
%autosetup -n sam-%{version}
# The vendored crates and the Cargo config that uses them.
tar -xJf %{SOURCE1} --strip-components=1

%build
export CARGO_HOME="$PWD/.cargo-home"
%{?build_rustflags:export RUSTFLAGS="%{build_rustflags}"}
cargo build --frozen --offline --release -p sam-jail-cli -p sam-gtk

%install
install -Dpm 0755 target/release/sam-jail     %{buildroot}%{_bindir}/sam-jail
install -Dpm 0755 target/release/sam-jail-run %{buildroot}%{_bindir}/sam-jail-run
install -Dpm 0755 target/release/sam-jail-gui %{buildroot}%{_bindir}/sam-jail-gui
install -Dpm 0644 data/io.github.gitzekatze.SAM.desktop      %{buildroot}%{_datadir}/applications/io.github.gitzekatze.SAM.desktop
install -Dpm 0644 data/io.github.gitzekatze.SAM.metainfo.xml %{buildroot}%{_metainfodir}/io.github.gitzekatze.SAM.metainfo.xml
install -Dpm 0644 data/io.github.gitzekatze.SAM.svg          %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/io.github.gitzekatze.SAM.svg
install -Dpm 0644 -t %{buildroot}%{_mandir}/man1 data/man/*.1

%check
desktop-file-validate %{buildroot}%{_datadir}/applications/io.github.gitzekatze.SAM.desktop
appstream-util validate-relax --nonet %{buildroot}%{_metainfodir}/io.github.gitzekatze.SAM.metainfo.xml
export CARGO_HOME="$PWD/.cargo-home"
%{?build_rustflags:export RUSTFLAGS="%{build_rustflags}"}
cargo test --frozen --offline --workspace

%files
%license LICENSE
%{_bindir}/sam-jail-gui
%{_datadir}/applications/io.github.gitzekatze.SAM.desktop
%{_metainfodir}/io.github.gitzekatze.SAM.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/io.github.gitzekatze.SAM.svg
%{_mandir}/man1/sam-jail-gui.1*

%files -n sam-jail-cli
%license LICENSE
%doc README.md CHANGELOG.md docs/security.md docs/profiles.md
%{_bindir}/sam-jail
%{_bindir}/sam-jail-run
%{_mandir}/man1/sam-jail.1*
%{_mandir}/man1/sam-jail-[!g]*.1*

%changelog
* Tue Nov 10 2026 gitzekatze <206283406+gitzekatze@users.noreply.github.com> - 0.1.0-1
- First release.
