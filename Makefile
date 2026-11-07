# Appseal build helper.
#
#   make                 build CLI (Rust) and GUI (Qt) in release mode
#   make test            run the Rust test suite
#   make install         install into $(DESTDIR)$(PREFIX)
#   make install-cli     CLI only (appseal, appseal-run)
#
# Uses the project-local Rust toolchain in ../.toolchain when present.

PREFIX  ?= /usr
DESTDIR ?=
BINDIR   = $(DESTDIR)$(PREFIX)/bin
DATADIR  = $(DESTDIR)$(PREFIX)/share

# (shell test instead of $(wildcard): the path may contain spaces)
TOOLCHAIN := $(shell cd ../.toolchain 2>/dev/null && pwd)
ifeq ($(shell test -x "$(TOOLCHAIN)/cargo/bin/cargo" && echo yes),yes)
export RUSTUP_HOME := $(TOOLCHAIN)/rustup
export CARGO_HOME  := $(TOOLCHAIN)/cargo
CARGO ?= "$(TOOLCHAIN)/cargo/bin/cargo"
else
CARGO ?= cargo
endif

.PHONY: all cli gui test install install-cli install-gui clean

all: cli gui

cli:
	$(CARGO) build --release --locked -p appseal-cli

gui:
	cmake -S gui -B gui/build-release -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$(PREFIX)
	cmake --build gui/build-release

test:
	$(CARGO) test --workspace --locked

install-cli:
	install -Dm755 target/release/appseal     $(BINDIR)/appseal
	install -Dm755 target/release/appseal-run $(BINDIR)/appseal-run
	install -Dm644 README.md                  $(DATADIR)/doc/appseal/README.md
	install -Dm644 docs/security.md           $(DATADIR)/doc/appseal/security.md
	install -Dm644 docs/profiles.md           $(DATADIR)/doc/appseal/profiles.md

install-gui:
	install -Dm755 gui/build-release/appseal-gui        $(BINDIR)/appseal-gui
	install -Dm644 data/org.appseal.Appseal.desktop     $(DATADIR)/applications/org.appseal.Appseal.desktop
	install -Dm644 data/org.appseal.Appseal.metainfo.xml $(DATADIR)/metainfo/org.appseal.Appseal.metainfo.xml
	install -Dm644 data/org.appseal.Appseal.svg         $(DATADIR)/icons/hicolor/scalable/apps/org.appseal.Appseal.svg

install: install-cli install-gui

clean:
	$(CARGO) clean
	rm -rf gui/build gui/build-release
