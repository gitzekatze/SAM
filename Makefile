# SAM build helper.
#
#   make                 build CLI and GUI (GTK 4 / libadwaita) in release mode
#   make test            run the Rust test suite
#   make install         install into $(DESTDIR)$(PREFIX)
#   make install-cli     CLI only (sam-jail, sam-jail-run)
#   make dist            release tarballs (source + vendored crates) in dist/
#   make man             regenerate the man pages in data/man
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

.PHONY: all cli gui test install install-cli install-gui clean dist appimage man

all: cli gui

cli:
	$(CARGO) build --release --locked -p sam-jail-cli

gui:
	$(CARGO) build --release --locked -p sam-gtk

test:
	$(CARGO) test --workspace --locked

install-cli:
	install -Dm755 target/release/sam-jail     "$(BINDIR)/sam-jail"
	install -Dm755 target/release/sam-jail-run "$(BINDIR)/sam-jail-run"
	install -Dm644 README.md                  "$(DATADIR)/doc/sam/README.md"
	install -Dm644 docs/security.md           "$(DATADIR)/doc/sam/security.md"
	install -Dm644 docs/profiles.md           "$(DATADIR)/doc/sam/profiles.md"
	install -Dm644 CHANGELOG.md               "$(DATADIR)/doc/sam/CHANGELOG.md"
	for f in data/man/sam-jail*.1; do case "$$f" in *sam-jail-gui.1) ;; *) install -Dm644 "$$f" "$(DATADIR)/man/man1/$${f##*/}" ;; esac; done

install-gui:
	install -Dm755 target/release/sam-jail-gui           "$(BINDIR)/sam-jail-gui"
	install -Dm644 data/io.github.gitzekatze.SAM.desktop     "$(DATADIR)/applications/io.github.gitzekatze.SAM.desktop"
	install -Dm644 data/io.github.gitzekatze.SAM.metainfo.xml "$(DATADIR)/metainfo/io.github.gitzekatze.SAM.metainfo.xml"
	install -Dm644 data/io.github.gitzekatze.SAM.svg         "$(DATADIR)/icons/hicolor/scalable/apps/io.github.gitzekatze.SAM.svg"
	install -Dm644 data/man/sam-jail-gui.1                    "$(DATADIR)/man/man1/sam-jail-gui.1"

install: install-cli install-gui

dist:
	scripts/make-release.sh dist

# Regenerate the man pages in data/man from the command definitions.
man: cli
	target/release/sam-jail man data/man

# Needs RUNTIME=/path/to/runtime-x86_64 (see scripts/make-appimage.sh).
appimage:
	scripts/make-appimage.sh dist

clean:
	$(CARGO) clean
