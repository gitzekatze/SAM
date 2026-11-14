# SAM build helper.
#
#   make                 build CLI and GUI (GTK 4 / libadwaita) in release mode
#   make test            run the Rust test suite
#   make install         install into $(DESTDIR)$(PREFIX)
#   make install-cli     CLI only (sam-jail, sam-jail-run)
#   make dist            release tarballs (source + vendored crates) in dist/
#   make man             regenerate the man pages in data/man
#   make pot             collect translatable strings into po/sam.pot
#   make mo              compile the translations (po/*.po) into target/locale
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

.PHONY: all cli gui test test-library report install install-cli install-gui clean dist appimage man pot mo

# Languages with a translation (po/LINGUAS).
LINGUAS := $(shell cat po/LINGUAS 2>/dev/null)

all: cli gui

cli:
	$(CARGO) build --release --locked -p sam-jail-cli

gui: mo
	$(CARGO) build --release --locked -p sam-gtk

# Translations need msgfmt (gettext); without it SAM is built in English.
mo:
	@if command -v msgfmt >/dev/null; then \
	  for l in $(LINGUAS); do mkdir -p target/locale/$$l/LC_MESSAGES && msgfmt --check -o target/locale/$$l/LC_MESSAGES/sam.mo po/$$l.po || exit 1; done; \
	else echo "msgfmt not found: translations skipped"; fi

pot:
	xgettext -L Rust --keyword=tr --from-code=UTF-8 --package-name=sam --msgid-bugs-address=https://github.com/gitzekatze/SAM/issues -o po/sam.pot crates/sam-gtk/src/*.rs crates/sam-gtk/src/*/*.rs
	for l in $(LINGUAS); do msgmerge --update --backup=none po/$$l.po po/sam.pot; done

test:
	$(CARGO) test --workspace --locked

# The catalog of all tests (docs/test-library.md).
test-library:
	python3 scripts/test-library.py

# The version report (docs/reports/): tests, line coverage and timings per
# part, the dependencies between the parts, and the differences to the
# previous report.
report:
	python3 scripts/version-report.py

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
	for l in $(LINGUAS); do f=target/locale/$$l/LC_MESSAGES/sam.mo; [ ! -f $$f ] || install -Dm644 $$f "$(DATADIR)/locale/$$l/LC_MESSAGES/sam.mo"; done

install: install-cli install-gui

dist:
	scripts/make-release.sh dist

# Regenerate the man pages in data/man from the command definitions.
man: cli
	target/release/sam-jail man data/man

# Needs RUNTIME=/path/to/runtime-ARCH (see scripts/make-appimage.sh).
appimage:
	scripts/make-appimage.sh dist

clean:
	$(CARGO) clean
