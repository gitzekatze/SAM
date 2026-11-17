# The maintainer handbook

This handbook is for whoever looks after SAM: you, after a long break, or
someone who joins later. It assumes no experience with GitHub or Rust. Each
page says **what** a task is, **how** to do it and **why** it is done that
way. Read this page first; it tells you where everything is and what to do
next.

## SAM in one minute

SAM sandboxes AppImages: it unpacks an AppImage without running it, gives it
a sandbox built by Bubblewrap with only the access you allow, and starts it
there. It is written in Rust and has two faces: the window (`sam-jail-gui`)
and the command line (`sam-jail`). The window does everything through the
command line, so both always behave the same.

Five columns guide every change and every design decision (from
[CONTRIBUTING](../../CONTRIBUTING.md)): Reliability, Security, Simplicity,
Compatibility and Privacy.

## Where everything is

SAM lives on GitHub (github.com/gitzekatze/SAM): code, issues, pull
requests, releases, this website and the test results. You work in a clone,
a full copy of the repository on your computer, and send changes back
through pull requests ([how GitHub works](github.md)).

Inside the repository:

| Folder | What it holds |
|---|---|
| `crates/` | the code, in nine parts ([architecture](../architecture.md) explains them) |
| `docs/` | documentation; `docs/handbook/` is this handbook |
| `tests/` | test scripts that need more than `cargo test` (the window, real apps, upgrades) |
| `scripts/` | tools for releasing, reports and checks ([your tools](tools.md)) |
| `po/` | the translations |
| `data/`, `packaging/` | menu entry, icon, man pages, packages for distributions |

## The pages of this handbook

1. [How SAM looks after itself](looks-after-itself.md): the whole
   maintenance machine on one page, what runs without you, where you are
   needed, and your weekly routine. **Read this second.**
2. [How GitHub works for SAM](github.md): repository, commits, branches,
   pull requests, CI, releases, the website, issues and security reports.
3. [Everyday work](workflow.md): making a change, from idea to merged.
4. [Updating SAM and the repository](tips.md): dependencies, Rust, and the
   Git situations that come up, each with its fix.
5. [When something outside SAM changes](outside.md): the contract map, the
   early warnings, and what to do when a part of the outside world breaks.
6. [Your tools](tools.md): every command and script, what it does and when.
7. [Releasing a version](../releasing.md): the checklist, and the one
   command that does most of it.
8. [Keeping SAM healthy](care.md): what to look at weekly, monthly, yearly.
9. Deeper references: [testing](../testing.md), [translating](../translating.md),
   [architecture](../architecture.md), [the JSON interface](../json-interface.md),
   [packaging](../packaging.md), [contracts](../contracts.md), [AUTOMATION.md](../../AUTOMATION.md).

## What to do next

When you come back after a break, in this order:

1. **Look at GitHub:** security reports (Security tab) first; then issues,
   especially `early-warning` and `upstream-change` (the outside world
   changed while you were away; each issue names the contract and what to
   do); then open pull requests and the newest CI run on `main` (Actions
   tab). [How SAM looks after itself](looks-after-itself.md) explains what
   each one means.
2. **Update your clone:** `git switch main` and `git pull`.
3. **Check that everything still works:** `make test`.
4. **Read the newest entries:** the files in [changes/](../../changes/README.md)
   and *Unreleased* in [CHANGELOG.md](../../CHANGELOG.md) (or *What's new* on the
   website, which shows both): that is what changed since the last version.
5. **Pick the next task:** from the issues, or ask Claude to read this
   handbook and the changelog and propose the next steps.
