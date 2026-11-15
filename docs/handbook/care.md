# Keeping SAM healthy

What to look at, how often, and what to do about it. Nothing here is urgent
unless it says so.

## Every week (5 minutes)

- **Security tab → Advisories:** a private report about a way out of the
  sandbox. **Urgent:** answer within a week, fix before anything else, and
  publish the advisory with the fixed version ([SECURITY.md](../../SECURITY.md)).
- **Issues:** answer questions, label bugs, close what is done. A bug report
  from SAM (`sam-jail report`) already hides personal data.
- **Actions → the newest run on `main`:** green means all is well. Red on
  `main` means something outside SAM changed (a dependency, a distribution);
  look at it soon.

## Every month

- **Dependabot pull requests:** updates of dependencies. If the checks are
  green, merging is usually safe; security updates first.
- **Security tab → Dependabot alerts:** a dependency with a known problem.
  Update it, or note why SAM is not affected.

## Before every release

The [release checklist](../releasing.md): mutation testing, the real-app
runs, the upgrade test, complete translations, the version report, the
changelog. `scripts/new-version.sh` checks most of it itself.

## Once a year

- **Rust and the distributions:** SAM needs Rust 1.92 or newer and is tested
  on Ubuntu, Debian, Fedora, Arch and openSUSE. When a distribution releases a
  new version, add it to the release tests (`.github/workflows/release.yml`).
- **The test AppImages:** add new kinds of apps to the real-app sets, so SAM
  keeps opening "nearly any AppImage".

## Every three years

- **The release key expires on 2029-11-14.** Extend it before then: your
  private guide (`SAM/personal/release-key-guide.md`), section 5.

## When something goes wrong

| What happened | What to do |
|---|---|
| CI is red on a pull request | read the red step's last lines; fix on the branch; ask Claude with the link |
| CI is red on `main` | usually an outside change; open an issue and look at it before the next release |
| a security report arrives | do not discuss it publicly; reproduce, fix, release, publish the advisory |
| the release key is lost or stolen | your private guide, section 7 |
| you lost track | start at the [handbook's first page](index.md), "What to do next" |
