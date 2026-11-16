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

## The release key

SAM updates itself only to AppImages signed with the release key
(`AFE940EDA5A0C5C4B94B0A3FB1764CFD72A238E6`). The secret part and its
passphrase never go into the repository, the chat or GitHub.

- **Keep a backup** of the secret key and its revocation certificate
  somewhere safe and offline, for example a password manager or a USB stick
  in a drawer.
- **It expires on 2029-11-14.** Extend it before then, then publish the
  extended public key (`sam-release-key.asc` in the repository) with the
  next release:

  ```sh
  gpg --quick-set-expire AFE940EDA5A0C5C4B94B0A3FB1764CFD72A238E6 3y
  gpg --armor --export AFE940EDA5A0C5C4B94B0A3FB1764CFD72A238E6 > sam-release-key.asc
  ```

- **If it is lost or stolen:** publish the revocation certificate, make a new
  key, put its fingerprint into `RELEASE_KEYS`
  (`crates/sam-runner/src/release_key.rs`) and release a new version signed
  with the old key if you still have it. Without the old key, people must
  download the new version by hand; say so in a security advisory.

## When something goes wrong

| What happened | What to do |
|---|---|
| CI is red on a pull request | read the red step's last lines; fix on the branch; ask Claude with the link |
| CI is red on `main` | usually an outside change; open an issue and look at it before the next release |
| a security report arrives | do not discuss it publicly; reproduce, fix, release, publish the advisory |
| the release key is lost or stolen | [The release key](#the-release-key), above |
| you lost track | start at the [handbook's first page](index.md), "What to do next" |
