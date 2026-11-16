# How GitHub works for SAM

GitHub keeps SAM's code and history, runs its tests, publishes its releases
and website, and is where people report problems. This page explains each
part in plain words, with what you do and why.

## The repository and its history

The **repository** ("repo") is SAM's folder with its complete history. Every
saved change is a **commit**: a snapshot with a message that says what
changed and why. Commits form a timeline that never gets lost; any old state
can be looked at or brought back.

Your computer has a full copy, the **clone**. You change files there, make
commits, and **push** them to GitHub. **Pull** brings GitHub's newer commits
to your copy.

```sh
git status          # what changed on your computer
git log --oneline   # the newest commits
git pull            # get the newest commits from GitHub
```

Commits show the author's email. SAM's use your private GitHub address
(`…@users.noreply.github.com`), set for this repository with
`git config user.email`, so your real address stays private.

## Branches and pull requests

`main` is the official state of SAM. It is **protected**: nobody, not even
you, can change it directly. Every change goes like this:

1. **A branch:** a copy of `main` under its own name (`git switch -c fix-icon`),
   where the change is made and committed.
2. **Push the branch** to GitHub (`git push -u origin fix-icon`).
3. **A pull request** ("PR"): a page on GitHub that shows the change and asks
   to bring it into `main` (`gh pr create`, or the button GitHub offers).
4. **Checks:** CI tests the change automatically (see below). The PR shows a
   green tick when everything passes.
5. **Merge:** you press *Merge* on the PR page. Now `main` has the change.

**Why:** every change is tested before it reaches `main`, and nobody can
change SAM behind your back. The protection rules: a pull request is
required, and seven checks must pass: the tests on Intel/AMD and on ARM
processors, the Fedora sandbox tests, the window tests under KDE and under
GNOME, the dependency check, and "Needs your approval" (AUTOMATION.md);
the rules apply to you as admin too, and nobody can rewrite or delete `main`.

## CI: the tests GitHub runs for you

**CI** (continuous integration) runs on every push and pull request, on
GitHub's computers. See it in the **Actions** tab. Its jobs:

| Job | What it checks |
|---|---|
| **test** | builds SAM, checks the code format and lints, runs all tests twice (a test that changes its answer is flaky), checks the generated documents and translations, and opens every page of the window |
| **sandbox-fedora** | the real sandbox tests (breakout attempts, hostile AppImages) on Fedora |
| **window-flows** | clicks through the window like a person, through the accessibility interface, under KDE's KWin |
| **window-flows-gnome** | the same under GNOME's Mutter (not yet required for merging; it becomes required once it has proved stable) |
| **deny** | dependencies: known security problems, licenses, where they come from |

**Document-only changes are quick:** when a pull request changes only
documents or the website, the build, test, window and sandbox steps are
skipped (text cannot break the code) and the checks finish in about a
minute; the website, the test library and the function map are still
checked. Any change to code runs everything.

A red cross means something failed: open the run, then the red job, and read
the last lines of the red step. Ask Claude with a link to the run.

More workflows run on their own: **Release** builds and tests the
AppImages when you tag a version, **Pages** publishes the website, **Early
warning** checks SAM's contracts every night on the distributions that come
next, and **Upstream watch** reads the release notes of the projects SAM
builds on every week. The last two open issues when something breaks; see
[When something outside SAM changes](outside.md).

## Releases

A **release** is a published version with files to download. Versions have
numbers like `0.2.0` (see [Version numbers](../../CONTRIBUTING.md#version-numbers)).
A **tag** marks the commit a version was made from. Making one is described
step by step in [Releasing a version](../releasing.md); one command does most
of it, and publishing stays your click.

## The website

The website (gitzekatze.github.io/SAM) is built from the repository on every
change to `main`, by the **Pages** workflow and `scripts/site.py`. It is
never edited by hand: change the documents in `docs/`, and the website
follows.

## Automation and its checks

What automation may do, what it may never do, the risk class of every
pull request, the contract verifier, protected tests and the kill switch
are in [AUTOMATION.md](../../AUTOMATION.md). In short: a pull request that
weakens a security promise, changes a protected test or adds a dependency
passes only when you set the label **`owner-approved`** on it. Every pull
request shows a check **"Needs your approval"**: green when nothing needs
you; otherwise its summary lists what to look at. To approve: pull request
→ **Labels** (right sidebar) → **owner-approved**.

## Issues, suggestions and security reports

- **Issues** (Issues tab) are bug reports and ideas. The forms ask for what
  is needed, for example a bug report from SAM itself.
- **Pull requests from others** need your merge, like your own. Only accept
  what you understand; ask Claude to review one.
- **Security reports** arrive privately in the **Security** tab
  (*Advisories*). Never discuss them in a public issue. Answer within a week
  ([SECURITY.md](../../SECURITY.md)).
- **Forks:** anyone may copy SAM and publish changed versions under the same
  open license (GPL-3.0). Only this repository is SAM, and only you change it.

## Security features GitHub provides

- **Secret scanning** blocks a push that accidentally contains a password or
  token.
- **Dependabot** warns about dependencies with known security problems and
  proposes updates as pull requests.
- **Private vulnerability reporting**, described above.

## Words used here

| Word | Meaning |
|---|---|
| commit | a saved change with a message |
| push / pull | send commits to GitHub / get commits from GitHub |
| branch | a line of work separate from `main` |
| pull request (PR) | a request to bring a branch into `main`, with its checks |
| merge | bring a pull request into `main` |
| CI | the tests GitHub runs on every change |
| tag | a name for one commit, for example a version |
| release | a published version with its files |
| fork | someone's own copy of SAM on GitHub |
