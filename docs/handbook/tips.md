# Updating SAM and the repository

The things that come up again and again: keeping SAM's building blocks up
to date, and the Git situations that confuse everyone at first. Each one
says what to do and why.

## Keeping SAM up to date

### Dependencies (the Rust crates SAM uses)

**Dependabot** opens a pull request when a crate SAM uses has a new version.
If its checks are green, merge it; security updates first. To update
everything at once yourself:

```sh
git switch main && git pull
git switch -c update-crates
cargo update                      # newest versions that fit Cargo.toml
make test
git commit -am "Update dependencies" && git push -u origin update-crates
gh pr create --fill
```

**Why a pull request:** the *deny* job checks the new versions for known
security problems and acceptable licenses, and all tests run on them before
they reach `main`.

### Rust

SAM needs Rust 1.92 or newer (`rust-version` in `Cargo.toml`). CI always
uses the newest stable Rust, so a new Rust release shows up there first: new
lints from `clippy` turn a run red. Update your own Rust the same way:

```sh
rustup update stable
cargo clippy --workspace --all-targets -- -D warnings
```

Fix what clippy reports on a branch, like any change. Raise `rust-version`
only when SAM needs a newer feature, and say so in the changelog: packagers
read it.

### Distributions

When Ubuntu, Fedora, Debian, Arch or openSUSE release a new version, add it
to the install tests in `.github/workflows/release.yml`, and drop versions
that have reached their end of life. The supported list in
[Install SAM](../install.md) changes with it.

### Texts and translations

After changing a text people read:

```sh
python3 scripts/i18n.py extract   # collect the new and changed texts
python3 scripts/i18n.py check     # what is missing in German, Spanish, French
```

CI requires the three languages to be complete and in the informal form
(*du*, *tú*, *tu*). See [translating](../translating.md).

## Git situations and their fixes

### "Your branch is behind" or a pull request has conflicts

`main` changed while you worked. Bring the newest `main` into your branch:

```sh
git switch your-branch
git fetch origin                  # get GitHub's newest state
git merge origin/main             # bring it into your branch
```

If Git reports a **conflict**, it marks the spots in the files with
`<<<<<<<`, `=======` and `>>>>>>>`. Keep the right text, delete the marks,
then `git add` the files, `git commit` and `git push`. The pull request
updates itself.

### Undo something

| Situation | Command |
|---|---|
| changed a file, not committed, want the old one back | `git restore FILE` |
| committed, not pushed, want to change the last commit | change the files, then `git commit --amend` |
| committed, not pushed, want to drop the last commit but keep the changes | `git reset HEAD~1` |
| a merged pull request broke something | open it on GitHub and press **Revert**: that makes a new pull request that undoes it |

**Never** rewrite what is already on GitHub's `main`; the protection
refuses it anyway. Undo with a new change instead, so the history stays
honest.

### See what happened

```sh
git log --oneline -15             # the newest commits
git log -p FILE                   # every change to one file
git diff main                     # what your branch changes
git blame FILE                    # who changed each line last, and in which commit
```

### Clean up old branches

After a merge, GitHub offers **Delete branch**. On your computer:

```sh
git switch main && git pull
git branch --merged main          # branches whose changes are in main
git branch -d old-branch          # delete one (refuses if it is not merged)
git fetch --prune                 # forget branches deleted on GitHub
```

### A pull request from someone else

Read the change on GitHub (*Files changed*), wait for the checks, and ask
questions in the pull request. Merge only what you understand; for anything
touching the sandbox, ask for a second opinion first. To try it on your
computer: `gh pr checkout NUMBER`.

## Good habits

- **One change per branch and pull request.** Small pull requests are easy to
  review and easy to revert.
- **Pull before you start.** `git switch main && git pull` first saves most
  conflicts.
- **Commit messages say why,** not only what: the history is SAM's memory.
- **Never commit secrets.** Keys, passphrases and tokens stay out of the
  repository; GitHub's secret scanning blocks most mistakes, not all.
- **A red check is information, not a failure.** Read the last lines of the
  red step before changing anything.
