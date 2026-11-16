# Everyday work

How a change gets from an idea into SAM. Most changes are made together with
Claude; the steps are the same either way.

## 1. Agree on what and why

Write down what should change and why, in one or two sentences. Check it
against SAM's five columns (Reliability, Security, Simplicity, Compatibility,
Privacy; see [CONTRIBUTING](../../CONTRIBUTING.md)). For a larger change, open an issue first, so the
decision is on record.

## 2. Start a branch

```sh
cd SAM                           # your clone of the repository
git switch main && git pull      # start from the newest state
git switch -c short-name         # a branch for this change
```

**Why:** `main` stays untouched until the change is tested.

## 3. Test first where it pays

For a bug, a security limit or a new function, write the test before the
code: it must fail first and pass after the change. A new function goes into
`docs/functions.toml` with its promise. See
[Tests for every change](../../CONTRIBUTING.md#tests-for-every-change).

**Why:** a test written after the code tends to check what the code does,
not what it should do. Mutation testing showed exactly these gaps in SAM.

## 4. Make the change and check it

```sh
make test                         # all tests
cargo fmt --all                   # the code format
cargo clippy --workspace --all-targets -- -D warnings
make test-library                 # after adding or renaming tests
python3 scripts/contract-map.py    # after the code starts using something outside SAM
python3 scripts/i18n.py check     # after changing texts people read
make mutants-diff                 # for security-relevant code: do the tests catch mistakes?
```

Texts people read are written as whole sentences and translated into German,
Spanish and French, in the informal form ([translating](../translating.md)).
Add a line to [CHANGELOG.md](../../CHANGELOG.md) under *Unreleased*.

## 5. Commit, push, pull request

```sh
git add -A
git commit -m "What changed, in one line" -m "Why, in a few sentences."
git push -u origin short-name
gh pr create --fill
```

Then open the pull request on GitHub and wait for the checks. A change that
only touches documents is checked in about a minute.

If **Needs your approval** is red, the change weakens a promise, changes a
protected test or adds a dependency: its summary lists exactly what. If that
is what you want, set the label **owner-approved** (pull request → Labels);
only that check runs again. See [AUTOMATION.md](../../AUTOMATION.md).

## 6. Merge

When every check is green, press **Merge pull request** on GitHub, then
**Delete branch**. On your computer:

```sh
git switch main && git pull
git branch -d short-name
```

## When a check fails

Open the failed run (the red cross on the pull request → *Details*), read the
last lines of the red step, fix the cause on the same branch, commit and push
again. The pull request updates itself. If the reason is unclear, give Claude
the link.

## Working with Claude

- Claude follows this handbook, CONTRIBUTING and the project memory.
- Claude works on branches and opens pull requests; you merge.
- Ask for a report when a task is done: what changed, what was tested, what
  is still open.
- Private things (keys, passphrases, personal notes) never go into the
  repository or the chat.
