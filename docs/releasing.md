# Releasing SAM

This is the checklist for a new version. `scripts/release.sh` does most of
the steps; the list says what it does and what stays a person's job.

## Before the release

1. **CI is green on `main`**, including the Fedora sandbox tests.
2. **Mutation testing** (`cargo mutants`, once per version, because it takes
   hours): it changes the code on purpose and checks that a test notices.
   Every surviving change in the security-relevant crates (`sam-sandbox`,
   `sam-runner`, `sam-intake`, `sam-detect`) gets a test or a written reason
   in the version report.

   ```sh
   # Through a guard: a mutant that breaks a loop can write without end.
   cargo install --locked cargo-mutants
   cargo mutants -p sam-sandbox -p sam-runner -p sam-intake -p sam-detect --test-workspace=true -j 6 --timeout 120 -o target/mutants
   ```

3. **Real apps:** the 120-AppImage test set runs without a new failure
   (`tests/real-apps/run.sh`, see [testing](testing.md)).
4. **Upgrades work:** `tests/upgrade/run.sh vLAST target/upgrade-test` builds
   the last released version, creates apps, settings and a preset with it, and
   checks that this version keeps them and still starts the apps.
   `scripts/new-version.sh` runs it by itself.
5. **Translations are complete:** `python3 scripts/i18n.py check`.
6. **The version report** for the finished state: `make report`. It also
   updates the dashboard and the function map's results.
7. **The changelog** has every user-visible change under *Unreleased*, in
   whole sentences.
8. **The release key** is on this computer. Its fingerprint,
   `AFE940EDA5A0C5C4B94B0A3FB1764CFD72A238E6`, is built into SAM
   (`RELEASE_KEYS` in `crates/sam-runner/src/release_key.rs`): SAM updates
   itself only to AppImages signed with it. The key expires on 2029-11-14;
   extend it before then (`gpg --quick-set-expire <fingerprint> 3y`) and
   publish the extended public key.

## Making the release: one command

After the checks above, one command does the rest, up to the last click:

```sh
scripts/new-version.sh X.Y.Z --dry-run   # only checks that everything is ready
scripts/new-version.sh X.Y.Z
```

It checks that the version is new, the tree is clean, `main` matches GitHub,
the last CI run on it passed and the release key is here. It asks once for
the key's passphrase and keeps GnuPG from forgetting it during the release.
Then it makes a branch `release-X.Y.Z` (`main` is protected and takes
changes only through pull requests), runs `scripts/release.sh` there, pushes
the branch and the tag, and opens the pull request *Release X.Y.Z*. It waits
for the *Release* workflow, seals the AppImages with
`scripts/sign-release.sh`, waits for the pull request's checks and merges it
with a merge commit. A merge commit keeps the tagged commit in `main`'s
history; a squash merge would not, and the next release's upgrade test would
not find the tag. It ends with the address of the draft release; publishing
it is a person's click. If a step fails, it stops and says what, and nothing
is published.

The sections below are what it does, step by step, for when a step has to be
repeated by hand.

## Making the release by hand

```sh
git switch -c release-X.Y.Z
SIGN_KEY=AFE940EDA5A0C5C4B94B0A3FB1764CFD72A238E6 scripts/release.sh X.Y.Z
```

The script checks that the tree is clean and the version is new, sets the
version everywhere, dates the changelog, runs clippy and all tests, commits
"Release X.Y.Z", makes a signed tag `vX.Y.Z`, and builds the source files.
It pushes nothing. GnuPG asks for the passphrase.

Then push the branch and the tag, and open the pull request:

```sh
git push -u origin release-X.Y.Z && git push origin vX.Y.Z
gh pr create --base main --title "Release X.Y.Z" --fill
```

Merge the pull request once its checks pass, with **Create a merge commit**
(not *Squash*), so the tagged commit becomes part of `main`.

## After the push

The *Release* workflow builds the AppImages for x86_64 and aarch64 from the
tag, tests them on fresh Ubuntu, Debian, Fedora, Arch and openSUSE
containers, adds build provenance for the source files (once the repository
is public) and makes a **draft** release with the files and the changelog as
notes.

1. **Sign the AppImages** on this computer, so the key never goes to GitHub:

   ```sh
   SIGN_KEY=AFE940EDA5A0C5C4B94B0A3FB1764CFD72A238E6 scripts/sign-release.sh vX.Y.Z
   ```

   It downloads the draft's files, writes the signature into each AppImage
   and checks it, writes the `.zsync` and `.sha256` files again (they
   depend on the signed file), adds a detached `.asc` signature to every
   file and uploads them to the draft.
2. Check the draft: every file is there (AppImages with `.zsync`, `.sha256`
   and `.asc`, source and vendored tarballs, `SHA256SUMS`), and the notes
   read well.
3. **Publish the draft.** This stays a person's decision.
4. Update the packages that are not built from the tag (AUR, COPR) with the
   checksums the script wrote.

Anyone can check a file with the public key:
`gpg --verify SAM-X.Y.Z-x86_64.AppImage.asc`, and, once the repository is
public, a source file's provenance with
`gh attestation verify sam-X.Y.Z.tar.gz --repo gitzekatze/SAM`.
