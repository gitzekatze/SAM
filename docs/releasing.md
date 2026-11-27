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
5a. **The outside world is fine:** no open `early-warning` issue for a
    distribution SAM supports, and `sam-jail doctor --contracts` shows no
    broken contract on this computer.
6. **The version report** for the finished state: `make report`. It also
   updates the dashboard and the function map's results.
7. **The changelog** has every user-visible change under *Unreleased*, in
   whole sentences.
8. **The Rust version for release builds** is still the one you want:
   `RUST_VERSION` in `.github/workflows/release.yml` (fixed, so the same
   tag gives the same files; CI tests with the newest stable Rust). It is
   named twice there, for the AppImage build and for the test app of the
   container test; raise both together, on purpose, after CI has been green
   with that version.
9. **The release key** is on this computer. Its fingerprint,
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
changes only through pull requests), runs `scripts/release.sh` there (set
`SAM_RELEASE_TEST_COMMAND` first, see below: that script runs no tests on
this computer), pushes
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
SAM_RELEASE_TEST_COMMAND=/path/to/run-tests-in-a-container \
SIGN_KEY=AFE940EDA5A0C5C4B94B0A3FB1764CFD72A238E6 scripts/release.sh X.Y.Z
```

The script checks that the tree is clean and the version is new, sets the
version everywhere, dates the changelog, runs clippy, has the whole test
suite run, commits "Release X.Y.Z", makes a signed tag `vX.Y.Z`, and builds
the source files. It pushes nothing. GnuPG asks for the passphrase.

The script never runs the test suite on the computer it runs on: the tests
start real sandboxes and SAM's own programs, and belong in a container or
under a separate account. `SAM_RELEASE_TEST_COMMAND` names the program that
runs them there; it gets the checkout's path as its one argument and
`SAM_REQUIRE_SANDBOX=1` in its environment, which it should pass on to the
tests, so a sandbox test that cannot build its sandbox fails instead of
passing. If that program fails, the release stops before its commit.
Without that variable the script stops before it changes anything, unless
`SKIP_TESTS=1` says the tests already passed elsewhere on this commit
(`SKIP_TESTS=1` skips clippy too).

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
containers, and makes a **draft** release with the files and the changelog as
notes. The build jobs themselves add build provenance for every file they
made, the unsigned AppImages included: GitHub's signed statement that this
workflow built them from this tag. The SBOM is made in a job of its own that
can change nothing, and gets its provenance from another job that runs no
third-party action; only the job that makes the draft may write.

The AppImages' programs contain no test or release tools
([Testing](testing.md)): the AppImage build writes the update information
and the `.zsync` file with a `sam-jail` of its own, a release build with the
`dev-tools` feature, and the test on fresh containers makes its test app
before the containers start, then checks that the shipped `sam-jail`
refuses those tools and `sam-jail-gui` the options `--screenshot`, `--size`
and `--delay` (`--focus-walk` takes no value, so only the source check in
`crates/sam-jail-cli/tests/shipped_programs.rs` guards it). `scripts/sign-release.sh`
signs with a release build that has them switched on, so signing runs like
the shipped program, with developer variables off. Before the release key
is used, the script runs `scripts/check-release-build.sh` on that tool,
which fails if the tool follows SAM's developer variables (debug
assertions turned on by Cargo settings from outside the repository);
`scripts/make-appimage.sh` (which the release workflow runs through
`make appimage`) runs the same check on its release tools and on the
`sam-jail` that goes into the AppImage, `scripts/release.sh` on the
`sam-jail` it builds for the man pages, and the package recipes' build steps
(not their test steps, which builders can skip) on the programs they build. The Makefile's `cli` target does not run it,
because a developer builds with it for local use and the check starts the
built program ([Packaging](packaging.md)).

1. **Sign the AppImages** on this computer, so the key never goes to GitHub:

   ```sh
   cargo build --release --locked --target-dir target/sign-tools -p sam-jail-cli --features dev-tools
   SIGN_KEY=AFE940EDA5A0C5C4B94B0A3FB1764CFD72A238E6 scripts/sign-release.sh vX.Y.Z
   ```

   It downloads the draft's files and first checks every one of them, before
   the key signs anything (a draft can be edited, and the release key must
   never sign anything else):
   - every AppImage, and every other file the script does not write itself
     (the SBOM), must be the file the release build of **this tag** made
     (`gh attestation verify --source-ref refs/tags/vX.Y.Z`: a file built
     for an older release is refused too);
   - the source tarballs must have the checksums `scripts/release.sh` wrote
     into the PKGBUILD;
   - `SHA256SUMS` and the AppImages' `.zsync` and `.sha256` files are
     written again from the checked files, never taken from the draft.

   A file that passes none of these (one added to the draft, say) stops the
   script with its name; remove it from the draft and start again. Then it
   writes the signature into each AppImage and checks it, adds a detached
   `.asc` signature to every file and uploads them to the draft.
2. Check the draft: every file is there (AppImages with `.zsync`, `.sha256`
   and `.asc`, source and vendored tarballs, `SHA256SUMS`, the SBOM `sam-vX.Y.Z.spdx.json`), and the notes
   read well.
3. **Publish the draft.** This stays a person's decision.
4. Update the packages that are not built from the tag (AUR, COPR) with the
   checksums the script wrote.

Anyone can check a file with the public key:
`gpg --verify SAM-X.Y.Z-x86_64.AppImage.asc`, and, once the repository is
public, a source file's provenance with
`gh attestation verify sam-X.Y.Z.tar.gz --repo gitzekatze/SAM`.
