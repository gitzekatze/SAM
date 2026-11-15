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
   cargo install --locked cargo-mutants
   cargo mutants -p sam-sandbox -p sam-runner -p sam-intake -p sam-detect --in-place=false -o ../.work/mutants
   ```

3. **Real apps:** the 120-AppImage test set runs without a new failure
   (`tests/real-apps/run.sh`, see [testing](testing.md)).
4. **Translations are complete:** `python3 scripts/i18n.py check`.
5. **The version report** for the finished state: `make report`. It also
   updates the dashboard and the function map's results.
6. **The changelog** has every user-visible change under *Unreleased*, in
   whole sentences.
7. **The release key:** the GPG key that signs the release is on this
   computer, and its fingerprint is in `RELEASE_KEYS`
   (`crates/sam-runner/src/release_key.rs`). Without it, SAM cannot check its
   own updates and says so.

## Making the release

```sh
SIGN_KEY=<key id> RUNTIME=/path/to/runtime-x86_64 scripts/release.sh X.Y.Z
```

The script checks that the tree is clean and the version is new, sets the
version everywhere, dates the changelog, runs clippy and all tests, commits
"Release X.Y.Z", makes a signed tag `vX.Y.Z`, and builds and signs the
release files. It pushes nothing.

Then push the commit and the tag:

```sh
git push && git push origin vX.Y.Z
```

## After the push

The *Release* workflow builds the AppImages for x86_64 and aarch64 from the
tag, tests them on fresh Ubuntu, Debian, Fedora, Arch and openSUSE
containers, adds build provenance (once the repository is public) and makes
a **draft** release with the files and the changelog as notes.

1. Check the draft: every file is there (AppImages, source and vendored
   tarballs, checksums, signatures), and the notes read well.
2. Optionally check a file's provenance:
   `gh attestation verify SAM-X.Y.Z-x86_64.AppImage --repo gitzekatze/SAM`.
3. **Publish the draft.** This stays a person's decision.
4. Update the packages that are not built from the tag (AUR, COPR) with the
   checksums the script wrote.
