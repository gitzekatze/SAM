### The release key signs only what this release's build made

- The signing script now checks every file of a draft release before the
  release key signs anything: AppImages and the SBOM must come from the
  release build of that very tag (a file built for an older release is
  refused), the source tarballs must match the package recipe, and the
  checksum lists are written again from the checked files. A file someone
  added to the draft stops the signing instead of getting SAM's signature.
- The SBOM gets GitHub's build provenance too, from a job that runs no
  third-party action.
- The release script runs the test suite with the sandbox required: a
  sandbox test that cannot run fails the release instead of passing.
- CI checks more of its own rules in a required job: actions pinned to a
  full commit, checkouts without their token, read-only workflows, checked
  downloads, every script linted, and every test run that may not skip the
  sandbox. A document the tests read (`docs/permissions.md`) now runs the
  tests when it changes, and the weekly fuzz runs require the sandbox.
- `make test` and the scripts that run the whole suite (the flaky-test
  check, the version report) now require the sandbox too, as CI does; CI's
  rule check covers the Makefile and Python scripts. CI also runs
  actionlint, a checker for the workflow files, pinned to a checked
  release. In a Python script, the rule check counts only an environment
  the calling function itself sets, not one set in a function that may
  never run.
