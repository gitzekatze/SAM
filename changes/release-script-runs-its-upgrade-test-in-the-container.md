### The one-command release no longer runs the upgrade test itself

- `scripts/new-version.sh` no longer starts the upgrade test
  (`tests/upgrade/run.sh`) itself: it builds the last release and starts
  SAM's programs and sandboxes, and belongs in a container or under a
  separate account. The script runs the program
  `SAM_RELEASE_UPGRADE_COMMAND` names instead, with the checkout's path and
  the last release's tag. Where that program runs the test is up to it: the
  script does not check it.
- The upgrade test counts as passed only when that program exits with
  status 0 and its output holds the test's line `RESULT pass`. Otherwise
  the release stops, and the script names the program, its exit status and
  the log `target/upgrade-test.log`.
- Without that variable, and without `SKIP_UPGRADE_TEST=1` after the
  upgrade test passed elsewhere, the dry run no longer says "ready" and the
  real run stops before it changes anything. `SKIP_TESTS=1` does not skip
  the upgrade test.
- The script no longer builds SAM on its own computer for the upgrade test.
