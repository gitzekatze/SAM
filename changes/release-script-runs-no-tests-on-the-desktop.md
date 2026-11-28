### The release script no longer runs the tests itself

- `scripts/release.sh` no longer starts SAM's test suite itself: the tests
  start real sandboxes and SAM's own programs, and belong in a container or
  under a separate account. It runs the program `SAM_RELEASE_TEST_COMMAND`
  names instead, with the checkout's path, and stops before the release
  commit when that program fails. Where that program runs the tests is up
  to it: the script does not check it.
- Without that variable, and without `SKIP_TESTS=1` after the tests passed
  elsewhere, the script stops before it changes anything and names both
  ways.
- `scripts/new-version.sh` checks the same among its ready checks: its dry
  run no longer says "ready" without either setting, and the real run stops
  before it makes the branch `release-X.Y.Z`.
