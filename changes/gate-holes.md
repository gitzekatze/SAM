### Tests cannot be emptied quietly

- The approval check also catches two more ways to switch a protected
  test off by only adding lines: `cfg_attr`, and a home-made `assert!`
  that checks nothing.
- 27 more test files are protected: the real attacks on the sandbox, the
  terminal, the network, signatures and unpacking.
- Changing the test machinery needs the owner: the CI workflow, the test
  runner, the rule for when a sandbox test may skip, the test environment
  and the builder of hostile test AppImages.
- The test runner in CI fails when a test program crashes before it ends,
  or when cargo reports an error without a failed test. Before, only the
  per-test lines counted, so a crash stayed green. It also keeps each
  test's program name again with current cargo.
- The `owner-approved` label counts only right after it is set: reopening
  a pull request takes it off, as a push does.
- A network test that failed about one run in three now picks its port
  outside the range pasta never forwards.
