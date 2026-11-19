### The approval check cannot be talked out of itself

- The "Needs your approval" check runs its checker and settings as `main`
  has them. Before, it ran the pull request's own copy, so a change that
  also rewrote the checker could pass without the owner.
- Any change to the checker, its settings or the approval workflow needs
  the owner.
- The `owner-approved` label counts for what the owner saw: a later push
  takes it off.
- Protected tests can no longer be switched off by only adding lines
  (`#[cfg(any())]`, `#[ignore]`, an early `return`).
- Older or swapped versions of dependencies need the owner, not only new
  ones.
- CI no longer turns green without the tests: a change to
  `docs/contracts.toml` (built into SAM) runs them, the desktop test goes
  by cargo's exit status, and the nightly early warning fails instead of
  skipping where Bubblewrap is broken.
