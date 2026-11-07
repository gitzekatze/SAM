# Tests

- Unit tests live next to the code in each crate (`cargo test --workspace`).
- The end-to-end sandbox test is `crates/appseal-runner/tests/sandbox.rs`.
- `fixtures/`: synthetic AppImages, generated with
  `appseal dev make-fixture fixtures/Hello.AppImage --name Hello`.
- `appimages/`: put real AppImages for the compatibility corpus here
  (not committed); see `docs/testing.md` for the manual checklist.
