# Tests

- Unit tests live next to the code in each crate (`cargo test --workspace`).
- The end-to-end sandbox test is `crates/sam-runner/tests/sandbox.rs`.
- `fixtures/`: synthetic AppImages, generated with
  `sam-jail dev make-fixture fixtures/Hello.AppImage --name Hello`.
- `appimages/`: put real AppImages for the compatibility corpus here
  (not committed); see `docs/testing.md` for the manual checklist.
- `gui/smoke.sh OUTDIR`: opens every page of the window against a
  throwaway data set and fails on GTK warnings (CI runs it on Broadway).
  Locally, run it inside the invisible session of `real-apps/run.sh`
  (`SESSION_SCRIPT`), never in your own desktop session.
- `real-apps/`: runs real AppImages through SAM's whole flow in an invisible
  KWin session with a private D-Bus and a fake home.
