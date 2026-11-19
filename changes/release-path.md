### The release key signs only what the release build made

- Before the release key signs an AppImage of a draft release, the signing
  script checks GitHub's build provenance: the file must be the one the
  build job made. A draft can be edited by anyone with access, and a
  changed file is now refused instead of signed.
- The build jobs make that provenance themselves; the software bill of
  materials comes from a job of its own that can change nothing; only the
  job that makes the draft may write. The source tarballs must match the
  checksums in the package recipe.
- The release script sets the tag only after everything is built.
- Every GitHub Action is pinned to a fixed commit, checkouts keep no
  token, and the website checks the diagram script it serves.
- CI runs shellcheck, ruff and zizmor; release builds use one fixed Rust
  version and stop on arithmetic overflow instead of wrapping around.
