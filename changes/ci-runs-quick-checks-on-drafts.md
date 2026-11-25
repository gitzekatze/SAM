### CI runs only its quick checks on draft pull requests

- A draft pull request now gets only CI's quick checks (formatting, the
  linters, the generated pages and documents), as a change of documents
  alone does; the build, test, window and sandbox jobs are skipped. Marking
  the pull request ready for review runs every job. Small pull requests of
  a batch are opened as drafts and tested whole once, through the batch's
  pull request. GitHub never merges a draft.
