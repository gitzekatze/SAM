### Update downloads are tested more closely

Nothing changes for users; these are tests.

- Tests now check that an update description with exactly as many
  blocks as SAM plans with is accepted, that the short last block of an
  update is reused from the installed version only when both its
  checksums match, and that blocks which must match together with the
  next one (zsyncmake's usual choice) are reused, also in zsyncmake's
  short format.
- Tests now check that a failed download says why, also after other
  error output, and that the installed version, read into memory for a
  delta update, is released again afterwards.
