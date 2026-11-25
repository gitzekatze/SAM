### SAM refuses an older release also for apps checked before it kept the signing time

- SAM refuses an update that is signed with the same key as the installed
  version but earlier: an older release may have security holes that were
  fixed since. Apps whose signature SAM checked before it kept the signing
  time (before 18 November 2026) could still be handed an older release.
  Now SAM checks the installed version again at update time to learn when
  it was signed, and refuses the older release.
- When SAM still cannot read when one of the two versions was signed, it
  cannot tell whether the update is older, so it asks first, the same way
  as for a signature it cannot check (*Update Anyway*,
  `sam-jail update --accept-key-change`). A yes installs exactly the file
  you were shown.
- SAM does not update itself when it cannot read when the new release or
  the running version was signed.
