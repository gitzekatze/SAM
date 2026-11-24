### Tests now notice an update installed without a question when GnuPG is missing

The mutation run of 2026-11-24 found that no test covered an update whose
signature cannot be checked because GnuPG is missing, after the installed
version's signature was checked. A test now updates such an app from a
local server with GnuPG taken away, and notices:

- the update installed without asking first;
- the installed version changed before the person said yes;
- a yes to the file that was shown covering a newer file published
  meanwhile, or not installing the file shown.

Nothing changes for users; these are tests.
