### Tests now notice when a start from the menu goes quiet

A start from the menu has no terminal, so SAM speaks through notifications.
The inspection's mutation run found that no test watched them. Tests now
notice:

- a refused or failed menu start (an app SAM does not know, a file name
  that is not valid text) that sends no notice;
- a start the sandbox check refuses that does not point to the app's
  *Test*;
- an app that fails right after starting without the notice "stopped
  right after starting", or a "Show the fix" button that does not open SAM
  at that app's repair page, or a button offered when no SAM window can be
  found;
- the notice sent for an app that ended fine, or for one that failed after
  it ran for a while;
- the files from the menu not reaching the app, or a leading `--` passed to
  the app as its first argument;
- a terminal app's window that waits for Enter after a clean end, or closes
  at once after a failure;
- `sam-jail man` writing no pages, or pages for the hidden developer
  commands instead of the visible ones.

Nothing changes for users: the checks moved into small functions of their
own, with the same behaviour.
