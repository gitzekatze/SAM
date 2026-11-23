### The Wayland security context is tested for what it hides

- With a security context, the desktop hides its privileged functions from
  the app: reading the clipboard in the background, capturing the screen,
  typing or moving the mouse for you, listing other windows. The test only
  checked that SAM's log said a context was made. It now asks the
  compositor, from inside the sandbox, which functions it offers the app,
  and compares them with what a program outside gets: every one of these
  functions must be missing for the app. It runs in the hidden KDE
  session of `tests/gui/desktop-sandbox.sh` with a newer KWin (6.8 was
  checked). CI's KDE session has KWin 5.27, which makes no security
  contexts, so CI cannot run this check yet.
- The security page now lists what KDE Plasma hides, and says what it
  still offers sandboxed apps: drawing a panel or overlay above other
  windows and changing the screen layout. That is the desktop's choice;
  SAM cannot narrow it.
