### SAM hides your keys without the whole home, whatever the key switches say

The switches for SSH keys, GnuPG keys and the other credential stores
apply only with full home access, as the settings window has always shown
them. The sandbox now follows the same rule:

- an app whose stored settings have one of these switches on but not the
  whole home (an old profile, a hand-edited file, `sam-jail set`) no
  longer sees `~/.ssh`, `~/.gnupg` or the credential stores where a
  granted extra folder shows them (for example `~/.ssh` kept as a link
  into a granted `~/Sync`); before, such a switch showed them there;
- a key folder that such a folder shows writable is watched like one the
  app was not given;
- the sandbox, the sandbox check and the "private keys exposed" warning
  now take this answer from one shared place.

With full home access nothing changes: the switches show the keys as
before.
