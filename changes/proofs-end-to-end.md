### Six more promises proven in a real run, not only by stand-ins

- A changed signing key: an update signed with another key is refused and
  its download deleted, until you accept the change.
- Bus names an app may not own (the desktop's own protocols, the shell):
  refused inside a real sandbox, also when written into the settings by
  hand.
- An image with a `..` entry, made by hand as an attacker would: refused,
  and nothing is written outside the app's folder.
- A hostile name in an AppImage's desktop file adds no line to SAM's menu
  entry.
- With the whole home writable, the file that says where Documents and the
  other user folders are stays read-only.
- Nested sandboxes stay refused with the syscall filter switched off, and
  the app has no capabilities at all, not even ones it could gain later.
