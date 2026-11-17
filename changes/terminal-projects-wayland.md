### Three protections kept where they had gaps

- **Terminal:** an app started with its input redirected (from a script, or
  `< file`) had its output reach your terminal unfiltered, clipboard codes
  included. Its output now passes the same filter whenever it is shown in a
  terminal.
- **Project folders:** an app that calls itself a development tool no longer
  gets read and write access to `~/Projects` suggested; a writable project
  folder lets an app plant code that runs outside the sandbox (git hooks).
  You can still grant a project folder yourself.
- **Wayland:** when the desktop offers a Wayland security context but making
  one fails, the start is now marked *Protection missing*, like a missing
  Landlock or syscall filter, instead of only a note.
