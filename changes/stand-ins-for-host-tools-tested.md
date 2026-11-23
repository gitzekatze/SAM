### The stand-in for `flatpak-spawn` gets a test in a real sandbox

- Inside every sandbox, SAM replaces the programs that ask a service
  outside to start a program: `systemd-run` runs the command right there,
  in the sandbox, and `flatpak-spawn` refuses. Only `systemd-run` was ever
  run inside a sandbox by a test. A new test runs both in a real sandbox,
  also with `systemd-run` installed as a link, and fails if either reaches
  the program it replaces.
