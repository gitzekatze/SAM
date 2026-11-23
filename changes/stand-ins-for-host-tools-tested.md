### The stand-in for `flatpak-spawn` gets a test in a real sandbox

- Inside every sandbox, SAM replaces the programs that ask a service
  outside to start a program: `systemd-run` runs the command right there,
  in the sandbox, and `flatpak-spawn` refuses. Only `systemd-run` was ever
  run inside a sandbox by a test. A new test runs both in a real sandbox,
  also with `systemd-run` installed as a link, and fails if either reaches
  the program it replaces.
- The contract for these tools (`host-escape-tools`) now also names the
  function it serves: the app can't start programs outside its sandbox.
- The README and the contributor guide now say what the tests really do:
  every security promise is attacked by a test, most of them from inside a
  real sandbox, and the threat model names each one.
