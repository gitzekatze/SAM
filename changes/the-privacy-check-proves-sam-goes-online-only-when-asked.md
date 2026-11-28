### A privacy check proves that SAM goes online only when you ask

- SAM refuses an update address that holds a login (`https://name:secret@…`,
  also with extra slashes or `%40`) before curl runs, so the login is never
  sent to a server.
- SAM's build gains a check of its own code. A safety net, not a proof: in the
  code CI's clippy compiles (the debug build for x86_64 with default
  features), a new direct call of a function listed in clippy.toml fails CI —
  clippy without an `#[expect]`, the pin test without its exact line in the
  reviewed list. It catches accidental new network or program calls in SAM's
  own code, not code written to get around it; the traced run and the request
  tests are the proof of what SAM does. The exact arguments of every update
  request are fixed by tests.
- In the tests, the window's start and SAM's everyday commands run under a
  tracer and make no internet connection.
- For an app with a `.zsync` source, what an update check and an update send
  is recorded by a stand-in server: only the address, the server's name,
  SAM's user agent, what SAM accepts and which part of a file. The GitHub
  request is built from tested arguments but not recorded. The privacy
  report (docs/reports) names what the checks do not cover.
