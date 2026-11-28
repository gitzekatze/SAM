### A privacy check proves that SAM goes online only when you ask

- SAM refuses an update address that holds a login (`https://name:secret@…`,
  also with extra slashes or `%40`) before curl runs, so the login is never
  sent to a server.
- A new direct call in SAM's program code of one of the functions listed in
  clippy.toml fails CI's clippy step until it is listed with its exact line.
  This covers the code CI's clippy compiles: the debug build for x86_64, all
  features. The exact arguments of every update request are fixed by tests.
- In the tests, the window's start and SAM's everyday commands run under a
  tracer and make no internet connection.
- For an app with a `.zsync` source, what an update check and an update send
  is recorded by a stand-in server: only the address, the server's name,
  SAM's user agent, what SAM accepts and which part of a file. The GitHub
  request is built from tested arguments but not recorded. The privacy
  report (docs/reports) names what the checks do not cover.
