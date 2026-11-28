### A privacy check proves that SAM goes online only when you ask

- SAM refuses an update address that holds a login (`https://name:secret@…`)
  before curl runs, so the login is never sent to a server.
- Tests now keep SAM's network use as the security page describes it
  (*Network use by SAM itself*): a new way to start a program, open a socket
  or hand over a link in SAM's code fails the build until it is listed, and
  the exact arguments of every update request are fixed.
- The window's start and SAM's everyday commands run under a tracer in the
  tests, and none of them opens an internet socket.
- What an update check and an update send is recorded by a stand-in server:
  only the address, the server's name, SAM's user agent, what SAM accepts
  and which part of a file. The privacy report (docs/reports) names what
  the checks do not cover.
