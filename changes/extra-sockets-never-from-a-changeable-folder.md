### Extra sockets in a folder the app can change are no longer passed in

- SAM checks an extra socket when it builds the sandbox, but the sandbox
  takes it by name a moment later. If the socket lay in a folder the app
  may write, a running copy of the app could swap it for a link to
  another socket (such as the session bus) in between.
- Such a socket, also one below such a folder, is now left out with a
  note that says why. Where the app may use that folder, it still
  reaches the socket there. A socket in a folder the app may only read
  is passed in as before.
