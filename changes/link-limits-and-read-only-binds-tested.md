### Link limits and read-only extra binds are tested

- SAM follows links the way Linux does when it works out where an app
  reaches a place, and when it checks a socket listed for the app. Tests
  now check the exact limit: a way through 40 links is followed, one
  through 41 counts as a loop, and a loop ends in time.
- Tests now check that a socket reached through a link in a folder SAM
  shows read-only for its own purposes (an extra bind, as for the
  diagnosis run) is passed in: the app cannot have made that link. Only
  a folder the app can write makes such a link suspect.
- Tests now check that a damaged record of the home's protections is
  refused as a whole, also when a line of a known kind has parts missing
  or too many.
