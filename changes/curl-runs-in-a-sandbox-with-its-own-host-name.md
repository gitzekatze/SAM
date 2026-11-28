### SAM runs curl in a small sandbox with its own host name

- On a computer whose own name is not known locally, every curl SAM started
  (update checks, updates, the contract check and the bug report) sent this
  computer's name to the DNS server when curl's libraries loaded. SAM now
  runs every curl in a small sandbox with the host name `localhost` and a
  read-only view of the computer, so that lookup no longer happens.
- Without Bubblewrap, or when the sandbox cannot start, SAM sends no update
  request and says why.
