### SAM rates key agents as dangerous

- The **SSH agent** switch is now rated *Dangerous* instead of *Think
  twice*. While your keys are unlocked, an app that reaches the agent can
  use them to log in to other computers and sign as you, without ever
  seeing the keys.
- An **extra socket** that belongs to a key agent is rated *Dangerous* too,
  and SAM says why: GnuPG's agent (`S.gpg-agent` and its `.ssh`, `.extra`
  and `.browser` sockets) and SSH agents at their usual places (OpenSSH's
  `/tmp/ssh-…/agent.…`, `ssh-agent` in a name, GNOME Keyring's, gcr's,
  1Password's and Bitwarden's). Such an app can also decrypt your files.
- A key agent together with the full network counts as *can send what it
  reads*, as your key folders already did.
- As before, SAM asks before you allow anything rated *Think twice* or
  *Dangerous*. Apps that already have the SSH agent keep it; only the
  rating and its warning change.
- An extra socket listed under another name that leads to a key agent is
  no longer passed in, as for the other dangerous sockets; list it by its
  real place if the app needs it.
