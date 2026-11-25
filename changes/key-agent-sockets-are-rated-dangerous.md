### SAM rates key agents as dangerous

- The **SSH agent** switch is now rated *Dangerous* instead of *Think
  twice*. While your keys are unlocked, an app that reaches the agent can
  use them to log in to other computers and sign as you, without ever
  seeing the keys.
- An **extra socket** that is a key agent at its usual places: GnuPG's agent (`S.gpg-agent`), OpenSSH's (`~/.ssh/agent/…` and `/tmp/ssh-…/agent.…`), `ssh-agent` in a name (systemd's, Bitwarden's), `openssh_agent`, GNOME Keyring's (`keyring/ssh`), gcr's (`gcr/ssh`) and 1Password's (`~/.1password/agent.sock`) is rated *Dangerous* too, and SAM
  says why. Such an app can also decrypt your files.
- A key agent together with the full network counts as *can send what it
  reads*, as your key folders already did.
- With access to the whole home, also read-only, the agents' sockets kept
  there stay hidden: 1Password's and Bitwarden's now too, OpenSSH's in
  `~/.ssh` as before.
- As before, SAM asks before you allow anything rated *Think twice* or
  *Dangerous*. Apps that already have the SSH agent keep it; only the
  rating and its warning change.
- An extra socket listed under another name that leads to a key agent is
  no longer passed in, as for the other dangerous sockets; list it by its
  real place if the app needs it. A link is passed in only when the name
  you listed is dangerous for the same reason as where it leads.
