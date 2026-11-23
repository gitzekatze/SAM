### Risk words see where folders, sockets and bus names really lead

- Extra folders are rated where they lead. Written as `/.`, `//run`,
  `/tmp/..` or `~/..`, a folder used to read *Harmless* although the
  sandbox showed the whole computer or every home; it is now *Dangerous*
  and asks first, also when it comes in a preset. A folder that holds your
  home counts as the home, and a relative path or one with `..` is
  *Dangerous* too.
- A folder grant of `/tmp`, or of the places in it where terminal sessions,
  SSH connections and the X server listen, is *Dangerous*, also read-only:
  connecting to a program needs no write access, and a terminal session
  runs commands outside the sandbox. The explanation of extra read-only
  folders now says so.
- A password service allowed by name on the session bus (the Secret
  Service, KWallet, GNOME's keyring or online accounts) counts as the
  *Passwords & keyring* switch: *Think twice*, and asks first. A wildcard
  that covers the desktop portal is *Dangerous*: it lets every portal
  function through.
- Extra sockets are passed in from where their links lead. One reached
  through a link in a folder the app may change is left out with a note
  (the app could have pointed it at the session bus or another program),
  and so is one that leads to a socket SAM rates *Dangerous* unless you
  listed that socket itself. The sound server's own socket
  (`pulse/native`) as an extra socket is *Dangerous*, like *Sound without
  SAM's relay*.
