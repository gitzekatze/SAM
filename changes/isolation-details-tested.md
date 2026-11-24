### D-Bus filter, 32-bit socket filter, Wayland check and shared homes are tested more closely

Nothing changes for users; these are tests.

- Tests now check that a bus name on the always-blocked list is not
  talked to while the other allowed names stay allowed, and that SAM's
  tray names get no numbered instance names.
- Tests now check that a 32-bit app opens every allowed socket family
  (internet, IPv6, netlink) as it would without the filter, not only
  local sockets.
- Tests now check that security contexts count as unsupported where no
  compositor answers or one hangs up.
- Tests now check that a launch that still runs keeps its record and its
  home is left alone; only a launch whose launcher is gone gets the last
  look.
