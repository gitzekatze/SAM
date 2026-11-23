### Tests now check that every warning appears exactly where it applies

The mutation run found 23 small faults in the warning list that no test
noticed. Tests now check both sides, so each warning shows when it
applies and stays away when it does not:

- the danger warning that private keys are visible, for a full home with
  SSH keys, GnuPG keys or the other hidden files on (each on its own);
- the danger warning for raw input, USB or sound devices (each on its
  own) and the notice for unchecked Bubblewrap arguments;
- the full session bus named as a way out of the sandbox, dangerous
  allowed bus names and a missing xdg-dbus-proxy named for the filtered
  bus only, and a wildcard over a blocked name named only where it would
  be used;
- "cannot open windows" only without any display, and the network advice
  only where it fits the setting and what the app seems to need;
- unusable user namespaces, a missing Wayland socket, X11 display or
  sound server named only on a computer that really lacks them.

Nothing changes in what SAM does; these warnings were already right.
