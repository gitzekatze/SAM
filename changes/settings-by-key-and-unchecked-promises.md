### Rules for functions and signals can be set on the command line while the list is empty

- `sam-jail permissions set <app> dbus.session.calls <rule>` (and
  `dbus.session.broadcasts`) refused a plain rule or a comma-separated list
  while the list was still empty, and took it once it had an entry. Both
  now take the same input as every other list.

### Tests now notice more of what the inspection's mutation run found unchecked

- "This computer only" forwarding other ports than the ones listed, or
  the host's DNS (port 53).
- A wildcard such as `org.kde.*`, a sub-name such as
  `org.gnome.Shell.Screencast`, a versioned name such as `org.kde.kded5`
  or a wildcard over the portal's names no longer counted as dangerous.
- A Docker, Podman, containerd, libvirt or bus socket listed as an extra
  socket rated lower than Dangerous.
- A misspelt key under `advanced.*` reported as set while nothing changed.
- A user-folder switch or a switched-on integration that silently did
  nothing.
- A settings file that cannot be read replaced by the defaults, the root
  or the home folder accepted as the extraction folder, and a current
  settings file migrated again.
