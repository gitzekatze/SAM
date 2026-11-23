### Rules for functions and signals can be set on the command line while the list is empty

- `sam-jail permissions set <app> dbus.session.calls <rule>` (and
  `dbus.session.broadcasts`) refused a plain rule or a comma-separated list
  while the list was still empty, and took it once it had an entry. Both
  now take the same input as every other list.
