### Settings and presets say what they are

- The last function or signal rule of a D-Bus service, and a variable set
  for an app, can be taken away again from the window. Before, the change
  was refused, so a Dangerous rule (one that reaches systemd, say) could not
  be taken back there, and undoing a group change of these rules failed.
- `sam-jail set APP dbus.session.calls 'org.example.A=Foo'` (and
  `dbus.session.broadcasts`, and `group set`) works while the list is
  empty, with a comma list like every other list.
- Changing an app's raw Bubblewrap arguments asks again, as any other
  Dangerous change does. Before, an app that already had some (accepted
  once) took any others without a question.
- One switch changed (`sam-jail set`, a group change, a repair step or its
  undo, a single switch in the window) no longer counts as confirming the
  settings SAM chose for an app added without `--accept`: it still starts
  only after `sam-jail review APP` or *Mark as Reviewed*. Applying a preset
  or setting the whole profile still confirms them.
- An app record whose format number was lowered while it kept SAM's
  checksum counts as changed outside SAM, like one without a checksum.
- The risk word of a preset is worked out from its permissions. A preset
  file placed in the presets folder by hand could show "Harmless" for full
  home and network.
- Importing a preset never replaces one of the same name: the file is
  imported as "NAME (imported)" and SAM says so.
