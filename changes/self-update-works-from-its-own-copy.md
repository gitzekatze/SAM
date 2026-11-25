### SAM updates itself from its own copy, one update at a time

- When SAM updates itself, it now first copies its AppImage into its own
  folder and reads everything it needs from that copy: where updates are
  published, the parts of the old version it can reuse, and the signature
  of the running version. Before, it read the file in your folder while it
  worked, and a file shortened meanwhile could crash SAM. Your file is
  still moved to the backups at the end, as before.
- Only one update of SAM runs at a time. Updating SAM from the window and
  from the command line at once could delete the other update's files,
  the backup of the old SAM among them. A second update is now refused at
  once and says that SAM is already updating itself. Checking for a new
  version still works meanwhile.
