### Room service is tested with rooms that end with their program

Nothing changes for users; these are tests.

- Tests now ask for a room that ends together with the program that
  requested it (Bubblewrap's `--die-with-parent`, which helpers such as
  glycin use), check that it starts, and check that it ends when that
  program is killed.
- Tests now check that Room service runs only with a static room
  helper: one built to need a loader is refused, even when it is not
  empty.
