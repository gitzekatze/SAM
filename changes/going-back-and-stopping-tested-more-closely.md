### Going back after an update, and stopping an app, are tested more closely

Nothing changes for users; these are tests.

- Tests now check that stopping an app asks only that app's own
  processes to quit, never another sandbox's.
- Tests now check that going back after an update keeps each file's
  mode (nothing becomes writable for others), that a kept version
  changed since SAM checked it asks for a review, and that when going
  back fails, both versions stay where they were, also when they have the
  same file name.
