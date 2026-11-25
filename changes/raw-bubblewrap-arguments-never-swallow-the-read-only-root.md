### Extra Bubblewrap arguments missing a value stop the start

- The advanced setting for extra Bubblewrap arguments is placed right
  before SAM's last step, which makes the sandbox's root read-only. When
  the list ended with an option still missing its value, that option took
  SAM's step as its value, and the root stayed writable without a word.
- SAM now refuses to start the app and names the incomplete option.
