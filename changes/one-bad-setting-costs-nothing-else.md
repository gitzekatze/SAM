### One unreadable setting no longer resets all the others

- A value of the wrong kind in `config.toml` (for example `max_files = "x"`)
  or an unknown word now resets only that setting, and SAM says which one.
  Before, all settings went back to their defaults, so stricter choices
  such as "never offer compatibility mode" were lost.
- The private data of an app whose record SAM cannot read (damaged and
  moved aside, or written by a newer SAM) is no longer offered as left
  over for deletion.
