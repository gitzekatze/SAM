### A man page for every command it names

- The man pages of `sam-jail config`, `group`, `preset` and `profile`
  pointed to pages for their commands (`sam-jail-config-get(1)`,
  `sam-jail-preset-apply(1)` and 20 more) that did not exist. Each of these
  commands now has its page, and the ten that had no description in
  `--help` got one.
- The pages no longer point to pages for `sam-jail help` and each
  command's `help`: they would only repeat `--help`, which every page
  lists. The `help` command itself stays.
