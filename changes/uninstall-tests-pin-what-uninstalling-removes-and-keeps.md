### Tests check what uninstalling SAM removes and keeps, and what a bug report hides

- A new test uses SAM through `sam-jail` in a test home and checks what
  `sam-jail uninstall --yes` removes and keeps, with and without
  `--keep-data`, for an unpack folder SAM made, the default one, a linked
  one and an earlier one.
- A new test checks that a report made with `sam-jail report` after the
  app ran does not show the home folder, the user name, an email or IPv4
  address or the value of a variable given to the app.
