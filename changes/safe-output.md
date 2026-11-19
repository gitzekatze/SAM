### Nothing SAM prints can reach past your terminal

- Every line SAM prints passes one filter: text, line breaks, tabs and
  SAM's own colours stay; escape codes, direction overrides and invisible
  characters are removed. Before, an AppImage's file name, the lines of its
  log, the error line a failed start was explained with, and preset and
  release names reached the terminal as they were, with a clipboard code or
  a window title in them. Rust's code check now refuses any other way of
  printing.
- Names lose direction overrides and invisible characters, also in the
  window: `invoice‹override›fdp.exe` no longer shows as `invoiceexe.pdf`.
- Logs keep only the text of what the app and the unpack tools wrote, and
  older logs are shown that way too.
- `--json` output writes these characters as `\u` escapes: the same data.
- Bug reports also hide tokens after `#` and inside link paths,
  `Authorization` and cookie lines and named secrets (`token=`,
  `password:`), and an app's log can no longer end the report's code block.
- Logging out while an app started from the menu runs: SAM asks the app to
  quit, gives it 10 seconds, records the start as closed and cleans up.
  Before, SAM ended at once, the app was killed hard, and the start was
  neither recorded nor cleaned up.
