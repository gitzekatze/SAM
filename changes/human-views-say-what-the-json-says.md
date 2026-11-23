### `sam-jail command` keeps each option with its values

- `sam-jail command APP` shows the sandbox command one option per line.
  `--uid`, `--gid`, `--overlay-src`, `--overlay`, `--remount-ro` and
  `--json-status-fd`, which SAM's own command has, were split from their
  values, so `--uid` and `1000` stood on lines of their own. Every
  option of Bubblewrap now stays on one line with its values. The
  command itself was always complete and in order.
- The views the command line prints for people (risk, warnings, states,
  the dependency report, the command and the app list) are now tested
  against what the JSON says, so none of them can lose a warning or the
  risk unnoticed.
