### Exit codes a script can rely on

- A command that ran but whose check did not pass now ends with 3 instead
  of 0: `verify` with a failed check, `selftest` with an app that failed,
  `doctor` with a failed check or a broken contract, and `preset apply`
  when it was not applied. So `sam-jail verify APP && sam-jail run APP`
  starts the app only when the sandbox check passed. The output still
  says what failed.
- `run --json` ends with the app's exit code, as `run` without `--json`
  already did; before, it ended with 0 even when the start failed.
- `compat APP ON` turns compatibility mode on (it meant off), and a word
  other than on or off is refused instead of meaning off.
