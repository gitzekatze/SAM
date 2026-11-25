### The sandbox's systemd-run stand-in understands more of its options

- Inside the sandbox, `systemd-run` is a stand-in that runs the command
  directly. It did not know that `--job-mode`, `--capsule` (`-C`) and
  `--expand-environment` take a value, nor the value options of `run0`
  (`--group`, `--chdir`, `--area`, `--shell-prefix`, `--lightweight`),
  so a start script using them ran that value as the command and
  failed. It now skips them like the other options.
