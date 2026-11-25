### The sandbox's systemd-run stand-in understands more of its options

- Inside the sandbox, `systemd-run` is a stand-in that runs the command
  directly. It did not know that `--job-mode` and `--capsule` (`-C`) take
  a value, so a start script using them ran that value as the command
  and failed. It now skips them like the other options.
