### The test against typing into your terminal accepts only a real refusal

- The hostile-AppImage test that tries to type into the terminal
  (`TIOCSTI`) counted any error as blocked. Without a terminal the call
  fails anyway (`ENOTTY`), so the test would have passed with SAM's syscall
  filter missing. It now counts only the filter's refusal (`EPERM`).
- The threat model now names the tests that prove this from inside a real
  sandbox: the breakout test (both ways of typing into a terminal are
  refused by the filter) and the terminal test (escape codes that reach
  past the terminal are dropped).
