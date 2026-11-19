### One rule for asking, and risk words that count everything

- Every change that adds something rated *Think twice* or *Dangerous* asks
  first: a switch in the window, the Permission Manager for several apps
  at once, presets and the command line (`set`, `profile set`, `group set`
  need `--yes`). Before, some switches asked and others did not (X11, the
  webcam, the SSH agent, the filter switched off), the Permission Manager
  gave the full session bus to many apps without asking, and the window
  asked nothing at all when its permission list failed to load.
- Settings that take a protection away count in the risk word: the syscall
  filter or Landlock switched off, nested namespaces, passed-through
  variables that hold secrets, local services the app may reach, and raw
  Bubblewrap arguments (now *Dangerous*). The network together with your
  home, keys or passwords is *Dangerous*: the app can send what it reads.
- Every switch shows the same risk word as the assessment behind the
  badges and the asking (raw sound devices are *Think twice* in both now).
- An app's "Strict syscall filter" switch works by itself; the separate
  global switch for it is gone.
- An app whose settings nobody has confirmed (added on the command line
  without `--accept`) does not start until they are confirmed.
