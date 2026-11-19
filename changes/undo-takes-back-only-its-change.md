### Undo takes back only its own change, and one permission list

- The window saves only what you changed, on top of the app's settings as
  they are now. Before, it wrote back the whole set it had loaded, so a
  change made meanwhile in the Permission Manager, on the command line or
  by a repair step was silently undone. If someone changed the same
  setting in between, SAM changes nothing and says so (code
  `changed-meanwhile`).
- Undo in the Permission Manager takes back only that change; later
  changes stay. Switching off repair steps leaves settings you changed
  yourself after the step as you set them.
- An undo that adds something rated *Think twice* or *Dangerous* back asks
  like every other change (`group restore --yes`); before, `group restore`
  could grant anything without asking.
- New: `sam-jail profile change APP` applies a change given as "from" and
  "to". `group restore` reads the new `undo` object of `group set`
  (JSON interface level 2).
- One permission list: `sam-jail info` shows every permission (it left out
  Bluetooth, the SSH agent, the key folders, bus names, variables and all
  advanced settings), the window shows the replacement of bundled
  libraries, and the permissions page names every key. Tests keep the
  window, `info` and the documentation in line with the catalogue.
