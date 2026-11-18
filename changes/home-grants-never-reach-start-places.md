### Grants of parts of the home never reach start places, keys or SAM's records

- A writable folder that holds start places (`~/.config`, `~/.local`, a
  dotfiles folder) now gets the same protections as the whole home. Before,
  an app given `~/.config` could leave a new autostart entry, and nobody
  looked.
- A user folder (Documents, Downloads, …) that `user-dirs.dirs` sets to the
  home, a folder above it, a system folder, a key folder or a place inside
  SAM's folders is no longer shown. Before, a Documents folder pointing at `/home` showed
  every key in it. A user folder that is a link is shown where it leads.
- Files named on the command line are checked where they really lead: keys,
  credential stores (`~/.netrc` too), start places behind a link, and
  anything inside SAM's folders are never shared. Before, an app opened with
  its own record could rewrite it.
- With the whole home granted, a `~/.bashrc` (or another start file) that
  is a link no longer stops every app from starting.
- More credential stores stay hidden with the whole home: Vivaldi, Edge,
  Opera, LibreWolf and other browsers, Bitwarden and 1Password, the GitHub
  and GitLab command line tools, npm, PyPI, Cargo, rclone and other logins,
  and the data of Flatpak and Snap apps. A grant of any start place or
  credential store is now rated *Dangerous*.
- Launch logs and app records are readable by you alone, and a record is
  written to disk completely before SAM goes on.
