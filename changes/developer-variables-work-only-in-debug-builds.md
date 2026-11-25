### Developer variables work only in developer builds

- `SAM_CLI` and `SAM_RUN` (another `sam-jail` or `sam-jail-run` for the
  window), `SAM_LOCALE_DIR` (another folder of translations) and
  `SAM_DBUS_LOG` (a log of every D-Bus call) are for working on SAM itself.
  An installed (release) SAM now ignores them: it always uses its own
  programs next to it, its installed translations, and keeps no D-Bus log.
  A forgotten setting, or a variable something else put into your
  desktop's environment, can no longer make the window run another program
  outside any sandbox, change the wording of SAM's questions, or write your
  apps' D-Bus calls into a file.
- When the window and its command line tool do not match, the message now
  only asks you to install matching versions of both.
