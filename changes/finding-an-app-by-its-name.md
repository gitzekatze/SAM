### A name an app chose cannot take over another app's command

- `sam-jail run firefox` no longer starts an app added later that simply
  calls itself "firefox" in place of your "Firefox Web Browser". When a
  name matches several apps, the app that was there first keeps it; if
  that is not clear, SAM lists the apps and asks you to name one by its id.
