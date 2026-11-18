### A record changed outside SAM stays blocked until you confirm it

- When something other than SAM changed an app's settings, SAM refused the
  first start, but that refused start saved the record and erased the
  mark: the second start ran with the changed settings, never confirmed.
  Changing another switch, setting start arguments or the change check
  erased it as well. The mark is now kept through every save; only
  confirming (`sam-jail review`, or the button on the app's page) clears
  it. The same holds for a swapped AppImage file.
- A record without SAM's checksum (removed, or from a SAM version before the
  checksum) is marked too, and confirmed once.
- Work that takes a while (the update check, a start) saves onto the record
  as it is on disk now, so a switch you change meanwhile is no longer
  turned back.
