### A protected place whose name is not valid text stops the start

- SAM hides its own folders and key folders such as `~/.ssh` with an
  empty folder in their place, and locks start files and its own programs
  read-only. When such a place's name was not valid text, SAM wrote it
  with a replaced character, so the empty folder landed at another name
  and the real folder stayed visible; a lock was left out, so the place
  stayed writable.
- Such a name now stops the start with a message that names the place,
  as it already did for other required places. The same holds for the
  folder an app starts in and for an app folder kept writable.
