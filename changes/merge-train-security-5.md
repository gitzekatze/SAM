### SAM gives one clear reason when two rules refuse a user folder

- SAM has two rules for a user folder (Documents, Downloads and the
  others) reached through a link: one refuses a link in a folder the app
  can change, the other refuses a link the app could have planted out of
  what the home shows, and any link to where programs outside the
  sandbox listen. Each rule refuses on its own, so SAM shows the folder
  only where both allow it.
- Where both refuse a folder, the launch log now gives the reason of the
  second rule: it names the danger or says that the link leads out of
  what the home shows, and tells you how to show the folder if you made
  the link yourself. The shorter note that only names the link stays for
  a link in a folder the app can change that leads to a place the home
  shows anyway.
- With the whole home writable and Downloads set to read-only, the app
  can no longer plant a link in Downloads, since SAM mounts it read-only
  over the home. A link it planted in an earlier start, while Downloads
  was still writable, is still not followed.
