### Apps' private folders are for your user only

- An app's private home, its own layer of a writable app folder and what
  SAM moved aside are now created readable by your user only (0700), and
  folders an older SAM made readable for everyone are tightened at the next
  start. Before, with the usual settings, other users on the computer could
  read them where they can enter your home folder (Debian's default) or
  where SAM's data folder lies outside it.
