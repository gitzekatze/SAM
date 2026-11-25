### A second launch no longer reports a folder SAM made itself as moved aside

- When an app that may write the whole home started while another app
  ran that saw a start folder such as `~/.local/bin` missing, SAM made
  that folder for the new start and then moved it aside again at once,
  because the other app had seen it missing. The new start then
  told you of something moved aside that no app had made, and lost the
  read-only lock on that folder anyway.
- SAM now leaves such a place missing while the other app runs. Both
  watches keep it empty: whatever an app puts there is moved aside, as
  for start files SAM never makes (`~/.bash_profile`). Without another
  app running, SAM makes the folder and locks it as before.
