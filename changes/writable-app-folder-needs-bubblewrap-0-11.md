### The writable app folder asks for Bubblewrap 0.11

- SAM counted overlays, which the writable app folder needs, as available
  from Bubblewrap 0.10, but Bubblewrap added them in 0.11.0. SAM now asks
  for 0.11 or newer, and `doctor` and the warning at start name 0.11. With
  Bubblewrap 0.10 the app folder stays read-only, with the same
  explanation as on older versions.
