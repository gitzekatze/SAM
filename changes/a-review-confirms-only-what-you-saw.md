### Confirming an app confirms only what its page showed you

- "Confirm Settings", "Mark as Reviewed" and "Got It" on an app's page
  now confirm only the app as the page showed it. When the app changed
  after the page was drawn (its settings, its AppImage, or a new notice,
  for example from "Unpack Again" in a terminal), nothing is confirmed:
  SAM says so and shows the app as it is now, so you can look again.
- The question of "Confirm Settings" also names the note about an
  updated AppImage's needs, which confirming accepts too.
- `sam-jail info` shows a `review_fingerprint`, and
  `sam-jail review APP --seen FINGERPRINT` confirms only that state.
