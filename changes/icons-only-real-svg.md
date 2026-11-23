### Only a real SVG is taken as an SVG icon

- An AppImage's icon counted as SVG when the text `<svg` appeared anywhere
  in its first 2 KiB, so an XPM or ICO image could reach the desktop's
  image code under an `.svg` name. SAM now takes an SVG only when it is
  text whose first element is `<svg`; other icons are left out and the app
  shows the standard icon.
