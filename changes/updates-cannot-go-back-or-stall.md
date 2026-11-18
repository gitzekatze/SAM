### Updates cannot hand out an older version or keep SAM busy

- A signed update that was signed earlier than the installed version is an
  older version and is refused, for apps and for SAM itself: whoever
  controls the download could otherwise install an old release with
  security holes fixed since.
- A hostile update server can no longer stall or crash SAM: every request
  has a time limit, downloads have a size limit, update addresses are not
  expanded as patterns, sizes in the update description are checked
  before use, and planning a partial download stops after a minute.
- A GitHub update source named "." or ".." is refused.
- Data kept from a removed app goes back only to that same AppImage; a
  different file that gets the same short id gets an id of its own.
