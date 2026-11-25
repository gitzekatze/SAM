### A start file kept through several links, or through a link to a place that does not exist yet, cannot be planted

- With the home granted read/write, SAM looks again after a start at the
  places that would make the computer run something later, and puts back
  a protected link the app replaced. It looked only at the protected name
  itself. When `~/.profile` led through a second link (`~/cfg`) to the
  real file, an app could replace that second link with a folder of its
  own; when `~/.zshrc` led to a place that did not exist yet, an app could
  create it. Either way the protected link stayed as it was and led to the
  app's file outside the sandbox. SAM now also watches every further link
  on the way inside the home, and the first part of the way that does not
  exist, and puts them back or moves aside what the app left there, while
  the app runs and after it ends.
- A folder on that way that the app swaps for a link of its own is moved
  aside, so the way leads nowhere rather than into the app's folder. A
  place that is only on the way (such as a sync folder a link points
  into) is never deleted: when it cannot be moved aside, SAM says it is
  still there. A launch next to a running one also keeps watching every
  place the running one watches.
