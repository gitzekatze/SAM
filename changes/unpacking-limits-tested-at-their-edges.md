### The unpacking limits are tested at their exact edges

- Tests now check that as many files and bytes as the limits allow are
  unpacked and one more is refused, that a folder the unpacking tool
  removes or locks while SAM counts is still handled within the limits,
  and that a folder swapped for a link is never opened through it, so
  nothing outside the box is changed.
- Tests now check how the end of an unpacking tool is read: a plain
  failure is not reported as a size limit, a full disk is recognised by
  the exit code or by the tool's own message, and no memory limit set
  means the tool runs without one.
