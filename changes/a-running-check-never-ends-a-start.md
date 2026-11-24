### A check whether an app runs no longer ends a start of that app

- When SAM's window, `sam-jail list`, removing or re-unpacking a sandbox
  checked whether an app runs at the very moment that app started, the
  start could end with "locking …/running.lock: Resource temporarily
  unavailable". A start now waits a moment for such a check, at most
  2 seconds, and otherwise stops with a message that names the lock.
