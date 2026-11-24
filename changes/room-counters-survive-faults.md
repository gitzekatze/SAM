### Room service keeps serving after a fault in one request

- Room service counts open requests (at most 64) and running rooms (at
  most 16). Before, a fault (an unforeseen error that ends a request's
  thread) skipped giving back its count. After 16 such faults every later
  room waited until the app ended; after 64 every request was refused, and
  the start record reported requests as unfinished that were not. Now
  each count is given back whenever its request ends, also by a fault.
