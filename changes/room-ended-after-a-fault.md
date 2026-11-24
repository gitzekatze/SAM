### Room service ends a room whose request meets a fault

- A fault (an unforeseen error that ends a request's thread) after a
  room's Bubblewrap had started left that room unwaited and on the
  service's list, and the program that asked for the room waited for an
  answer until the app ended. Now the room is ended and waited for before
  its slot is given back, the program hears that a fault in Room service
  ended the room, and the start record names it.
