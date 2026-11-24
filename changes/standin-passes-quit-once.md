### A program in a room is asked to quit exactly once

- When SAM asks an app to quit (Close, logout) while one of its programs
  is starting a room, the room's program is asked once, also when the ask
  comes just as the room's request goes out. Before, that moment could
  pass the ask on twice; a second ask means "quit now" to some programs,
  which then could lose what they were saving.
