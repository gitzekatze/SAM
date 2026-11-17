### Command-line tools work in pipes

- `cat data.json | sam-jail run jq .` printed nothing: a terminal program
  with its input from a pipe or a file got an empty terminal of its own
  and waited for typing that never came. Now the input goes to the tool
  and its output comes back to you.
- Output passed on without a terminal arrives unchanged, byte for byte:
  SAM no longer adds a line end at the end or splits very long lines, so
  data in a pipe stays exact. It also arrives at once, so a question
  without a line end ("Password: ") shows.
- Without a terminal of its own the tool has none to type into, and output
  shown in a terminal is filtered as before.
