### A refused room names the connection number that is wrong

- A program that asks for a room while it holds an open connection
  numbered 1024 or higher still gets no room, as before. SAM's refusal,
  shown where Bubblewrap's error would be, now names that number, says
  that SAM's Room service accepts only connections numbered below 1024,
  and says what the program can do: close the connection or move it to a
  lower number before it starts `bwrap`.
- A request that names a negative connection number, or the same number
  twice, is refused with a reason that names that number, instead of
  "the request's connection numbers are not valid".
- The limits themselves are unchanged.
