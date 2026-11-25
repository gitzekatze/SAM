### A 32-bit call of a 64-bit app always ends it

- SAM's syscall filter compared a few call numbers before it checked
  whether a call came from 32-bit code. Two 32-bit calls of an app that
  is not a 32-bit app therefore got an error answer instead of ending the
  app, as the documentation says. The filter now checks the architecture
  first.
