### The weekly mutation run judges again

- The weekly mutation run stopped before judging anything: a test it may
  not skip needed PipeWire, which only CI's test job installed. Every run
  of the whole test suite now installs from one shared list, so a package
  one of them needs cannot be missing in another.
