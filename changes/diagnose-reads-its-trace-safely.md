### The diagnose run reads its trace safely

- The trace of a diagnose run lies in a folder the app can write. SAM now
  reads it only as a plain file, at most 32 MiB, never through a link and
  never from a named pipe. An app could otherwise make SAM copy one of your
  private files into its log folder, fill SAM's memory or make it wait
  forever.
