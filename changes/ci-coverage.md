### Every proof runs somewhere, and CI says what did not run

- The Fedora job now also runs the proofs Ubuntu's runners cannot: "This
  computer only" (an app's ports offered on this computer only, the
  sandbox check's part for it) and the sound server refusing to load code.
- A test that does not apply to a machine ("not here") is named in the job
  summary, and the job fails when it is not on the agreed list for that
  machine. Before, such a test passed without a trace.
- Two checks that were left out without a word now say so: the sandbox
  check's part for "This computer only", and the sound server's refusal on
  a PipeWire older than 1.2.
- The weekly fuzz run draws a random seed at the start instead of using
  the week's number, which anyone could know in advance; the report names
  it, so a failure can be repeated.
- The testing guide names what CI machines cannot prove (granting real
  devices) and adds it to the manual checks.
