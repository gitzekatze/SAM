### Sound goes through SAM's relay and can no longer load code into the sound server

- An app with only sound on could make your sound server, which runs
  outside the sandbox, load a module (shown on 2026-11-18). Now every app
  with sound gets its own small relay: a second copy of PipeWire's
  PulseAudio server with module loading switched off, passing the sound on
  to your PipeWire. Playing and recording work as before. The relay runs
  in a sandbox of its own (no home, no SAM folders, no network): PipeWire
  before 1.2 ignores the switch, and a module loaded there stays inside it.
- Where the relay cannot run (a sound server without PipeWire), the app has
  no sound, and the start says why. A new advanced switch, *Sound without
  SAM's relay* (Dangerous), allows the old direct connection anyway, with a
  warning at every start.
- `sam-jail doctor` says whether apps get sound through the relay, and
  `sam-jail doctor --contracts` checks that the relay refuses modules on
  your computer.
