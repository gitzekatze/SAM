### The terminal filter works from an allow-list

- An app's output to your terminal now passes only whole, known, harmless
  pieces: text, colours, cursor movement, screen modes, the window title,
  links. Everything else is removed, including what is malformed or
  unknown. Before, the filter removed what it knew to be harmful, and a
  doubled escape, an escape inside another code, an extra parameter, a
  long sequence or the UTF-8 form of an 8-bit control code brought a
  clipboard code or a title report past it.
- Also removed now: programmable function keys, kitty's graphics and file
  transfer, font and working-folder codes. Images in the terminal (sixel,
  kitty graphics) are not shown for sandboxed apps.
- Requests the terminal answers (cursor position, colours, capabilities)
  pass only on SAM's terminal relay, where the answer goes to the app;
  without it the answer would land in your shell, so they are removed.
- When an app ends, SAM switches off mouse reporting, bracketed paste and
  similar modes it left on, and discards the terminal's late replies until
  it has been quiet for a moment.
- `sam-jail run jq . data.json > out.json` keeps its output exact: with the
  output going to a file, the app no longer gets a terminal of its own.
- One parser for terminal output (the log used a second one, which could
  keep half a code when a read cut it).
