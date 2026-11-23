### Unpacking with the system's tools gets a test

- SAM unpacks most AppImages with its own reader. The rare ones it cannot
  read go to the system's tools: lzo-compressed images to `unsquashfs`,
  and the old type 1 AppImages to `bsdtar`. A new test sends one of each
  through `sam-jail add` and checks that the tool unpacked it inside the
  unpack sandbox, with SAM's options, and that the files came out whole.
  Before, no test ever saw these tools succeed, although the contract with
  them was listed as fully tested.
