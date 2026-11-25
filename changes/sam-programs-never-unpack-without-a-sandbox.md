### SAM never unpacks without a sandbox, whatever its program is called

- Where no sandbox can be built (Bubblewrap cannot run, or SAM's
  `sam-jail` is not next to the program), SAM refused to unpack an
  AppImage and checked signatures with GnuPG only in a sandbox, but it
  recognised its own programs by their file names. A package that renames
  them (for example a wrapped program in Nix) unpacked AppImages and ran
  GnuPG on their keys without any sandbox.
- Now every release build of SAM refuses to unpack there, whatever its
  program is called, and says which of the two is missing. Only developer
  builds of SAM's tests still unpack in their own process.
