### Texts are filled in once, and translations come only from SAM's folders

- A file or app name containing something like `{file}` is shown as it is;
  before, it was filled in again with another value of the same message.
- SAM installed in your home (for example in `~/.local/bin`) no longer
  looks for translations in `~/target/locale`, a folder other programs
  could fill with their own wording for SAM's questions. Only a program
  built from SAM's source checkout looks there.
