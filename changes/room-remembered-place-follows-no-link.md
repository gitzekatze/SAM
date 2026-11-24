### A room opens a place on a removable drive again without following links

- A place on a drive that may be unmounted (a stick, a second disk, a
  network mount) is opened again for each room. SAM now remembers where it
  really is when the app starts, with every link resolved, and opens it
  again there without following any link. Before, it followed links on the
  way: an app that can write a folder above such a place could plant a
  link there and learn from the room's refusal whether a file outside its
  sandbox exists. The room was refused either way; now the refusal is the
  same whatever the link leads to, and the launcher never looks there.
