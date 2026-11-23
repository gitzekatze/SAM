### Signatures are checked inside a sandbox

- GnuPG read the key and the signature that come inside an AppImage as you,
  with your home folder and the network, every time you added one. They are
  the AppImage maker's data, so GnuPG now reads them inside the same
  sandbox SAM unpacks in, with no network and nothing of your home.
