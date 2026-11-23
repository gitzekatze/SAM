### Unpacking keeps its limits with every tool and stops at a full disk

- The limits on files and size held only while SAM's own reader unpacked.
  When it could not read an image (for example one compressed with LZO),
  `unsquashfs`, `bsdtar` or `dwarfsextract` took over and were checked only
  after they had finished, so a crafted AppImage could fill the disk first.
  Now SAM stops any unpacking program as soon as it passes a limit, and no
  single file can grow past the size limit.
- Every unpacking program may now use at most 4 GiB of memory
  (`extraction.max_memory_mb`), so a crafted image cannot use up the
  memory and freeze the desktop while it unpacks.
- When the disk became full while unpacking, SAM did not notice: it filled
  the disk again with the next tool and then offered to let the AppImage
  unpack itself. Now it stops at once, removes what was unpacked and says
  that the disk is full.
- When the newly unpacked app could not be moved into place, the old one
  had already been moved away, and the app had no files left to start.
  Now the two change places in one step, and where the file system cannot
  do that, the old app is put back.
