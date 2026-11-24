### Room service tells a swapped stick from the one the app was shown

- A room shows a place on a drive that may be unmounted (a USB stick, a
  second disk) only while it is still the drive the app was shown when it
  started. Before, SAM compared only device and inode numbers, which
  another stick at the same port often has too (every FAT stick's top
  folder has the same inode). Now SAM also compares the drive's own
  identity: the mount's unique ID on Linux 6.8 and later, before that the
  file system's ID from `/dev/disk/by-uuid`.
