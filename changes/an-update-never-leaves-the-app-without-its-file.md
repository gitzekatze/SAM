### An update or going back never leaves the app without its file

- An update now writes the new version whole under a hidden name in the
  AppImage's folder and then renames it into place. Before, SAM deleted the
  old AppImage first: a crash, a power loss or a full disk at that moment
  left no AppImage, or half of one.
- The earlier kept version is deleted only once the app's record names the
  new one. When an update fails before that, the old AppImage, the record
  and the way back stay as they were, and no temporary file is left.
- Going back works in the same order, so it no longer needs a second copy
  to undo a failed step, and it never replaces an earlier version that an
  interrupted run left aside. What such a run leaves, SAM repairs when it
  can tell the files apart; otherwise going back and updating stop and say
  where both files are, so you can choose which one to keep.
- A half-written copy that a stopped SAM left in the AppImage's folder
  (hidden, named `.sam-incoming-…`) is removed at the app's next update or
  go back.
