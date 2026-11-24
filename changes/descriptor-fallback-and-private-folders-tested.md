### Older kernels' descriptor marking and private folders' upper end are tested

- SAM marks every descriptor it inherited close-on-exec, so none reaches
  an app's sandbox. Linux 5.11 and later do this in one call; older
  kernels go through the list in `/proc/self/fd`. Test computers all
  have newer kernels, so that list was never walked in a test. A test
  now takes it on any kernel and checks that an inherited descriptor is
  marked, a marked one keeps its mark, and the standard three are left
  alone.
- When SAM makes an app's folders private, it stops below SAM's data
  folder. A test now checks that the data folder and the folders above
  it keep their modes, so the person's own folders are never changed.
