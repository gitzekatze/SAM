### Updates stay safe: own download folder, same sandbox, a real way back

- Updates are downloaded and checked in SAM's own folder, not next to the
  AppImage: another app with access to that folder (often Downloads) could
  plant a link under the download's name, and SAM wrote the update through
  it into any of your files. SAM also never copies through a link when it
  puts the new version in place. The same for SAM's own update.
- An update keeps the app's sandbox. A new version that asks for more (for
  example by calling itself a network app) no longer gets it silently; the
  app page shows what it asks for.
- Going back to the earlier version destroyed it when both versions had the
  same file name, while saying the app was back. Now both versions are kept.
  The way back is also recorded before the new version is unpacked.
- A swapped AppImage is noticed even after "Check all AppImages for changes"
  or moving it: SAM compares with what it unpacked last.
