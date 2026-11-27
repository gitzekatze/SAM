### No access for files you open with an app now shares none of them

- Files opened with an app can be set to *No access*
  (`sam-jail set APP filesystem.opened_files none`). SAM accepted and saved
  that setting, but the sandbox still shared each file or folder named on
  the command line read-only, exactly as with *Read-only*. Now SAM shares
  none of them, not even read-only. *Read-only* and *Read & write* work as
  before.
- Old profiles that still say `opened_files = false` already loaded as *No
  access*; such an app now gets no file you open with it shared; it sees
  one only where another permission shows its folder. Set it to
  *Read-only* or *Read & write* if it needs them.
- With *No access*, the app starts in its private home instead of a folder
  it cannot see, and a terminal app's start line and the launch log say
  which file SAM did not share and why.
- The app's permissions page offers *No access* as a third choice. A saved
  *No access* used to show there as *Read-only*. Its description says
  that a file in a folder another permission shows stays visible.
- A file inside a folder the app may see anyway (a granted folder, the
  whole home) stays visible: the setting withholds what SAM would add for
  the start, not what another permission shows.
