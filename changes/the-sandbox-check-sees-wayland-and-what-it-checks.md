### The sandbox check sees the Wayland security context and a changed computer

- The sandbox check now names the Wayland security context (*Privileged
  Wayland functions hidden*): it fails when the desktop offers security
  contexts but refused one, so the app would get every Wayland function,
  such as reading the clipboard in the background. Before, the check only
  looked whether a Wayland socket was there, and passed.
- A passed check counts for later starts only while what it would check is
  unchanged: the folders, key folders, devices, ports and desktop services
  it finds on this computer, and what it expects of each. Before, a check
  that passed while the keyring was not running was reused after it
  started, without looking that it stays hidden.
- The check expects of the session bus what a start gives: the bus also
  where SAM found its socket without an address, the desktop portal only
  while it is allowed, and the names an app may own or call functions of;
  wildcards count as the filter reads them. Before, such checks could fail
  although the sandbox was right.
