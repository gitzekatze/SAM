### The update check asks no server for an AppImage replaced outside SAM

- The update check took the update address from whatever file was in the
  AppImage's place. Another app that can write to that folder could put
  its own file there, naming an address of its choice: SAM then sent that
  address when you checked for updates (a way for an app without network
  to send data out), and could offer that app's page as the download page.
- Now SAM checks only the AppImage it unpacked last. It reads the file
  once, compares its checksum and takes the update address from exactly
  the bytes it compared. A file that changed outside SAM is not checked,
  no server is asked, and the app page says so: use **Unpack Again** and
  look at the app first.
