### The desktop services an app may use reach only their own objects

- The services SAM allows on the filtered session bus by default or through
  a switch (notifications, the tray, the input methods' sandbox frontends,
  the screen saver and power management's inhibit object for media
  controls, the file manager) now reach only their own objects. Before, the app could talk to
  the whole program behind such a name, also through the program's unique
  name: on KDE Plasma 6 the notification service is run by plasmashell,
  which also holds Klipper's clipboard history and the shell's script
  runner; the tray watcher is run by kded6 with the desktop's background
  services; the screen saver name is held by KWin with its scripting; the
  file manager name by Dolphin with its menu actions. Notifications, tray
  icons, input methods, screen saver inhibition and "Show in folder" work as
  before.
- The keyring switch still reaches its whole service: it hands out every
  stored password anyway. Any other name you allow yourself still reaches the
  whole program behind it, as the settings reference says.
