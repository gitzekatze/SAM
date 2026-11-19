### "This computer only" keeps the app's ports on this computer

- The app's own ports are offered on 127.0.0.1 and ::1 only. Before, pasta
  listened on every address: other computers could not use the port, but a
  network scan saw it.
- More local services are never taken over by an app automatically:
  browser and Node.js debugging, X11 and PulseAudio over the network, VNC,
  Remote Desktop, Docker, Kubernetes, Tor and other proxies, KDE Connect,
  Syncthing, Steam, Discord and more databases. List a port in
  `network.app_ports` when an app really needs it.
