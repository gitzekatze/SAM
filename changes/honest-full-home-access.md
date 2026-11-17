### SAM says plainly what full home access does not protect

- When an app gets read and write access to your whole home folder, SAM keeps
  keys hidden and the usual startup places (shell start files, autostart, menu
  entries) read-only, but it cannot protect every file other programs read.
  The warning in the window, the switch's description and the security page
  now say so, instead of promising more; stronger protection is being built.
- The security page also no longer suggests that replacing `systemd-run` keeps
  apps with full desktop-bus access away from system services.
