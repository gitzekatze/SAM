### SAM names the socket gap of 32-bit apps on their page and in the sandbox check

- For an app whose start program is 32-bit, the app's page and
  `sam-jail info` now say that its socket limit is incomplete: through
  the old socketcall call such an app can open sockets of families the
  filter would refuse, as in Flatpak, and with full network access also
  Bluetooth sockets when its Bluetooth switch is off. The sandbox check
  adds the same note; it does not count as a failure, so the app still
  starts.
