### The Bluetooth switch's help names the 32-bit exception

- The help of the *Bluetooth* switch said that other apps cannot open
  Bluetooth connections. That is not true without exception: an app whose
  start program is 32-bit can open a socket through the old `socketcall`
  call, which SAM's filter cannot limit to the listed types, so it can be
  a Bluetooth socket even with the switch off. The help now names this
  exception and points to the security page, and the security page says
  that the gap reaches Bluetooth sockets too. What SAM allows or refuses
  does not change.
