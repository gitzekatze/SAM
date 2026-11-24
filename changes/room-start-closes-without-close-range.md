### Rooms get nothing of SAM's launcher on kernels before Linux 5.11

- When Room service starts a room, every descriptor of SAM's launcher that
  the room does not need is closed as the room's sandbox starts. This used
  close_range, which needs Linux 5.11; on an older kernel the call failed
  without notice, and a descriptor of the launcher left open by mistake
  could reach the room. Now each one is closed on its own there.
