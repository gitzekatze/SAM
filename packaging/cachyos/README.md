# CachyOS packaging

CachyOS uses the Arch package format; the PKGBUILD in `../arch/` is the
CachyOS package. CachyOS's own build flags (x86-64-v3/v4, LTO) apply
automatically when it is built with the CachyOS `makepkg.conf`.

```sh
cd ../arch
makepkg -si
```

Runtime notes for CachyOS (KDE Plasma, Wayland, PipeWire, recent kernels):

- Landlock is available on CachyOS kernels and is enabled by default.
- `xdg-dbus-proxy` is recommended so the filtered session bus works.
