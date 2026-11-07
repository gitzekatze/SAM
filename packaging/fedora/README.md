# Fedora (Phase 2)

Planned: COPR package (whitepaper §2.23, Phase 2). Build requirements map to
`cargo`, `cmake`, `qt6-qtbase-devel`, `qt6-qtdeclarative-devel`,
`kf6-kirigami-devel`, `kf6-kirigami-addons-devel`, `kf6-kcolorscheme-devel`,
`kf6-kconfig-devel`; runtime requires `bubblewrap`, `libarchive`,
recommends `xdg-dbus-proxy`. `make && make install DESTDIR=… PREFIX=/usr`
produces the same layout as the Arch package.
