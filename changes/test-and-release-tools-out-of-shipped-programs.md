### SAM's programs no longer contain its test and release tools

- The installed `sam-jail` had hidden commands that only SAM's tests and
  its release process use: `dev make-fixture`, `dev bench`,
  `dev set-update-info`, `dev make-zsync` and `dev sign-appimage`.
  `sam-jail-gui` read the screenshot options `--screenshot`, `--size`,
  `--delay` and `--focus-walk`. Release builds, the AppImage and the
  packages now leave all of them out, so the programs carry less code that
  users never need.
- Builds from a source checkout (`cargo build`) still have them, and a
  release build has them with the `dev-tools` feature. The release checks
  now test that the finished AppImage refuses the five commands and the
  options `--screenshot`, `--size` and `--delay`; a check of SAM's source
  guards all of them, `--focus-walk` included.
