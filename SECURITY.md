# Security policy

SAM - Sandboxed AppImage Manager exists to contain untrusted AppImages, so
a way out of its sandbox is the most important kind of bug.

## Checking a download

SAM's releases are signed with SAM's release key, whose public part is
[sam-release-key.asc](sam-release-key.asc) in this repository:

- fingerprint `AFE9 40ED A5A0 C5C4 B94B  0A3F B176 4CFD 72A2 38E6`;
- every release file has a `.asc` signature next to it:
  `gpg --import sam-release-key.asc`, then
  `gpg --verify SAM-X.Y.Z-x86_64.AppImage.asc SAM-X.Y.Z-x86_64.AppImage`;
- the AppImages also carry the signature inside, and SAM updates itself only
  to an AppImage signed with this key.

## Reporting a vulnerability

**Please do not open a public issue.** Report it privately through GitHub:
*Security* tab of this repository → *Report a vulnerability*. Include:

- what an app inside the sandbox can do that it should not (read, write,
  reach, start …);
- the SAM version (`sam-jail version`), the distribution, desktop and kernel;
- the app's settings (`sam-jail get APP`) and, if possible, a small test
  AppImage or script that shows it.

You get an answer within a week. Once a fix is released, the report is
published with credit, unless you prefer otherwise.

## What counts

In scope: anything that breaks a promise in [docs/security.md](docs/security.md),
for example
- leaving the sandbox or starting a program outside it;
- reading or writing files the settings do not allow;
- reaching D-Bus services, portals or network the settings do not allow;
- an AppImage that runs code while SAM only inspects or unpacks it;
- an AppImage's name, metadata or output that makes SAM grant more access.

Out of scope, because SAM does not claim to stop them (see the
[threat model](docs/threat-model.md)): what X11 apps can do once X11 is allowed, kernel
exploits, malware that is already root, and access the user granted.

## Supported versions

Only the newest release gets security fixes before 1.0.
