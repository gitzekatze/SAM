# Debian / Ubuntu / Linux Mint (Phase 2)

Planned: Debian package / Ubuntu PPA (whitepaper §2.23, Phase 2).

Ubuntu 24.04+ restricts unprivileged user namespaces through AppArmor.
Bubblewrap needs an AppArmor profile there (`appseal doctor` detects and
explains this). Kirigami 6 / KF6 packages are required for the GUI; on
releases without KF6 only `appseal-cli` can be packaged.
