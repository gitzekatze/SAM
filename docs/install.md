# Install SAM

> **Status:** SAM's first release, version 0.2.0 (a beta), is being prepared.
> Until it is published there is no ready-made download. This page shows how
> installing will work, and how testers can build SAM themselves today.

## What your computer needs

SAM runs on Linux with a recent desktop:

- **Ubuntu 24.04** or newer, **Debian 13**, **Fedora 40** or newer, **Arch
  Linux**, **CachyOS** or **openSUSE Tumbleweed** (others with the same
  software work too);
- **Bubblewrap**, which builds the sandboxes, and **GTK 4** with
  **libadwaita 1.5** or newer, which most of these systems have installed;
- optional, for some features: **xdg-dbus-proxy** (filtered desktop
  services), **passt** ("This computer only" network) and **strace**
  (diagnostic runs). SAM's *Diagnostics* page tells you if one is missing.

Older systems such as Ubuntu 22.04 or Debian 12 are too old; SAM says so
and does not start there.

## The AppImage (recommended)

From the first release on, SAM itself comes as one AppImage file that works
on all the systems above.

1. Download `SAM-…-x86_64.AppImage` from the
   [releases page](https://github.com/gitzekatze/SAM/releases)
   (`aarch64` for 64-bit ARM computers).
2. Allow it to run: right-click the file → *Properties* → *Allow executing
   file as program* (the wording differs a little between desktops).
3. Double-click it. SAM opens and adds itself to your application menu.

**Updates:** SAM checks for new versions when you ask (main menu → *Check for
SAM Updates*) and installs only versions signed with SAM's release key.

**Checking the download** (optional): every file on the releases page has a
signature; [SECURITY.md](../SECURITY.md#checking-a-download) shows how to
check it.

## Packages for your distribution

Packages that install through your usual software tool are planned with the
first release: in the **AUR** for Arch Linux and CachyOS, and a **COPR**
repository for Fedora.

## Your first sandbox

1. Open SAM. It lists the AppImages in `~/Applications` and a few other
   usual folders; add more folders with the folder button at the top left.
2. Select an AppImage. SAM shows the access it recommends, without running
   anything yet.
3. Change what you like, then press **Create Sandbox**, then **Launch**.

The [user guide](guide.md) explains every setting.

## For testers: build SAM yourself

<details markdown="1">
<summary>Building from the source code (for people comfortable with a terminal)</summary>

You need Rust 1.92 or newer and the development files for GTK 4 and
libadwaita.

**Arch Linux, CachyOS:**

```sh
sudo pacman -S --needed base-devel rust gtk4 libadwaita bubblewrap xdg-dbus-proxy passt git
```

**Fedora:**

```sh
sudo dnf install cargo gtk4-devel libadwaita-devel bubblewrap xdg-dbus-proxy passt git gettext
```

**Ubuntu 24.04 or newer** (Ubuntu's Rust is too old; install Rust with
[rustup](https://rustup.rs) first):

```sh
sudo apt install build-essential libgtk-4-dev libadwaita-1-dev bubblewrap xdg-dbus-proxy passt git gettext
```

Then build and install SAM:

```sh
git clone https://github.com/gitzekatze/SAM.git
cd SAM
make
sudo make install PREFIX=/usr
```

SAM then appears in your application menu. To remove it later, see
[Removing SAM](../README.md#removing-sam).

</details>
