# Appseal — Corrected Whitepaper and Build Plan

Version: 3.0
Date: 2026-11-07
Status: Implementation-ready draft
Primary platform: CachyOS
Secondary platforms: Arch Linux, Fedora, openSUSE, Ubuntu, Linux Mint, Debian-based desktop distributions

---

## 1. Revision Notes

This document corrects and improves earlier drafts of the Appseal whitepaper.

### Major corrections

1. Network sandboxing has been rescoped.
   - The MVP will support full network access or no network access.
   - Localhost-only and domain-filtered networking are moved to experimental/advanced features.

2. AppImage compatibility has been expanded.
   - Appseal must handle Type 1 and Type 2 AppImages.
   - Appseal must support SquashFS, Zstd, gzip, and xz where practical.
   - Extraction must normalize permissions while preserving executability.
   - Appseal must set common AppImage runtime environment variables.

3. GPU and graphics support has been clarified.
   - GPU support requires more than exposing /dev/dri.
   - Appseal may need read-only access to host Vulkan ICD files, DRI drivers, and related driver metadata.

4. D-Bus sandboxing has been clarified.
   - Bubblewrap alone does not provide strong D-Bus filtering.
   - Bubblejail is recommended as an optional advanced backend for better D-Bus control.
   - Session D-Bus access is high risk.

5. Usability has been strengthened.
   - Appseal needs onboarding, plain-language permission explanations, repair tools, logs, and app status badges.
   - The UI should support both simple mode and advanced mode.

6. Firejail support is optional.
   - Firejail will not be enabled by default.
   - It is intended as a compatibility backend for advanced users.

7. Packaging has been narrowed.
   - The first release target is a native pacman package for CachyOS/Arch.
   - AppImage or Flatpak distribution of Appseal itself is secondary because Appseal needs host sandbox tools.

---

# 2. Whitepaper

---

## 2.1 Executive Summary

Appseal is a Linux desktop application that provides Flatseal-style permission management for AppImages.

It allows users to:

1. Add AppImages manually or detect them automatically.
2. Analyze AppImages for compatibility and required host resources.
3. Launch AppImages inside a sandbox using Bubblewrap by default.
4. Adjust permissions through a graphical interface.
5. Save reusable sandbox presets.
6. See clear warnings when permissions are risky.
7. Understand when an AppImage cannot be safely or functionally sandboxed.

Appseal is written in Rust and uses a KDE Breeze-inspired interface. It is developed with CachyOS as the primary platform, but designed to remain portable across mainstream Linux desktop distributions.

---

## 2.2 Problem Statement

AppImages are portable and convenient, but they usually run with the full permissions of the user.

A typical AppImage can access:

- The user home directory.
- The network.
- The display server.
- Audio services.
- GPUs.
- Removable media.
- D-Bus session services.
- Sensitive configuration files.
- Documents, downloads, pictures, music, and videos.

Flatpak provides a permission model and tools such as Flatseal. AppImage does not currently have a comparable mainstream permission manager.

Appseal fills this gap.

---

## 2.3 Goals

Appseal should:

1. Make AppImages safer by default.
2. Remain easy to use for normal desktop users.
3. Provide advanced controls for power users.
4. Support multiple sandbox backends.
5. Recommend safe but functional profiles.
6. Warn clearly when a permission is risky.
7. Detect common compatibility problems.
8. Integrate with desktop launchers.
9. Work natively on CachyOS.
10. Remain portable to other Linux distributions.

---

## 2.4 Non-Goals

Appseal is not intended to:

1. Replace Flatpak, Snap, or native package managers.
2. Become a full app store.
3. Guarantee perfect isolation against malicious software.
4. Sandbox root-level or kernel-level software.
5. Provide enterprise-wide policy enforcement.
6. Automatically fix every broken AppImage.
7. Hide security risks behind silent compatibility mode.

---

## 2.5 Threat Model

Appseal assumes the user is trusted, but individual AppImages may be untrusted, poorly packaged, or overly demanding.

### Threats Appseal should mitigate

1. Accidental access to unrelated user files.
2. Broad home directory access when only one folder is needed.
3. Network access for apps that should be offline.
4. Access to unnecessary devices.
5. Excessive D-Bus access.
6. Modification of unrelated configuration files.
7. Users unknowingly granting dangerous permissions.
8. Broken sandbox profiles causing silent failures.

### Threats Appseal cannot fully mitigate

1. X11 keylogging or screen capture by other X11 clients.
2. Kernel exploits.
3. Firmware compromise.
4. Root-level malware.
5. Social engineering.
6. Apps that require privileged host access to function.

Appseal must communicate these limitations clearly.

---

## 2.6 Design Principles

### 2.6.1 Secure by default, compatible by guided exception

Appseal should recommend safe defaults. If compatibility requires relaxing permissions, Appseal should explain why.

### 2.6.2 User control is mandatory

Advanced users must be able to override:

- Backend choice.
- Permissions.
- Dependency detection results.
- Compatibility warnings.
- Extraction behavior.

### 2.6.3 Compatibility is a first-class feature

Many AppImages are imperfect. Appseal should not silently fail. It should explain what is broken and offer safe fallbacks.

### 2.6.4 Prefer existing sandbox primitives

Appseal should orchestrate existing tools instead of inventing a new sandbox.

### 2.6.5 Make risk visible

Every risky permission should have a visible warning and a plain-language explanation.

### 2.6.6 Simple mode and advanced mode

Appseal should be usable by non-experts while still exposing detailed controls for power users.

---

## 2.7 Target Users

### Primary user

A CachyOS or Arch-based desktop user who uses AppImages and wants better sandboxing without writing manual Bubblewrap scripts.

### Secondary user

A general Linux user who wants a simpler, safer AppImage workflow.

### Power user

A user who wants to:

- Choose the sandbox backend.
- Create reusable profiles.
- Bind specific directories.
- Inspect generated sandbox commands.
- Debug sandbox failures.

---

## 2.8 High-Level Architecture

Appseal consists of the following components:

1. GUI
2. CLI
3. Core library
4. Runner
5. AppImage intake engine
6. Dependency detector
7. Profile engine
8. Backend orchestrator
9. Backend adapters
10. Storage layer

Conceptual structure:

    GUI / CLI
        |
    appseal-core
        |
    +---+----------------+----------------+
    |                    |                |
    AppImage intake      Dependency       Backend
    engine               detection        orchestrator
                                          |
                          +---------------+---------------+
                          |               |               |
                      Bubblewrap      Bubblejail       Firejail
                       default        optional         optional

---

## 2.9 Technology Stack

### Core language

Rust.

Rust is selected for:

- Memory safety.
- Performance.
- Strong typing.
- Good ecosystem for filesystem, process, and ELF handling.

### GUI

Primary recommendation:

- Rust core.
- Qt6/QML frontend.
- KDE Kirigami components where appropriate.
- Breeze visual style.

Fallback if Rust-Qt integration becomes too costly:

- Rust core exposed through C FFI.
- Thin C++ Qt shell.
- QML frontend.

Alternative fallback:

- Rust plus GTK4.
- Breeze-like theme.
- Weaker native KDE integration.

### CLI

A CLI is required for debugging, scripting, packaging, and QA.

Example commands:

    appseal scan
    appseal add /home/user/Applications/krita.AppImage
    appseal list
    appseal info krita
    appseal run krita
    appseal preset list
    appseal preset apply "Media Player Safe" krita
    appseal backend krita bubblewrap
    appseal doctor
    appseal logs krita

---

## 2.10 Application States

Each AppImage should have a clear state.

Possible states:

1. Detected
   - Found on disk but not yet added.

2. Registered
   - Added to Appseal database.

3. Extracted
   - Payload extracted successfully.

4. Profiled
   - Dependencies and recommended permissions generated.

5. Ready
   - Can be launched.

6. Stale
   - Source AppImage changed since extraction.

7. Broken
   - Extraction, dependency detection, or launch failed.

8. Unsafe
   - Appseal believes the app cannot be safely sandboxed.

9. Missing
   - Source AppImage no longer exists.

The GUI should display these states with badges.

---

## 2.11 AppImage Compatibility Model

This section corrects a major weakness in the previous draft.

AppImage compatibility is not trivial. Appseal must support the practical diversity of AppImages in the wild.

### 2.11.1 AppImage types

Appseal should support:

1. Type 1 AppImages
   - Usually ISO 9660 based.
   - Can often be extracted with libarchive-compatible tooling.

2. Type 2 AppImages
   - ELF container with appended SquashFS payload.
   - May use gzip, zstd, or xz compression.
   - Usually extractable using SquashFS tools if the payload offset is detected.

### 2.11.2 Extraction strategy

Preferred order:

1. Static extraction without executing the AppImage.
   - Safer.
   - Avoids running untrusted code during intake.

2. Use system tools or libraries:
   - libarchive for Type 1.
   - unsquashfs or compatible SquashFS extraction for Type 2.
   - zstd support where required.

3. Optional fallback:
   - Use the AppImage's own --appimage-extract mechanism only if static extraction fails.
   - Run fallback extraction in a restricted environment where possible.
   - Require user consent for fallback extraction of untrusted AppImages.

### 2.11.3 Extraction location

Default:

    ~/.local/share/appseal/extracted/<app-id>/

Each extracted app should have:

- AppDir payload.
- Metadata file.
- Extraction log.
- Desktop metadata cache.
- Icon cache.

### 2.11.4 Extraction safety rules

During extraction, Appseal must:

1. Preserve normal executable bits.
2. Remove setuid and setgid bits.
3. Sanitize unsafe permissions.
4. Preserve symlinks only when safe.
5. Detect suspicious file types.
6. Detect path traversal attempts.
7. Record file count and total size.
8. Abort if extraction exceeds user-configured limits.

### 2.11.5 Runtime environment

When launching an extracted AppImage, Appseal should set common environment variables where appropriate:

- APPDIR
- APPIMAGE
- OWD
- XDG_DATA_DIRS
- XDG_CONFIG_DIRS
- LD_LIBRARY_PATH only if needed
- QT_QPA_PLATFORM if needed
- GDK_BACKEND if needed

Recommended behavior:

- APPDIR should point to the extracted AppDir.
- APPIMAGE should point to the original AppImage path if available.
- If the original file is missing, APPIMAGE should point to the extracted AppRun or be unset with a warning.
- OWD should point to the original working directory used for launch.

### 2.11.6 Desktop metadata

Appseal should locate and parse:

- .desktop files inside the AppImage.
- Icon files.
- MIME types.
- Categories.
- Application name.
- Comment.

Search locations may include:

- Root of AppDir.
- usr/share/applications.
- usr/share/icons.
- AppRun-linked metadata.

### 2.11.7 Update and staleness handling

Appseal should detect when the source AppImage changes.

Detection methods:

- File modification time.
- File size.
- SHA-256 checksum.
- Inode changes.
- File moved or deleted.

When a change is detected:

1. Mark sandbox as stale.
2. Ask whether to re-extract.
3. Re-run dependency detection.
4. Recalculate recommended profile.
5. Warn if new permissions are required.

Appseal should not automatically replace a user-tuned profile without confirmation.

---

## 2.12 Desktop Integration

Appseal should create desktop launchers for registered apps.

Example desktop entry:

    [Desktop Entry]
    Type=Application
    Name=Krita
    Exec=appseal-run --app-id appimage-krita-9f3c %F
    Icon=appseal-appimage-krita-9f3c
    Categories=Graphics;
    Terminal=false

Important rule:

The desktop entry should launch the app through Appseal, not directly through the original AppImage.

Appseal should also:

- Extract icons.
- Install icons into its own cache.
- Update launchers when metadata changes.
- Remove launchers when apps are removed.
- Avoid duplicate entries.
- Handle broken or missing icons gracefully.

---

## 2.13 Sandboxing Model

### 2.13.1 Default backend

Default backend:

    Bubblewrap

Bubblewrap is selected as the default because it is:

- Lightweight.
- Widely available.
- Compatible with unprivileged user namespaces.
- Used by Flatpak.
- Easier to reason about than Firejail.

### 2.13.2 Backend choices

Appseal supports:

1. Bubblewrap
   - Default.
   - Best for most apps.

2. Bubblejail
   - Optional.
   - Useful for better D-Bus filtering and desktop-oriented sandboxing.

3. Firejail
   - Optional.
   - Disabled by default.
   - Useful for compatibility with certain complex apps.
   - Requires clear warning because of security tradeoffs.

4. Unsandboxed
   - Last resort.
   - Requires explicit confirmation.
   - Used only when sandboxing is impossible or breaks the app completely.

### 2.13.3 Backend selection logic

Automatic selection should prefer:

1. Bubblewrap if available and functional.
2. Bubblejail if D-Bus filtering is required and Bubblejail is installed.
3. Firejail only if the user enables it or a known compatibility preset requires it.
4. Unsandboxed only as explicit fallback.

Users can override the backend per app.

Appseal should display:

- Why the backend was chosen.
- Whether the backend is installed.
- Whether the backend is recommended.
- What risks the backend introduces.

### 2.13.4 Environment checks

Before launching, Appseal should check:

- Bubblewrap is installed.
- User namespaces are available.
- Unprivileged user namespaces are permitted.
- Required kernel features are present.
- Backend binary version is compatible.
- AppImage extraction exists.
- Desktop entry is valid.
- Required sockets exist.

If a check fails, Appseal should show actionable guidance.

Examples:

- "Bubblewrap is not installed."
- "User namespaces are disabled on this system."
- "The selected AppImage no longer exists."
- "PipeWire socket not found. Audio may not work."
- "The Wayland socket is not available."

---

## 2.14 Filesystem Model

Appseal should expose a minimal runtime filesystem.

Example sandbox view:

    /opt/app              extracted AppImage payload, read-only
    /usr/lib/dri          host GPU drivers, read-only
    /usr/share/vulkan     Vulkan metadata, read-only
    /etc/vulkan           Vulkan configuration, read-only
    /usr/share/fonts      fonts, read-only
    /etc/fonts            font configuration, read-only
    /usr/share/icons      icon themes, read-only
    /usr/share/locale     locale data, read-only
    /usr/share/zoneinfo   timezone data, read-only
    /etc/ssl/certs        certificates, read-only
    /tmp                  private temporary directory
    /run/user/1000        selected sockets only
    /home/user/...        user-selected directories only

Appseal should not expose the full host filesystem by default.

---

## 2.15 Permission Model

### 2.15.1 Permission categories

Permissions are grouped into:

1. Filesystem
2. Network
3. Devices
4. Display server
5. Audio
6. D-Bus
7. Sockets
8. Environment
9. Advanced kernel features

### 2.15.2 Filesystem permissions

Example permission levels:

- None
- Documents
- Downloads
- Music
- Pictures
- Videos
- Custom read-only paths
- Custom read/write paths
- Full home

Full home access should be high risk and require explicit confirmation.

Example configuration:

    [filesystem]
    home = false
    documents = "rw"
    downloads = "rw"
    music = "ro"
    pictures = "rw"
    videos = "ro"
    ssh = false
    gnupg = false
    hidden_files = false
    custom_read = []
    custom_write = []

### 2.15.3 Network permissions

MVP modes:

    [network]
    mode = "full" | "none"

Explanation:

- full: app shares host network.
- none: app is placed in an isolated network namespace.

Advanced/experimental modes:

    mode = "localhost"
    mode = "filtered"

These require extra tooling and should not be part of the MVP.

### 2.15.4 Device permissions

Example:

    [devices]
    gpu = true
    audio = true
    webcam = false
    input = false
    usb = false
    bluetooth = false

GPU access should expose:

- /dev/dri
- Relevant render nodes
- Host graphics driver files
- Vulkan ICD metadata where needed

Audio should expose:

- PipeWire socket
- PulseAudio socket where needed
- Required runtime directory entries

Raw ALSA device access should be off by default unless required.

### 2.15.5 Display permissions

Example:

    [display]
    wayland = true
    x11 = true

Appseal should warn:

    X11 access allows the app to observe input and other windows.
    Wayland is safer, but some apps may require XWayland.

### 2.15.6 Audio permissions

Audio should be treated as medium risk.

Supported audio stacks:

- PipeWire
- PulseAudio
- ALSA as fallback

Default recommendation:

- PipeWire socket access if PipeWire is detected.
- PulseAudio socket access if PulseAudio is detected.
- Raw ALSA devices only if required.

### 2.15.7 D-Bus permissions

D-Bus is high risk.

Example:

    [dbus.session]
    mode = "filtered" | "full" | "none"
    allow = []
    deny = []

    [dbus.system]
    mode = "none"

Defaults:

- System D-Bus denied.
- Session D-Bus filtered where possible.
- Full session D-Bus requires warning.

Bubblewrap alone cannot strongly filter D-Bus. Bubblejail or other tooling may be required for stricter filtering.

---

## 2.16 Dependency Detection

This section improves previous dependency handling.

Appseal must detect required host resources without blindly exposing the host system.

### 2.16.1 Primary method: static analysis

Appseal should scan ELF binaries inside the extracted AppImage.

It should inspect:

- Executable entry point.
- Bundled shared libraries.
- DT_NEEDED entries.
- Runtime search paths.
- Missing libraries.
- Graphics requirements.
- Audio requirements.
- Font requirements.
- Network certificate requirements.

Possible Rust crates:

- object
- goblin
- elf

### 2.16.2 Dependency classification

Dependencies must be classified.

#### Safe host resources

Usually safe to expose read-only:

- /usr/share/fonts
- ~/.local/share/fonts
- /etc/fonts
- /usr/share/icons
- /usr/share/locale
- /usr/share/zoneinfo
- /etc/ssl/certs
- /usr/share/themes
- /usr/share/mime

#### Controlled runtime resources

Exposed only if permission is enabled:

- Wayland socket
- X11 socket
- PipeWire socket
- PulseAudio socket
- D-Bus session socket
- GPU devices

#### Graphics and driver resources

Medium risk, often required:

- /dev/dri
- /usr/lib/dri
- /usr/share/vulkan
- /etc/vulkan
- Selected host graphics libraries if required

Appseal should prefer exposing driver directories over exposing arbitrary host libraries.

#### Dangerous host libraries

Should not be silently exposed:

- libc
- libstdc++
- libgtk
- libqt
- libssl
- libcrypto
- systemd libraries
- polkit libraries
- host graphical stack core libraries if ABI-sensitive

If these are missing, Appseal should warn that the AppImage may be incompatible.

### 2.16.3 Dynamic fallback

If static analysis is insufficient, Appseal may use a controlled diagnostic run.

Possible tools:

- strace
- ltrace
- bpftrace
- perf trace

Dynamic fallback workflow:

1. Launch app in diagnostic mode.
2. Use a broader but still limited sandbox.
3. Record denied paths and missing resources.
4. Classify failures.
5. Automatically grant low-risk fixes.
6. Ask the user for medium/high-risk fixes.
7. Save the resulting profile.

Dynamic tracing should not run with full home access by default.

### 2.16.4 Compatibility mode

If Appseal cannot safely detect all dependencies, it may offer compatibility mode.

Compatibility mode may include:

- Broader read-only host runtime exposure.
- Host theme directory exposure.
- Host GPU stack exposure.
- X11 access.
- D-Bus session access.
- Network access.

Compatibility mode must display warnings.

Example:

    This AppImage may require broader host access to function correctly.
    Appseal can grant additional permissions, but this reduces isolation.

---

## 2.17 Recommended Profiles

When an AppImage is added, Appseal should generate a recommended profile.

Recommendation sources:

1. Desktop entry category.
2. App name.
3. Binary name.
4. Detected libraries.
5. Detected GPU requirements.
6. Detected audio requirements.
7. Detected network requirements.
8. Known AppImage presets.

### Example profile categories

#### Browser

Recommended:

- Network: full
- Downloads: read/write
- Documents: read-only or none
- Audio: enabled
- GPU: enabled
- Wayland: enabled
- X11: enabled if needed

Warnings:

- Network access.
- X11 access if enabled.

#### Media player

Recommended:

- Network: none unless streaming is detected.
- Music: read/write
- Videos: read/write
- Pictures: read-only
- Audio: enabled
- GPU: enabled

#### Image editor

Recommended:

- Network: none
- Pictures: read/write
- Documents: read/write
- GPU: enabled

#### Game

Recommended:

- Network: full if multiplayer is likely.
- GPU: enabled
- Audio: enabled
- Game directories: read/write

#### Text editor

Recommended:

- Network: none
- Documents: read/write

#### Utility

Recommended:

- Minimal permissions.
- High caution if system access is required.

---

## 2.18 User-Defined Presets

The user can modify a recommended profile and save it as a preset.

Workflow:

1. Appseal recommends profile.
2. User adjusts permissions.
3. User clicks Save as Preset.
4. User names preset.
5. Preset can be applied to other AppImages.

Example presets:

- Strict Browser
- Media Player Safe
- Game Performance
- Untrusted Utility
- Office Documents Only

Preset data should include:

- Name
- Description
- Permission set
- Risk score
- Creation date
- Modification date
- Compatibility notes

Example preset:

    [preset]
    name = "Strict Browser"
    description = "Browser profile with no home access except Downloads"

    [permissions]
    network = "full"
    home = false
    downloads = "rw"
    documents = false
    audio = true
    gpu = true
    x11 = true
    wayland = true
    dbus_session = "filtered"
    dbus_system = "none"

When applying a preset, Appseal should:

1. Check compatibility.
2. Warn if the preset removes permissions the app likely needs.
3. Warn if the preset adds dangerous permissions.
4. Allow the user to confirm or cancel.

---

## 2.19 Security Model

### 2.19.1 Default posture

For a newly added AppImage, Appseal should prefer:

- No full home access.
- No system D-Bus.
- No raw devices.
- No privileged capabilities.
- No host /proc write access.
- No host /sys write access.
- No unnecessary libraries.
- Network only if recommended profile requires it.
- GPU only if app likely needs rendering.
- Audio only if app likely needs audio.

### 2.19.2 Risk scoring

Each permission receives a risk score.

Examples:

| Permission | Risk |
|---|---|
| Fonts read-only | Low |
| Icons read-only | Low |
| Locale read-only | Low |
| Timezone read-only | Low |
| GPU | Medium |
| Audio | Medium |
| Network | High |
| X11 | High |
| Home directory | High |
| Full home read/write | Dangerous |
| System D-Bus | Dangerous |
| Raw device access | Dangerous |
| Root-like capabilities | Dangerous |

### 2.19.3 Required warnings

Appseal must warn when:

1. X11 is enabled.
2. Full home access is enabled.
3. Network is enabled for an app that does not appear to need it.
4. System D-Bus is requested.
5. Firejail is selected.
6. User namespaces are unavailable.
7. AppImage cannot be safely extracted.
8. AppImage appears to require privileged access.
9. Dynamic tracing requests high-risk permissions.
10. The app changes and requires new permissions.

### 2.19.4 Unsafe AppImage handling

If Appseal determines an AppImage cannot be safely sandboxed, it should show one of these states:

1. Functional but weakly isolated

   Message:
   "This app can run, but meaningful isolation is limited."

2. Functionality likely broken

   Message:
   "This app probably cannot run correctly inside a sandbox."

3. Unsafe to sandbox

   Message:
   "This app requires access that cannot be safely sandboxed. Run unsandboxed only if you trust this application."

---

## 2.20 Usability Requirements

This section was underdeveloped in previous drafts and is now mandatory.

### 2.20.1 First-run onboarding

On first launch, Appseal should explain:

- What Appseal does.
- What sandboxing means.
- What permissions mean.
- That some apps may require compatibility mode.
- That X11 is less secure than Wayland.
- That Appseal cannot guarantee perfect security.

The onboarding should be short and skippable.

### 2.20.2 Simple mode and advanced mode

Appseal should offer:

1. Simple mode
   - Large toggles.
   - Plain language.
   - Recommended settings.
   - Minimal technical detail.

2. Advanced mode
   - Backend selection.
   - Detailed D-Bus rules.
   - Custom bind mounts.
   - Generated sandbox command.
   - Logs.
   - Diagnostic tools.

### 2.20.3 Drag-and-drop

Users should be able to drag an AppImage into the Appseal window to add it.

### 2.20.4 App status badges

Each app should show a badge:

- Ready
- Needs Review
- Compatibility Risk
- Stale
- Broken
- Unsafe
- Missing

### 2.20.5 Permission explanations

Each toggle should have a short explanation.

Example:

    Full Home Access
    Allows the app to read and write all files in your home directory.
    This is high risk and usually not required.

### 2.20.6 Repair workflow

If an app fails to launch, Appseal should offer:

1. View logs.
2. Re-extract AppImage.
3. Re-run dependency detection.
4. Reset profile to recommended.
5. Apply compatibility mode.
6. Switch backend.
7. Copy diagnostic report.

### 2.20.7 Logs and diagnostics

Appseal should provide:

- Launch logs.
- Sandbox command used.
- Backend output.
- Extraction logs.
- Dependency detection logs.
- Warnings.
- Crash exit codes.

A "Copy bug report" button should generate a redacted report.

### 2.20.8 Search and filtering

The app list should support:

- Search by name.
- Filter by state.
- Filter by risk level.
- Filter by category.
- Sort by recently used.

---

## 2.21 GUI Design

### 2.21.1 Main screens

Appseal should have:

1. Dashboard
2. App Details
3. Permissions Editor
4. Presets
5. Settings
6. Diagnostics

### 2.21.2 Dashboard

Displays:

- Detected AppImages.
- Manually added AppImages.
- Sandbox status.
- Last launched.
- Risk badges.
- Missing dependencies.
- Stale extractions.

Actions:

- Add AppImage
- Scan directories
- Run
- Configure
- Remove
- Update sandbox

### 2.21.3 App Details

Displays:

- App name.
- Icon.
- Source path.
- Checksum.
- AppImage type.
- Backend.
- Profile.
- Extraction status.
- Desktop entry status.
- Warnings.
- Dependencies.

### 2.21.4 Permissions Editor

Flatseal-style toggles for:

- Filesystem
- Network
- Devices
- Audio
- Display
- D-Bus
- Advanced

### 2.21.5 Preset Manager

Allows users to:

- Create presets.
- Edit presets.
- Duplicate presets.
- Delete presets.
- Apply presets.
- Import presets.
- Export presets.

Initial version can keep presets local. Later versions can support sharing.

### 2.21.6 Settings

Settings should include:

- Scan directories.
- Default backend.
- Theme.
- Extraction location.
- Automatic scanning.
- Desktop integration.
- Advanced kernel features.
- Diagnostic logging.
- Firejail enablement.
- Compatibility mode behavior.
- Simple/advanced mode.

### 2.21.7 Themes

Appseal should include four themes:

1. Breeze Light
2. Breeze Dark
3. Breeze High Contrast
4. CachyOS Neon

Theme selection should follow KDE styling conventions where possible.

---

## 2.22 CachyOS Integration

### 2.22.1 Primary platform

CachyOS is the lead development platform.

Appseal should be optimized for:

- Latest Linux kernels.
- KDE Plasma desktop.
- PipeWire.
- Wayland and X11 sessions.
- pacman package management.
- Modern hardware.

### 2.22.2 Kernel security features

Appseal should detect and optionally use:

#### Landlock

Used for additional filesystem restrictions.

Possible uses:

- Deny sensitive directories even if a parent directory is exposed.
- Enforce read-only behavior.
- Add defense in depth to Bubblewrap mounts.

Landlock should not be treated as a complete sandbox.

#### Seccomp

Optional syscall filtering.

Possible uses:

- Block dangerous syscalls in strict mode.
- Provide advanced profile option.

Seccomp must be optional because it can break apps.

#### eBPF

Experimental.

Possible uses:

- Network filtering.
- Advanced device policy.
- Observability.

eBPF features should be behind an experimental toggle and may require a privileged helper.

### 2.22.3 CachyOS package

Initial packaging:

- appseal
- appseal-cli

Dependencies:

- bubblewrap
- squashfs-tools
- libarchive
- zstd
- qt6-base
- qt6-declarative
- kirigami

Optional dependencies:

- bubblejail
- firejail
- strace
- bpftrace

---

## 2.23 Distribution Strategy

### Phase 1

Primary distribution:

- pacman package for CachyOS / Arch
- AUR package

This is the most reliable method because Appseal needs host access to sandboxing tools.

### Phase 2

Additional native packages:

- Fedora COPR
- openSUSE OBS
- Ubuntu PPA or Debian package

### Phase 3

Universal distribution may be added, but with caution.

Possible forms:

- Native static-ish binary with desktop assets.
- AppImage of Appseal for advanced users.
- Flatpak only if host sandbox tools are accessible and the design supports it.

The recommended primary distribution remains native packaging.

---

## 2.24 Storage Layout

Suggested filesystem layout:

    ~/.config/appseal/
        config.toml
        presets/
        logs/

    ~/.local/share/appseal/
        apps/
            app-id.json
        extracted/
            app-id/
        icons/
        desktop/

    ~/.local/share/applications/
        appseal-app-id.desktop

---

## 2.25 Configuration Example

    [general]
    theme = "breeze-dark"
    default_backend = "bubblewrap"
    scan_directories = [
        "~/Applications",
        "~/.local/bin",
    ]

    [security]
    warn_x11 = true
    warn_full_home = true
    warn_firejail = true
    allow_firejail = false
    experimental_landlock = true
    experimental_ebpf = false

    [dependencies]
    static_analysis = true
    dynamic_fallback = true
    automatic_low_risk_fixes = true

    [extraction]
    location = "~/.local/share/appseal/extracted"
    cleanup_stale = true

---

## 2.26 Error Handling and Diagnostics

Appseal should provide a diagnostics screen.

It should show:

- Missing backend binaries.
- User namespace availability.
- Bubblewrap version.
- Firejail status.
- Bubblejail status.
- Landlock availability.
- Extraction failures.
- Dependency detection failures.
- Sandbox launch logs.
- App crash logs.

Example diagnostic output:

    Bubblewrap: installed
    User namespaces: enabled
    Landlock: ABI v4 available
    Firejail: installed but disabled by default
    AppImage extraction: success
    Dependency detection: 3 host resources required
    Launch backend: bubblewrap

---

## 2.27 Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| AppImage formats vary widely | High | Robust intake pipeline, test corpus |
| Extraction consumes disk space | Medium | Cleanup tools, stale detection |
| GUI sandboxing breaks apps | High | Recommended profiles, compatibility mode |
| X11 cannot be secured | High | Warn users, prefer Wayland |
| Firejail security concerns | Medium | Optional, disabled by default |
| Missing dependencies | High | Static plus dynamic detection |
| Qt/Rust integration complexity | Medium | Thin C++ shell fallback |
| D-Bus filtering is difficult | High | Bubblejail optional, warn user |
| eBPF complexity | Medium | Defer to experimental phase |
| Cross-distro packaging complexity | Medium | Native packaging first |

---

## 2.28 Success Criteria

Appseal v1.0 should meet these criteria:

1. Add popular AppImages successfully.
2. Extract and launch them with Bubblewrap.
3. Generate reasonable recommended profiles.
4. Allow users to edit permissions.
5. Save and apply presets.
6. Show clear warnings for high-risk permissions.
7. Detect missing common host resources.
8. Integrate with desktop launchers.
9. Work on CachyOS with KDE Plasma.
10. Provide a CLI for debugging.
11. Pass basic sandbox escape and permission checks.
12. Package cleanly with pacman.

---

# 3. Build Plan

This build plan is designed for iterative development. It assumes Rust as the implementation language and CachyOS as the primary development platform.

---

## 3.1 Team and Effort Estimate

### Minimum viable team

- 1 Rust systems developer
- 1 UI developer familiar with Qt/QML or GTK
- 1 Linux packaging/QA contributor

If one person is doing all roles, multiply timeline by roughly 2x to 3x.

### Estimated timeline to v1.0

- Aggressive full-time schedule: 18 to 24 weeks
- Part-time open-source schedule: 6 to 9 months

---

## 3.2 Repository Structure

Recommended workspace:

    appseal/
        Cargo.toml
        README.md
        LICENSE
        docs/
            whitepaper.md
            security.md
            packaging.md
            profiles.md
        crates/
            appseal-core/
            appseal-backend-bubblewrap/
            appseal-backend-bubblejail/
            appseal-backend-firejail/
            appseal-detect/
            appseal-profile/
            appseal-storage/
            appseal-cli/
        gui/
            src/
            qml/
            themes/
        packaging/
            arch/
            cachyos/
            fedora/
            debian/
        tests/
            appimages/
            fixtures/
            integration/

---

## 3.3 Phase 0: Discovery, UX Prototype, and Compatibility Lab

### Duration

2 weeks

### Objectives

Validate the riskiest assumptions before building the full app.

### Tasks

1. Build minimal Rust prototype that:
   - Detects an AppImage.
   - Extracts it.
   - Launches it with Bubblewrap.

2. Build an AppImage compatibility corpus.

Suggested corpus categories:

- Browser
- Media player
- Image editor
- Video editor
- Game
- Terminal
- Text editor
- Utility
- Electron app
- Qt app
- GTK app

3. Test extraction:
   - Type 1 AppImages.
   - Type 2 AppImages.
   - Zstd-compressed AppImages.
   - AppImages with unusual desktop metadata.
   - AppImages with missing icons.
   - AppImages with broken permissions.

4. Test launch:
   - X11 session.
   - Wayland session.
   - PipeWire audio.
   - GPU rendering.
   - Network enabled.
   - Network disabled.

5. Evaluate UI stack:
   - Rust plus Qt6/QML.
   - Rust plus GTK4.
   - Thin C++ Qt shell fallback.

6. Draft simple-mode and advanced-mode UX flows.

### Exit Criteria

- At least 10 common AppImages can be extracted and launched inside Bubblewrap.
- A minimal permission set is sufficient for GUI, audio, and GPU.
- UI stack is selected.
- Major compatibility risks are documented.
- UX flows are drafted.

### Deliverables

- Prototype repository.
- Compatibility notes.
- UI stack decision document.
- Initial AppImage test corpus.
- UX wireframes.

---

## 3.4 Phase 1: Core Data Model and CLI

### Duration

2 to 3 weeks

### Objectives

Build the foundation used by both GUI and CLI.

### Tasks

1. Define core data types:
   - AppEntry
   - AppImageMetadata
   - SandboxProfile
   - Preset
   - PermissionSet
   - Warning
   - BackendChoice
   - DiagnosticReport

2. Implement configuration loading:
   - User config file.
   - Default scan directories.
   - Theme setting.
   - Backend defaults.
   - Security warnings.

3. Implement storage layer:
   - App registry.
   - Preset storage.
   - Logs.
   - Extraction metadata.

4. Implement CLI commands:

   - appseal scan
   - appseal add <path>
   - appseal list
   - appseal info <id>
   - appseal remove <id>
   - appseal run <id>
   - appseal doctor
   - appseal logs <id>

5. Implement basic logging and error reporting.

### Exit Criteria

- Appseal can add an AppImage by path.
- Appseal stores app metadata.
- Appseal can list registered apps.
- Appseal can remove registered apps.
- CLI can read and write configuration.

### Deliverables

- appseal-core
- appseal-cli
- Initial configuration schema
- Initial storage schema

---

## 3.5 Phase 2: AppImage Intake and Extraction

### Duration

3 to 4 weeks

### Objectives

Make AppImage ingestion reliable.

### Tasks

1. Implement AppImage magic detection.

2. Implement AppImage type detection:
   - Type 1
   - Type 2

3. Implement extraction support:
   - SquashFS
   - Zstd
   - gzip where possible
   - xz where possible
   - ISO9660/Type 1 where possible

4. Normalize extracted payload:
   - Remove setuid bits.
   - Remove setgid bits.
   - Sanitize permissions.
   - Preserve executable bits.
   - Handle symlinks safely.
   - Detect suspicious payloads.

5. Generate app ID:
   - Based on filename, checksum, and metadata.
   - Avoid collisions.
   - Keep human-readable slug where possible.

6. Extract desktop metadata:
   - Name
   - Icon
   - Categories
   - MIME types
   - Comment

7. Create launcher desktop entry.

8. Implement stale detection:
   - Checksum changed.
   - Source moved.
   - Source deleted.

9. Implement cleanup:
   - Remove extracted data when app removed.
   - Optional cleanup of stale entries.

10. Implement extraction limits:
   - Maximum file count.
   - maximum extracted size.
   - maximum extraction time.

### Exit Criteria

- Appseal can reliably extract common AppImages.
- Desktop entries launch through Appseal.
- Changed AppImages are detected.
- Removed AppImages are cleaned up safely.
- Extraction failures produce useful errors.

### Deliverables

- Extraction engine.
- Desktop integration engine.
- AppImage metadata parser.
- Stale detection logic.

---

## 3.6 Phase 3: Bubblewrap Backend MVP

### Duration

3 to 4 weeks

### Objectives

Implement the default sandbox backend.

### Tasks

1. Create backend trait.

2. Implement Bubblewrap adapter.

3. Build sandbox command generator.

4. Implement minimal safe sandbox:
   - User namespace.
   - Mount namespace.
   - Private /tmp.
   - Minimal /proc.
   - Controlled /dev.
   - Extracted app mounted read-only.

5. Implement permission mapping:
   - Filesystem toggles.
   - Network full/none.
   - GPU access.
   - Audio access.
   - Wayland socket.
   - X11 socket.
   - D-Bus session socket.

6. Implement warning generation.

7. Implement launch logging.

8. Implement crash capture:
   - Exit code.
   - Signal.
   - Sandbox command used.
   - Backend logs.

9. Implement environment checks:
   - bubblewrap installed.
   - user namespaces available.
   - backend binary version.
   - required sockets exist.

### Exit Criteria

- Appseal can launch most test AppImages with Bubblewrap.
- Permission toggles affect generated command.
- Warnings appear for risky permissions.
- Logs are useful for debugging.
- Network full and network none work reliably.

### Deliverables

- appseal-backend-bubblewrap
- Sandbox policy generator
- Launch diagnostics

---

## 3.7 Phase 4: Dependency Detection

### Duration

3 to 4 weeks

### Objectives

Detect required host resources without weakening security unnecessarily.

### Tasks

1. Implement ELF parsing for extracted binaries.

2. Identify bundled libraries.

3. Identify missing libraries.

4. Classify missing resources:
   - Safe
   - Controlled
   - Dangerous

5. Implement safe automatic fixes:
   - Fonts
   - Icons
   - Locale
   - Timezone
   - Certificates
   - Theme directories
   - GPU driver directories

6. Implement controlled fixes:
   - PipeWire
   - PulseAudio
   - Wayland
   - X11
   - D-Bus

7. Implement dangerous dependency warnings:
   - Host libc
   - Host GTK/Qt
   - Host crypto libraries

8. Implement dynamic fallback:
   - Optional first-run trace.
   - Detect denied paths.
   - Detect missing sockets.
   - Detect missing devices.

9. Implement dependency report data for GUI.

### Exit Criteria

- Appseal detects common missing resources.
- Safe fixes are applied automatically.
- Dangerous fixes require user confirmation.
- Dynamic fallback can diagnose basic failures.
- Dependency reports are understandable.

### Deliverables

- appseal-detect
- Dependency classification engine
- Diagnostic fallback runner

---

## 3.8 Phase 5: Recommended Profiles and Presets

### Duration

2 to 3 weeks

### Objectives

Implement profile recommendation and user presets.

### Tasks

1. Create recommended profile engine.

2. Use metadata to infer category:
   - Browser
   - Media
   - Game
   - Graphics
   - Office
   - Utility

3. Generate default permission set.

4. Calculate risk score.

5. Allow user modifications.

6. Implement preset saving.

7. Implement preset applying.

8. Implement preset import/export.

9. Implement compatibility checks when applying presets.

### Exit Criteria

- New AppImage receives a recommended profile.
- User can modify profile.
- User can save preset.
- Preset can be applied to another app.
- Warnings appear when preset is incompatible.

### Deliverables

- appseal-profile
- Preset manager logic
- Recommendation engine

---

## 3.9 Phase 6: GUI Implementation

### Duration

5 to 7 weeks

### Objectives

Build the Flatseal-like GUI with strong usability.

### Tasks

1. Set up Qt6/QML project.

2. Implement KDE Breeze styling.

3. Implement four themes:
   - Breeze Light
   - Breeze Dark
   - Breeze High Contrast
   - CachyOS Neon

4. Build Dashboard:
   - App list.
   - Add AppImage.
   - Scan.
   - Status badges.
   - Search.
   - Filters.

5. Build App Details screen:
   - Metadata.
   - Backend.
   - Extraction state.
   - Warnings.
   - Dependencies.

6. Build Permissions Editor:
   - Filesystem.
   - Network.
   - Devices.
   - Display.
   - Audio.
   - D-Bus.
   - Advanced.

7. Build Preset Manager:
   - Create.
   - Edit.
   - Delete.
   - Apply.
   - Import.
   - Export.

8. Build Settings screen:
   - Scan directories.
   - Default backend.
   - Theme.
   - Security toggles.
   - Experimental features.
   - Simple/advanced mode.

9. Build Diagnostics screen:
   - Backend availability.
   - User namespace status.
   - Landlock status.
   - Logs.
   - Copy bug report.

10. Build onboarding:
   - Short first-run explanation.
   - Permission explanations.
   - Security limitations.

11. Add drag-and-drop AppImage import.

12. Add repair workflow:
   - Re-extract.
   - Re-detect dependencies.
   - Reset profile.
   - Apply compatibility mode.
   - Switch backend.

### Exit Criteria

- GUI can perform all major CLI operations.
- User can add, configure, and run AppImages.
- GUI displays warnings clearly.
- Themes work.
- GUI is usable on KDE Plasma.
- Simple mode is understandable for non-experts.
- Advanced mode exposes enough detail for debugging.

### Deliverables

- appseal-gui
- QML components
- Theme assets
- Onboarding flow

---

## 3.10 Phase 7: Additional Backends

### Duration

2 to 3 weeks

### Objectives

Add optional backend support.

### Tasks

1. Implement Bubblejail adapter.

2. Add Bubblejail configuration generation.

3. Implement Firejail adapter.

4. Add Firejail warning flow.

5. Allow per-app backend override.

6. Add backend recommendation logic.

7. Add backend diagnostics.

### Exit Criteria

- User can choose backend per app.
- Bubblejail works where installed.
- Firejail is optional and clearly warned.
- Appseal explains why a backend was chosen.

### Deliverables

- appseal-backend-bubblejail
- appseal-backend-firejail
- Backend selection engine

---

## 3.11 Phase 8: Advanced Security Features

### Duration

3 weeks

### Objectives

Add CachyOS-oriented kernel security enhancements.

### Tasks

1. Detect Landlock support.

2. Implement optional Landlock filesystem rules.

3. Add seccomp strict mode as experimental.

4. Investigate eBPF network filtering.

5. Add experimental toggles.

6. Add warnings for experimental features.

7. Test on CachyOS kernels.

### Exit Criteria

- Landlock can strengthen filesystem restrictions.
- Experimental features are disabled by default.
- Appseal does not break on kernels without optional features.

### Deliverables

- Landlock integration
- Experimental security module
- Kernel feature detection

---

## 3.12 Phase 9: Packaging and Distribution

### Duration

2 to 3 weeks

### Objectives

Package Appseal for real users.

### Tasks

1. Create Arch/CachyOS package.

2. Create AUR package.

3. Add desktop entry for Appseal itself.

4. Add icons and metainfo.

5. Add optional dependencies.

6. Create install documentation.

7. Test on:
   - CachyOS KDE
   - Arch Linux
   - Fedora
   - Ubuntu

### Exit Criteria

- pacman package works on CachyOS or test repository.
- AUR package builds cleanly.
- Appseal launches from application menu.
- Backend dependencies are detected correctly.

### Deliverables

- PKGBUILD
- Package documentation
- Distro testing report

---

## 3.13 Phase 10: QA, Beta, and Hardening

### Duration

3 to 4 weeks

### Objectives

Stabilize Appseal for v1.0.

### Tasks

1. Build AppImage test corpus.

2. Run compatibility matrix.

3. Test:
   - X11
   - Wayland
   - PipeWire
   - GPU
   - No network
   - Full network
   - Home access variants
   - Preset application
   - Desktop launchers
   - Stale AppImage handling

4. Run security tests:
   - Attempt access to denied paths.
   - Verify /proc restrictions.
   - Verify /sys restrictions.
   - Verify D-Bus restrictions where possible.
   - Verify X11 warning appears.
   - Verify setuid bits are removed during extraction.
   - Verify symlink traversal does not escape sandbox.

5. Perform crash triage.

6. Improve logs.

7. Fix sandbox command generation bugs.

8. Run user testing.

### Exit Criteria

- Common AppImages work reliably.
- Warnings are accurate.
- No known sandbox escape due to Appseal configuration.
- GUI is stable.
- Packaging is reliable.

### Deliverables

- Beta release
- Bug triage process
- Compatibility report
- v1.0 release candidate

---

# 4. Milestone Plan

## Milestone M0: Prototype Validated

Goal: Prove Appseal is technically feasible.

Deliverables:

- Extract and run one or more AppImages with Bubblewrap.
- Basic GUI launch.
- Compatibility notes.

---

## Milestone M1: Core CLI

Goal: Establish core data model and CLI.

Deliverables:

- appseal add
- appseal list
- appseal info
- appseal remove
- appseal doctor

---

## Milestone M2: Sandbox MVP

Goal: Run AppImages through Bubblewrap with basic permissions.

Deliverables:

- Extraction pipeline.
- Bubblewrap backend.
- Basic permission mapping.

---

## Milestone M3: Dependency and Profile Engine

Goal: Generate useful recommended profiles.

Deliverables:

- Static dependency detection.
- Recommended profiles.
- Presets.

---

## Milestone M4: GUI Feature Parity

Goal: GUI can manage apps end-to-end.

Deliverables:

- Dashboard.
- Permissions editor.
- Preset manager.
- Settings.
- Diagnostics.
- Onboarding.

---

## Milestone M5: CachyOS Beta

Goal: Package and release beta for CachyOS.

Deliverables:

- pacman package.
- AUR package.
- Beta test feedback loop.

---

## Milestone M6: Appseal 1.0

Goal: Stable initial release.

Deliverables:

- Stable Bubblewrap backend.
- Optional Bubblejail/Firejail.
- Presets.
- Desktop integration.
- Documentation.

---

# 5. Minimum Viable Product Definition

The MVP should be small enough to ship but useful enough to matter.

## MVP includes

1. Add AppImage manually.
2. Scan one or more default directories.
3. Extract AppImage.
4. Generate sandbox profile.
5. Launch with Bubblewrap.
6. Basic permissions editor:
   - Filesystem
   - Network full/none
   - GPU
   - Audio
   - X11/Wayland
7. Recommended profile.
8. Save and apply presets.
9. Desktop launcher creation.
10. CLI for debugging.
11. pacman package.
12. Basic diagnostics and logs.

## MVP excludes

1. eBPF network filtering.
2. Cloud preset sharing.
3. Full Firejail integration.
4. Automatic dependency repair for all libraries.
5. App store features.
6. Mobile-style sandboxing.
7. Enterprise policy enforcement.
8. Localhost-only network mode unless experimental helper is ready.

---

# 6. Testing Strategy

## 6.1 Unit tests

Test:

- Config parsing.
- Profile serialization.
- Permission risk scoring.
- AppImage type detection.
- Dependency classification.
- Backend command generation.

## 6.2 Integration tests

Test:

- Add AppImage.
- Extract AppImage.
- Generate profile.
- Launch sandbox.
- Save preset.
- Apply preset.
- Remove app.
- Detect stale AppImage.

## 6.3 Compatibility tests

Maintain a corpus of common AppImages:

- Browsers
- Media players
- Image editors
- Video editors
- Games
- Text editors
- Terminals
- Utilities
- Electron apps
- Qt apps
- GTK apps

Track:

- Launch success.
- GUI rendering.
- Audio.
- GPU.
- Network.
- File access.
- Crash rate.

## 6.4 Security tests

Test:

- Denied home paths are inaccessible.
- Documents only accessible when enabled.
- Network disabled mode actually blocks network.
- System D-Bus denied by default.
- Dangerous permissions generate warnings.
- Extraction removes setuid bits.
- Symlink traversal does not escape sandbox.
- Desktop launcher uses Appseal runner.

## 6.5 Usability tests

Test:

- Can a new user add an AppImage?
- Can a new user understand warnings?
- Can a user save a preset?
- Can a user apply a preset?
- Can a user recover from a broken app?
- Can a user find logs?
- Can a user understand why an app is blocked?

## 6.6 Distro tests

Primary:

- CachyOS

Secondary:

- Arch Linux
- Fedora Workstation
- Ubuntu
- Linux Mint
- openSUSE

---

# 7. Documentation Plan

Appseal needs clear documentation.

## User documentation

1. Installing Appseal.
2. Adding an AppImage.
3. Understanding permissions.
4. Using presets.
5. Choosing a backend.
6. Troubleshooting.
7. Security warnings.

## Developer documentation

1. Architecture.
2. Backend adapter API.
3. Profile schema.
4. Dependency detection.
5. Packaging.
6. Test corpus.

## Security documentation

1. Threat model.
2. Permission risk table.
3. X11 limitations.
4. Firejail warning.
5. Experimental kernel features.

---

# 8. Recommended Technical Decisions

Based on the review, the following decisions are recommended.

## 8.1 Language

Use Rust.

## 8.2 UI

Use Rust plus Qt6/QML/Kirigami if feasible.

Fallback:

- Rust core plus thin C++ Qt shell.
- If Qt integration proves too slow, use GTK4 with Breeze-like styling.

## 8.3 Default backend

Use Bubblewrap as default.

## 8.4 Optional backends

Support:

- Bubblejail as optional advanced backend.
- Firejail as optional compatibility backend with warning.

## 8.5 AppImage execution

Use extraction into Appseal-managed storage as the primary execution method.

## 8.6 Dependency detection

Use:

1. Static ELF/library analysis.
2. Controlled dynamic fallback.
3. Compatibility mode only with warnings.

## 8.7 Kernel security

Use:

1. Landlock as defense in depth.
2. Seccomp optionally.
3. eBPF only as experimental future feature.

## 8.8 Packaging

Start with:

1. CachyOS pacman package.
2. AUR package.

Then expand to other distros.

---

# 9. Final Recommended Roadmap

## Stage 1: Feasibility Prototype and UX Exploration

Duration: 2 weeks

Prove that Appseal can extract and run common AppImages inside Bubblewrap and validate the UI direction.

---

## Stage 2: Core CLI and Storage

Duration: 2 to 3 weeks

Build the core app registry, config, and CLI.

---

## Stage 3: Extraction and Desktop Integration

Duration: 3 to 4 weeks

Make AppImage handling robust and user-visible.

---

## Stage 4: Bubblewrap Sandbox Engine

Duration: 3 to 4 weeks

Implement default sandbox backend and permission mapping.

---

## Stage 5: Dependency Detection and Profiles

Duration: 3 to 4 weeks

Implement recommended profiles, dependency analysis, and presets.

---

## Stage 6: GUI

Duration: 5 to 7 weeks

Build Flatseal-like UI with KDE Breeze themes and usability features.

---

## Stage 7: Optional Backends and Advanced Features

Duration: 2 to 4 weeks

Add Bubblejail, Firejail, Landlock, and experimental features.

---

## Stage 8: Packaging, Beta, and Release

Duration: 3 to 4 weeks

Package for CachyOS, test broadly, and release v1.0.

---

# 10. Final Summary

Appseal should become a practical permissions manager for AppImages.

The corrected plan positions Appseal as:

- A Rust-based desktop tool.
- A Flatseal-like permissions manager for AppImages.
- A sandbox orchestrator using Bubblewrap by default.
- A compatibility-focused system with clear warnings.
- A CachyOS-first application that remains portable.
- A practical product with an MVP that can ship before advanced features like eBPF filtering or community preset sharing.

The most important implementation principle is:

    Appseal should make AppImages safer without pretending that every AppImage can be made perfectly secure or compatible with zero user involvement.

With this corrected scope, Appseal is technically more realistic, more compatible with real-world AppImages, and significantly more usable for everyday Linux users.