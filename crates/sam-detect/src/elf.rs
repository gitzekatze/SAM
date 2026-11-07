//! Static analysis of an extracted AppDir (§2.16.1).
//!
//! Walks the AppDir without following symlinks, parses every ELF file,
//! collects DT_NEEDED entries, compares them against the bundled libraries
//! and the host, and derives requirements (GPU, audio, network, display ...).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Result;
use sam_core::util::now;
use sam_core::{
    Compatibility, DependencyReport, HostResource, IsolationVerdict, MissingLibrary, Requirements, ResourceClass,
    Warning,
};

use crate::classify::{classify_library, toolkit_of, Signal, GRAPHICS_HOST_RESOURCES, SAFE_HOST_RESOURCES};

#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    /// Entry point relative to the AppDir (usually `AppRun`).
    pub entry: String,
    /// `Exec=` from the desktop file, used when AppRun is a script.
    pub exec_hint: Option<String>,
    pub max_files: usize,
    pub max_elf_files: usize,
    pub max_elf_size: u64,
    pub host_lib_dirs: Vec<PathBuf>,
    pub host_arch: String,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        AnalyzeOptions {
            entry: "AppRun".into(),
            exec_hint: None,
            max_files: 300_000,
            max_elf_files: 4000,
            max_elf_size: 768 * 1024 * 1024,
            host_lib_dirs: default_host_lib_dirs(),
            host_arch: std::env::consts::ARCH.into(),
        }
    }
}

pub fn default_host_lib_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = [
        "/usr/lib",
        "/usr/lib64",
        "/lib",
        "/lib64",
        "/usr/lib/x86_64-linux-gnu",
        "/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/usr/local/lib",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    // ld.so.conf.d entries (e.g. /usr/lib/nvidia, /opt/... on some distros).
    if let Ok(rd) = fs::read_dir("/etc/ld.so.conf.d") {
        for e in rd.flatten() {
            if let Ok(s) = fs::read_to_string(e.path()) {
                for l in s.lines().map(str::trim) {
                    if l.starts_with('/') {
                        dirs.push(PathBuf::from(l));
                    }
                }
            }
        }
    }
    dirs.retain(|d| d.is_dir());
    dirs.dedup();
    dirs
}

fn host_has_lib(dirs: &[PathBuf], name: &str) -> bool {
    dirs.iter().any(|d| d.join(name).exists())
}

#[derive(Default)]
struct Walk {
    files: u64,
    bundled: BTreeSet<String>,
    elfs: Vec<PathBuf>,
    electron: bool,
    java: bool,
    qt_wayland_plugin: bool,
    kernel_modules: Vec<String>,
    truncated: bool,
}

fn walk(root: &Path, dir: &Path, w: &mut Walk, opts: &AnalyzeOptions) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        if w.files as usize >= opts.max_files {
            w.truncated = true;
            return;
        }
        w.files += 1;
        let path = e.path();
        let Ok(meta) = fs::symlink_metadata(&path) else { continue };
        let name = e.file_name().to_string_lossy().into_owned();
        if meta.is_dir() {
            walk(root, &path, w, opts);
            continue;
        }
        if name.contains(".so") {
            w.bundled.insert(name.clone());
        }
        if name == "chrome-sandbox" || name == "app.asar" || name == "libffmpeg.so" || name == "v8_context_snapshot.bin" {
            w.electron = true;
        }
        if name == "libjvm.so" {
            w.java = true;
        }
        if name.starts_with("libqwayland") {
            w.qt_wayland_plugin = true;
        }
        if name.ends_with(".ko") || name.ends_with(".ko.zst") || name.ends_with(".ko.xz") {
            w.kernel_modules.push(path.strip_prefix(root).unwrap_or(&path).display().to_string());
        }
        if meta.is_file() && meta.len() >= 52 && meta.len() <= opts.max_elf_size && is_elf(&path) {
            if w.elfs.len() < opts.max_elf_files {
                w.elfs.push(path);
            } else {
                w.truncated = true;
            }
        }
    }
}

fn is_elf(p: &Path) -> bool {
    let mut b = [0u8; 4];
    fs::File::open(p).and_then(|mut f| f.read_exact(&mut b)).is_ok() && &b == b"\x7fELF"
}

struct ElfFacts {
    needed: Vec<String>,
    glibc_max: Option<(u32, u32)>,
    arch: Option<&'static str>,
}

fn parse_elf(p: &Path) -> Option<ElfFacts> {
    let data = fs::read(p).ok()?;
    let elf = goblin::elf::Elf::parse(&data).ok()?;
    let arch = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => Some("x86_64"),
        goblin::elf::header::EM_AARCH64 => Some("aarch64"),
        goblin::elf::header::EM_386 => Some("i686"),
        goblin::elf::header::EM_ARM => Some("armhf"),
        goblin::elf::header::EM_RISCV => Some("riscv64"),
        _ => None,
    };
    let mut glibc_max: Option<(u32, u32)> = None;
    if let Some(verneed) = &elf.verneed {
        for need in verneed.iter() {
            for aux in need.iter() {
                if let Some(name) = elf.dynstrtab.get_at(aux.vna_name) {
                    if let Some(v) = parse_glibc_version(name) {
                        glibc_max = Some(glibc_max.map_or(v, |m| m.max(v)));
                    }
                }
            }
        }
    }
    Some(ElfFacts {
        needed: elf.libraries.iter().map(|s| s.to_string()).collect(),
        glibc_max,
        arch,
    })
}

/// Resolves a path-style DT_NEEDED entry (`$ORIGIN/../lib/libx.so`) against
/// the directory of the ELF file that needs it.
fn needed_path_exists(elf: &Path, needed: &str) -> bool {
    let origin = elf.parent().unwrap_or(Path::new("/")).to_string_lossy().into_owned();
    let resolved = needed.replace("${ORIGIN}", &origin).replace("$ORIGIN", &origin);
    let path = Path::new(&resolved);
    if path.is_absolute() {
        path.exists()
    } else {
        Path::new(&origin).join(path).exists()
    }
}

fn parse_glibc_version(s: &str) -> Option<(u32, u32)> {
    let v = s.strip_prefix("GLIBC_")?;
    let mut it = v.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next().and_then(|m| m.parse().ok()).unwrap_or(0);
    Some((major, minor))
}

pub fn host_glibc_version() -> Option<(u32, u32)> {
    #[cfg(target_env = "gnu")]
    {
        let c = unsafe { std::ffi::CStr::from_ptr(libc::gnu_get_libc_version()) };
        let s = c.to_string_lossy();
        let mut it = s.split('.');
        let major = it.next()?.parse().ok()?;
        let minor = it.next()?.parse().ok()?;
        return Some((major, minor));
    }
    #[allow(unreachable_code)]
    None
}

/// Look at an AppRun-style script for privilege escalation helpers.
fn script_privileged(text: &str) -> Option<&'static str> {
    for (needle, label) in [
        ("pkexec", "pkexec"),
        ("sudo ", "sudo"),
        ("gksu", "gksu"),
        ("kdesu", "kdesu"),
        ("insmod ", "insmod"),
        ("modprobe ", "modprobe"),
    ] {
        if text
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .any(|l| l.contains(needle))
        {
            return Some(label);
        }
    }
    None
}

/// Resolve the real binary when AppRun is a shell script.
fn resolve_entry_binary(appdir: &Path, opts: &AnalyzeOptions) -> (Option<PathBuf>, bool, Option<String>) {
    let entry = appdir.join(&opts.entry);
    let mut script_text = None;
    let is_script = match fs::read(&entry) {
        Ok(b) => {
            if b.starts_with(b"#!") {
                script_text = Some(String::from_utf8_lossy(&b[..b.len().min(64 * 1024)]).into_owned());
                true
            } else {
                false
            }
        }
        Err(_) => false,
    };
    if !is_script {
        let real = fs::canonicalize(&entry).ok().filter(|p| p.starts_with(appdir) && is_elf(p));
        return (real, false, None);
    }
    if let Some(exec) = &opts.exec_hint {
        let bin = exec.split_whitespace().next().unwrap_or("").trim_matches('"');
        let name = Path::new(bin).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        for cand in [appdir.join("usr/bin").join(&name), appdir.join(&name), appdir.join("bin").join(&name)] {
            if let Ok(real) = fs::canonicalize(&cand) {
                if real.starts_with(appdir) && is_elf(&real) {
                    return (Some(real), true, script_text);
                }
            }
        }
    }
    (None, true, script_text)
}

pub fn analyze_appdir(appdir: &Path, opts: &AnalyzeOptions) -> Result<DependencyReport> {
    let appdir = fs::canonicalize(appdir)?;
    let mut w = Walk::default();
    walk(&appdir, &appdir, &mut w, opts);

    let mut report = DependencyReport { analyzed_at: now(), ..Default::default() };
    let (entry_bin, is_script, script_text) = resolve_entry_binary(&appdir, opts);
    report.entry_is_script = is_script;
    report.entry_binary = entry_bin
        .as_ref()
        .map(|p| p.strip_prefix(&appdir).unwrap_or(p).display().to_string());

    let mut needed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut glibc_max: Option<(u32, u32)> = None;
    let mut arch: Option<&'static str> = None;
    // Parse the entry binary first so its architecture wins.
    let mut ordered = w.elfs.clone();
    if let Some(e) = &entry_bin {
        ordered.retain(|p| p != e);
        ordered.insert(0, e.clone());
    }
    let mut parsed = 0u64;
    for p in &ordered {
        let Some(f) = parse_elf(p) else { continue };
        parsed += 1;
        if arch.is_none() {
            arch = f.arch;
        }
        if let Some(v) = f.glibc_max {
            glibc_max = Some(glibc_max.map_or(v, |m| m.max(v)));
        }
        let rel = p.strip_prefix(&appdir).unwrap_or(p).display().to_string();
        for n in f.needed {
            // A DT_NEEDED entry with a slash is a path, usually `$ORIGIN/...`
            // relative to the binary. If it exists in the payload it is bundled.
            let n = if n.contains('/') {
                if needed_path_exists(p, &n) {
                    continue;
                }
                n.rsplit('/').next().unwrap_or(&n).to_string()
            } else {
                n
            };
            let by = needed.entry(n).or_default();
            if by.len() < 5 {
                by.push(rel.clone());
            }
        }
    }
    report.elf_count = parsed;
    report.bundled_libraries = w.bundled.len() as u64;
    report.arch = arch.unwrap_or("unknown").to_string();

    // Requirements from every library name we know about (needed or bundled).
    let mut req = Requirements::default();
    let mut toolkit: Option<&str> = None;
    for name in needed.keys().chain(w.bundled.iter()) {
        let info = classify_library(name);
        for s in &info.signals {
            match s {
                Signal::Gpu => req.gpu = true,
                Signal::Audio => req.audio = true,
                Signal::Network => req.network = true,
                Signal::X11 => req.x11 = true,
                Signal::Wayland => req.wayland = true,
                Signal::Fonts => req.fonts = true,
                Signal::Certificates => req.certificates = true,
                Signal::Dbus => req.dbus = true,
            }
        }
        if toolkit.is_none() {
            toolkit = toolkit_of(name);
        }
    }
    if w.qt_wayland_plugin || matches!(toolkit, Some("GTK3") | Some("GTK4") | Some("Qt6")) {
        req.wayland = true;
    }
    if w.electron {
        req.electron = true;
        req.gpu = true;
        req.audio = true;
        req.network = true;
        req.x11 = true;
        toolkit = Some("Electron");
    }
    if w.java {
        req.java = true;
        req.x11 = true;
        toolkit = toolkit.or(Some("Java"));
    }
    req.toolkit = toolkit.unwrap_or("Unknown").to_string();
    report.requirements = req;

    // Missing libraries.
    let mut compat = Compatibility::Good;
    let worsen = |c: &mut Compatibility, to: Compatibility| {
        let rank = |c: Compatibility| match c {
            Compatibility::Good => 0,
            Compatibility::Risk => 1,
            Compatibility::LikelyBroken => 2,
        };
        if rank(to) > rank(*c) {
            *c = to;
        }
    };
    let mut not_found = Vec::new();
    // Missing, but only bundled libraries need them (e.g. libappindicator's
    // GTK2 deps). Those libraries are often loaded optionally via dlopen.
    let mut lib_only_missing = Vec::new();
    let mut abi_sensitive = Vec::new();
    for (name, by) in &needed {
        if w.bundled.contains(name) || name.starts_with("ld-linux") || name.starts_with("ld64") {
            continue;
        }
        let info = classify_library(name);
        let host = host_has_lib(&opts.host_lib_dirs, name);
        let only_libs_need_it = by.iter().all(|f| f.rsplit('/').next().is_some_and(|n| n.contains(".so")));
        if !host && only_libs_need_it {
            lib_only_missing.push(name.clone());
            worsen(&mut compat, Compatibility::Risk);
        } else if !host {
            not_found.push(name.clone());
            worsen(&mut compat, Compatibility::LikelyBroken);
        } else if info.class == ResourceClass::Dangerous {
            abi_sensitive.push(name.clone());
            worsen(&mut compat, Compatibility::Risk);
        }
        report.missing.push(MissingLibrary {
            name: name.clone(),
            class: info.class,
            host_available: host,
            needed_by: by.clone(),
        });
    }
    if !not_found.is_empty() {
        report.warnings.push(Warning::danger(
            "libs-not-found",
            "Libraries not found",
            format!(
                "These libraries are neither bundled nor installed on this system: {}. The app will probably fail to start.",
                list(&not_found)
            ),
        ));
    }
    if !lib_only_missing.is_empty() {
        report.warnings.push(Warning::warn(
            "libs-not-found-optional",
            "Libraries not found (used by bundled libraries)",
            format!(
                "These libraries are neither bundled nor installed: {}. Only bundled libraries need them, and those are often optional (e.g. tray support), so the app may still start.",
                list(&lib_only_missing)
            ),
        ));
    }
    if !abi_sensitive.is_empty() {
        report.warnings.push(Warning::warn(
            "host-abi-libs",
            "Relies on host system libraries",
            format!(
                "This AppImage uses the host's copy of {}. These are ABI-sensitive; a version mismatch can cause crashes. The AppImage may be incompatible with this system.",
                list(&abi_sensitive)
            ),
        ));
    }

    if let (Some(need), Some(have)) = (glibc_max, host_glibc_version()) {
        report.notes.push(format!("requires glibc {}.{} (host has {}.{})", need.0, need.1, have.0, have.1));
        if need > have {
            worsen(&mut compat, Compatibility::LikelyBroken);
            report.warnings.push(Warning::danger(
                "glibc-too-old",
                "System C library too old",
                format!("The app needs glibc {}.{} but this system has {}.{}.", need.0, need.1, have.0, have.1),
            ));
        }
    }
    if let Some(a) = arch {
        if a != opts.host_arch && !(a == "i686" && opts.host_arch == "x86_64") {
            worsen(&mut compat, Compatibility::LikelyBroken);
            report.warnings.push(Warning::danger(
                "arch-mismatch",
                "Wrong CPU architecture",
                format!("This AppImage is built for {a}, but this system is {}.", opts.host_arch),
            ));
        }
    }
    if parsed == 0 {
        worsen(&mut compat, Compatibility::LikelyBroken);
        report.warnings.push(Warning::warn(
            "no-elf",
            "No executables found",
            "No ELF executables were found in the AppImage payload.",
        ));
    }
    if is_script && report.entry_binary.is_none() {
        report.notes.push("AppRun is a script; the main binary could not be determined".into());
    }
    if w.truncated {
        report.notes.push("analysis was truncated because the payload is very large".into());
    }

    // Isolation verdict (§2.19.4).
    let privileged = script_text.as_deref().and_then(script_privileged);
    report.verdict = if let Some(tool) = privileged {
        report.warnings.push(Warning::danger(
            "privileged",
            "Requires privileged access",
            format!("The AppImage's launcher calls '{tool}'. It appears to require root access, which cannot be sandboxed."),
        ));
        Some(IsolationVerdict::UnsafeToSandbox)
    } else if !w.kernel_modules.is_empty() {
        report.warnings.push(Warning::danger(
            "kernel-modules",
            "Contains kernel modules",
            format!("The payload contains kernel modules ({}). Kernel-level software cannot be sandboxed.", list(&w.kernel_modules)),
        ));
        Some(IsolationVerdict::UnsafeToSandbox)
    } else if compat == Compatibility::LikelyBroken {
        Some(IsolationVerdict::LikelyBroken)
    } else if needed.keys().any(|n| n.starts_with("libpolkit")) {
        Some(IsolationVerdict::WeaklyIsolated)
    } else if report.requirements.x11 && !report.requirements.wayland {
        report.notes.push("X11-only application: isolation between windows is limited".into());
        Some(IsolationVerdict::WeaklyIsolated)
    } else {
        None
    };
    report.compatibility = compat;

    // Host resources (§2.16.2).
    for (res, why) in SAFE_HOST_RESOURCES {
        let relevant = match *why {
            "TLS certificates" => report.requirements.certificates || report.requirements.network,
            _ => true,
        };
        if relevant {
            report.resources.push(HostResource {
                resource: res.to_string(),
                class: ResourceClass::Safe,
                reason: why.to_string(),
                auto: true,
            });
        }
    }
    if report.requirements.gpu {
        for (res, why) in GRAPHICS_HOST_RESOURCES {
            report.resources.push(HostResource {
                resource: res.to_string(),
                class: ResourceClass::Graphics,
                reason: why.to_string(),
                auto: false,
            });
        }
    }
    let controlled = [
        (report.requirements.wayland, "Wayland socket", "Wayland client libraries / toolkit support"),
        (report.requirements.x11, "X11 socket", "links X11 libraries"),
        (report.requirements.audio, "PipeWire / PulseAudio socket", "links audio libraries"),
        (report.requirements.dbus, "D-Bus session socket", "links D-Bus libraries"),
    ];
    for (needed, res, why) in controlled {
        if needed {
            report.resources.push(HostResource {
                resource: res.into(),
                class: ResourceClass::Controlled,
                reason: why.into(),
                auto: false,
            });
        }
    }
    if report.requirements.electron {
        report.notes.push("Electron app: Chromium's internal sandbox needs nested user namespaces".into());
    }
    Ok(report)
}

fn list(v: &[String]) -> String {
    if v.len() > 6 {
        format!("{} and {} more", v[..6].join(", "), v.len() - 6)
    } else {
        v.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fake_appdir(apprun: &str) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir_all(d.path().join("usr/bin")).unwrap();
        fs::create_dir_all(d.path().join("usr/lib")).unwrap();
        fs::copy("/bin/true", d.path().join("usr/bin/app")).unwrap();
        fs::write(d.path().join("AppRun"), apprun).unwrap();
        d
    }

    #[test]
    fn analyzes_script_apprun() {
        let d = fake_appdir("#!/bin/sh\nexec \"$APPDIR/usr/bin/app\" \"$@\"\n");
        let opts = AnalyzeOptions { exec_hint: Some("app %F".into()), ..Default::default() };
        let r = analyze_appdir(d.path(), &opts).unwrap();
        assert!(r.entry_is_script);
        assert_eq!(r.entry_binary.as_deref(), Some("usr/bin/app"));
        assert!(r.elf_count >= 1);
        assert!(r.missing.iter().any(|m| m.name.starts_with("libc.so")));
        assert_ne!(r.compatibility, Compatibility::LikelyBroken, "{:?}", r.warnings);
        assert!(r.verdict != Some(IsolationVerdict::UnsafeToSandbox));
    }

    #[test]
    fn flags_privileged_launcher() {
        let d = fake_appdir("#!/bin/sh\npkexec \"$APPDIR/usr/bin/app\"\n");
        let r = analyze_appdir(d.path(), &AnalyzeOptions::default()).unwrap();
        assert_eq!(r.verdict, Some(IsolationVerdict::UnsafeToSandbox));
    }

    #[test]
    fn electron_markers_and_bundled_symlinks() {
        let d = fake_appdir("#!/bin/sh\n");
        fs::write(d.path().join("chrome-sandbox"), b"").unwrap();
        fs::write(d.path().join("usr/lib/libfoo.so.1.2"), b"x").unwrap();
        symlink("libfoo.so.1.2", d.path().join("usr/lib/libfoo.so.1")).unwrap();
        let r = analyze_appdir(d.path(), &AnalyzeOptions::default()).unwrap();
        assert!(r.requirements.electron && r.requirements.network);
        assert_eq!(r.requirements.toolkit, "Electron");
        assert_eq!(r.bundled_libraries, 2);
    }

    #[test]
    fn origin_relative_needed_paths() {
        let d = fake_appdir("#!/bin/sh\n");
        fs::create_dir_all(d.path().join("py/bin")).unwrap();
        fs::create_dir_all(d.path().join("py/lib")).unwrap();
        fs::write(d.path().join("py/lib/libpython3.so.1.0"), b"x").unwrap();
        let bin = d.path().join("py/bin/python");
        assert!(needed_path_exists(&bin, "$ORIGIN/../lib/libpython3.so.1.0"));
        assert!(needed_path_exists(&bin, "${ORIGIN}/../lib/libpython3.so.1.0"));
        assert!(!needed_path_exists(&bin, "$ORIGIN/../lib/libmissing.so"));
    }

    #[test]
    fn glibc_version_parse() {
        assert_eq!(parse_glibc_version("GLIBC_2.34"), Some((2, 34)));
        assert_eq!(parse_glibc_version("GLIBC_PRIVATE"), None);
        assert!(host_glibc_version().is_some());
    }
}
