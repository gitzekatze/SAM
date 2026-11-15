//! Static analysis of an extracted AppDir.
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
use sam_core::{Compatibility, DependencyReport, HostResource, IsolationVerdict, MissingLibrary, Requirements, ResourceClass, Warning};

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
    let mut dirs: Vec<PathBuf> =
        ["/usr/lib", "/usr/lib64", "/lib", "/lib64", "/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/usr/local/lib"]
            .iter()
            .map(PathBuf::from)
            .collect();
    // ld.so.conf.d entries (e.g. /usr/lib/nvidia, /opt/cuda/lib64), which
    // the sandbox shows too (`HostInfo::extra_lib_dirs`).
    dirs.extend(sam_core::host::loader_lib_dirs());
    dirs.retain(|d| d.is_dir());
    dirs.dedup();
    dirs
}

fn host_has_lib(dirs: &[PathBuf], name: &str) -> bool {
    if dirs.iter().any(|d| d.join(name).exists()) {
        return true;
    }
    // An unversioned name ("libdl.so") is a development link; the loader
    // also accepts the versioned library ("libdl.so.2") many systems have.
    name.ends_with(".so")
        && dirs
            .iter()
            .any(|d| fs::read_dir(d).into_iter().flatten().flatten().any(|e| e.file_name().to_str().is_some_and(|f| f.starts_with(&format!("{name}.")))))
}

#[derive(Default)]
struct Walk {
    files: u64,
    bundled: BTreeSet<String>,
    elfs: Vec<PathBuf>,
    electron: bool,
    java: bool,
    /// Qt's Wayland platform plugins (libqwayland*.so).
    qt_wayland_plugins: Vec<PathBuf>,
    /// Qt's X11 platform plugin (libqxcb.so) is bundled.
    qt_xcb_plugin: bool,
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
            w.qt_wayland_plugins.push(path.clone());
        }
        if name.starts_with("libqxcb.so") {
            w.qt_xcb_plugin = true;
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
    Some(ElfFacts { needed: elf.libraries.iter().map(|s| s.to_string()).collect(), glibc_max, arch })
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
        // SAFETY: gnu_get_libc_version returns a pointer to a static, NUL-terminated string that lives as long as the program.
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
    for (needle, label) in [("pkexec", "pkexec"), ("sudo ", "sudo"), ("gksu", "gksu"), ("kdesu", "kdesu"), ("insmod ", "insmod"), ("modprobe ", "modprobe")] {
        if text.lines().map(str::trim).filter(|l| !l.starts_with('#')).any(|l| l.contains(needle)) {
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

/// Whether `AppRun` or one of linuxdeploy's `apprun-hooks` sets the app to
/// X11 only (GDK_BACKEND=x11, QT_QPA_PLATFORM=xcb, SDL_VIDEODRIVER=x11),
/// ignoring comments.
fn start_scripts_force_x11(appdir: &Path) -> bool {
    // AppRun.env: appimage-builder's environment file; .env: sharun's
    // (anylinux AppImages), which it applies over the environment.
    let mut scripts = vec![appdir.join("AppRun"), appdir.join("AppRun.env"), appdir.join(".env")];
    if let Ok(rd) = fs::read_dir(appdir.join("apprun-hooks")) {
        scripts.extend(rd.flatten().map(|e| e.path()));
    }
    scripts.iter().any(|f| {
        let Ok(meta) = fs::metadata(f) else { return false };
        if !meta.is_file() || meta.len() > 256 * 1024 {
            return false;
        }
        let Ok(text) = fs::read(f) else { return false };
        if text.starts_with(b"\x7fELF") {
            return false;
        }
        String::from_utf8_lossy(&text).lines().any(|l| {
            let code = l.split('#').next().unwrap_or("").replace(['"', '\''], "");
            // Whole words only: `VAR=${VAR:-x11}` keeps the user's choice, but
            // `VAR=${OTHER:-x11}` (FreeCAD) forces X11 all the same.
            code.split_whitespace().any(|w| {
                [("GDK_BACKEND", "x11"), ("QT_QPA_PLATFORM", "xcb"), ("SDL_VIDEODRIVER", "x11")].iter().any(|(var, x11)| {
                    let Some(value) = w.strip_prefix(var).and_then(|r| r.strip_prefix('=')) else { return false };
                    value == *x11
                        || value
                            .strip_prefix("${")
                            .and_then(|r| r.strip_suffix(&format!(":-{x11}}}")))
                            .is_some_and(|other| other != *var && other.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
                })
            })
        })
    })
}

/// What the app's programs (not its bundled libraries, which often name
/// every graphics backend and platform) reveal through the strings in them.
#[derive(Debug, Default, PartialEq)]
struct ProgramStrings {
    /// Names a graphics library it would load at run time (dlopen).
    loads_graphics: bool,
    /// Names its own variable for Qt's platform, such as MuseScore's
    /// `MU_QT_QPA_PLATFORM`: the program sets QT_QPA_PLATFORM itself
    /// (to X11) unless that variable says otherwise.
    qt_platform_override: Option<String>,
}

/// The app's programs among its ELF files: not libraries (`.so`, and Node
/// add-ons, `.node`, which can be hundreds of megabytes).
fn programs(elfs: &[PathBuf]) -> Vec<&PathBuf> {
    elfs.iter()
        .filter(|p| {
            p.file_name().is_some_and(|n| {
                let n = n.to_string_lossy();
                !n.contains(".so") && !n.ends_with(".node")
            })
        })
        .collect()
}

fn scan_programs(programs: &[&PathBuf], progress: &dyn Fn(usize)) -> ProgramStrings {
    use memchr::memmem;
    const GRAPHICS: [&[u8]; 4] = [b"libEGL.so", b"libGL.so", b"libGLX.so", b"libvulkan.so"];
    let graphics: Vec<memmem::Finder<'static>> = GRAPHICS.iter().map(|n| memmem::Finder::new(*n)).collect();
    const QPA: &[u8] = b"_QT_QPA_PLATFORM\0";
    let mut found = ProgramStrings::default();
    for (n, p) in programs.iter().enumerate() {
        progress(n + 1);
        let Ok(data) = fs::read(p) else { continue };
        found.loads_graphics |= graphics.iter().any(|f| f.find(&data).is_some());
        if found.qt_platform_override.is_none() {
            found.qt_platform_override = memmem::find_iter(&data, QPA).find_map(|i| {
                // The whole string: an upper-case prefix right after a NUL.
                let start = data[..i].iter().rposition(|b| !(b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')).map_or(0, |z| z + 1);
                let prefix = &data[start..i];
                (start > 0 && data[start - 1] == 0 && prefix.first().is_some_and(u8::is_ascii_uppercase))
                    .then(|| format!("{}_QT_QPA_PLATFORM", String::from_utf8_lossy(prefix)))
            });
        }
    }
    found
}

/// Whether one of Qt's Wayland platform plugins can load: Qt's Wayland
/// client library it needs is bundled too. OpenShot ships the plugins
/// without it, and the host's copy does not match the bundled Qt.
fn qt_wayland_usable(plugins: &[PathBuf], bundled: &BTreeSet<String>) -> bool {
    plugins.iter().any(|p| match parse_elf(p) {
        Some(f) => f.needed.iter().filter(|n| n.starts_with("libQt") && n.contains("WaylandClient")).all(|n| bundled.contains(n)),
        None => true,
    })
}

/// Static analysis of an unpacked AppImage: what its programs link and
/// bundle, what that tells about the access it needs, whether it can run
/// on this system, and how well a sandbox can isolate it. Nothing is run.
pub fn analyze_appdir(appdir: &Path, opts: &AnalyzeOptions) -> Result<DependencyReport> {
    analyze_appdir_with(appdir, opts, &|_, _| {})
}

/// [`analyze_appdir`], reporting `(files read, files to read)` as it goes:
/// every ELF file once, then every program once more.
pub fn analyze_appdir_with(appdir: &Path, opts: &AnalyzeOptions, progress: &dyn Fn(usize, usize)) -> Result<DependencyReport> {
    let appdir = fs::canonicalize(appdir)?;
    let mut w = Walk::default();
    walk(&appdir, &appdir, &mut w, opts);

    let mut report = DependencyReport { analyzed_at: now(), ..Default::default() };
    let (entry_bin, is_script, script_text) = resolve_entry_binary(&appdir, opts);
    report.entry_is_script = is_script;
    report.entry_binary = entry_bin.as_ref().map(|p| p.strip_prefix(&appdir).unwrap_or(p).display().to_string());

    let programs = programs(&w.elfs);
    let total = w.elfs.len() + programs.len();
    let links = read_links(&appdir, &w.elfs, entry_bin.as_ref(), &|n| progress(n, total));
    let strings = scan_programs(&programs, &|n| progress(w.elfs.len() + n, total));
    report.elf_count = links.parsed;
    if links.musl_variants > 0 {
        report.notes.push(format!("{} bundled program(s) built for musl (Alpine) skipped: alternatives that only run on musl systems", links.musl_variants));
    }
    if links.foreign_variants > 0 {
        report.notes.push(format!("{} bundled file(s) built for another CPU skipped: they are never loaded here", links.foreign_variants));
    }
    report.bundled_libraries = w.bundled.len() as u64;
    report.arch = links.arch.unwrap_or("unknown").to_string();

    report.requirements = requirements(&appdir, &w, &links.needed, &strings, &mut report.notes);
    let compat = check_compatibility(&mut report, &w, &links, opts);
    report.verdict = isolation_verdict(&mut report, &w, &links.needed, compat, script_text.as_deref());
    report.compatibility = compat;
    report.resources = host_resources(&report.requirements);
    if report.requirements.electron {
        report.notes.push(sam_core::i18n::tr("Electron app: Chromium's internal sandbox needs nested user namespaces"));
    }
    Ok(report)
}

/// What the app's programs link against (read from their ELF headers).
struct Links {
    /// Library name → up to five programs or libraries that need it.
    needed: BTreeMap<String, Vec<String>>,
    /// Highest glibc symbol version used.
    glibc_max: Option<(u32, u32)>,
    /// CPU architecture of the entry binary (or the most common one).
    arch: Option<&'static str>,
    parsed: u64,
    /// Programs built for musl (Alpine): bundled as alternatives (Node and
    /// Python packages ship both), never used on a glibc system. Their
    /// libraries are not missing for the app.
    musl_variants: u64,
    /// Files built for another CPU (Android/ARM builds of a Node add-on in
    /// an x86_64 app): never loaded, so their libraries are not missing.
    foreign_variants: u64,
    /// The entry binary relative to the AppDir, as in `needed`.
    entry: Option<String>,
    /// Libraries loaded when the entry binary starts: what it needs, and
    /// what the bundled libraries among those need, all the way down.
    /// A missing one stops the start, unlike a library loaded later.
    at_start: BTreeSet<String>,
}

fn read_links(appdir: &Path, elfs: &[PathBuf], entry_bin: Option<&PathBuf>, progress: &dyn Fn(usize)) -> Links {
    let rel = |p: &Path| p.strip_prefix(appdir).unwrap_or(p).display().to_string();
    let mut l = Links {
        needed: BTreeMap::new(),
        glibc_max: None,
        arch: None,
        parsed: 0,
        musl_variants: 0,
        foreign_variants: 0,
        entry: entry_bin.map(|e| rel(e)),
        at_start: BTreeSet::new(),
    };
    let mut files: Vec<(&PathBuf, ElfFacts)> = Vec::new();
    for (n, p) in elfs.iter().enumerate() {
        progress(n + 1);
        if let Some(f) = parse_elf(p) {
            l.parsed += 1;
            files.push((p, f));
        }
    }
    // The app's architecture: its entry binary's, else the most common one.
    let musl = |f: &ElfFacts| f.needed.iter().any(|n| n.starts_with("libc.musl") || n.starts_with("ld-musl"));
    l.arch = entry_bin.and_then(|e| files.iter().find(|(p, _)| *p == e)).and_then(|(_, f)| f.arch).or_else(|| {
        let mut count: BTreeMap<&'static str, usize> = BTreeMap::new();
        for a in files.iter().filter(|(_, f)| !musl(f)).filter_map(|(_, f)| f.arch) {
            *count.entry(a).or_default() += 1;
        }
        count.into_iter().max_by_key(|(_, n)| *n).map(|(a, _)| a)
    });
    // What each bundled file needs, by file name (the loader finds bundled
    // libraries by name), for the libraries loaded at start.
    let mut needs_of: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (p, f) in &files {
        if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
            needs_of.entry(n.to_string()).or_insert_with(|| f.needed.iter().map(|x| x.rsplit('/').next().unwrap_or(x).to_string()).collect());
        }
    }
    if let Some(start) = entry_bin.and_then(|e| e.file_name()).and_then(|n| n.to_str()) {
        let mut todo: Vec<String> = needs_of.get(start).cloned().unwrap_or_default();
        while let Some(lib) = todo.pop() {
            if l.at_start.insert(lib.clone()) {
                todo.extend(needs_of.get(&lib).cloned().unwrap_or_default());
            }
        }
    }
    for (p, f) in files {
        if musl(&f) {
            l.musl_variants += 1;
            continue;
        }
        if f.arch.is_some() && l.arch.is_some() && f.arch != l.arch {
            l.foreign_variants += 1;
            continue;
        }
        if let Some(v) = f.glibc_max {
            l.glibc_max = Some(l.glibc_max.map_or(v, |m| m.max(v)));
        }
        let r = rel(p);
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
            let by = l.needed.entry(n).or_default();
            if by.len() < 5 {
                by.push(r.clone());
            }
        }
    }
    l
}

/// The access the app needs, from every library name we know about
/// (needed or bundled), the files found in the payload and its start scripts.
fn requirements(appdir: &Path, w: &Walk, needed: &BTreeMap<String, Vec<String>>, programs: &ProgramStrings, notes: &mut Vec<String>) -> Requirements {
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
    // Qt finds its platform plugins in the AppImage: one that bundles the
    // X11 plugin but not the Wayland one can only open windows on X11, even
    // with Qt 6 (Gittyup, Nextcloud, nheko, RPCS3, Subsurface).
    // (A linked libwayland-client says nothing here: Qt only uses Wayland
    // through its plugin.)
    let qt_wayland = qt_wayland_usable(&w.qt_wayland_plugins, &w.bundled);
    let qt_x11_only = w.qt_xcb_plugin && !qt_wayland;
    if start_scripts_force_x11(appdir) {
        // The app's own start script insists on X11 (linuxdeploy's GTK
        // hook does, and so every Tauri AppImage); SAM's choice is overridden.
        req.x11 = true;
        req.wayland = false;
    } else if let Some(var) = programs.qt_platform_override.as_ref().filter(|_| w.qt_xcb_plugin) {
        // So does the program itself (MuseScore and Audacity 4).
        req.x11 = true;
        req.wayland = false;
        notes.push(sam_core::i18n::trf("The app sets Qt to X11 itself (unless {var} says otherwise)", &[("var", &var)]));
    } else if qt_x11_only {
        req.x11 = true;
        req.wayland = false;
    } else if qt_wayland || matches!(toolkit, Some("GTK3") | Some("GTK4") | Some("Qt6")) {
        req.wayland = true;
    }
    // Engines that build their own sandbox from namespaces.
    let nested = ["libwebkit2gtk", "libwebkitgtk", "libcef", "libQt5WebEngineCore", "libQt6WebEngineCore"];
    if needed.keys().chain(w.bundled.iter()).any(|n| nested.iter().any(|p| n.starts_with(p))) {
        req.nested_sandbox = true;
    }
    // Programs that load OpenGL or Vulkan at run time (dlopen) link no
    // graphics library, but name one (WezTerm, Rust/wgpu apps). Without the
    // GPU their EGL setup fails and no window appears.
    if !req.gpu && programs.loads_graphics {
        req.gpu = true;
        notes.push(sam_core::i18n::tr("A program of the app loads OpenGL or Vulkan at run time"));
    }
    if w.electron {
        req.electron = true;
        req.nested_sandbox = true;
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
    req
}

/// Raises `c` to `to` if that is worse.
fn worsen(c: &mut Compatibility, to: Compatibility) {
    let rank = |c: Compatibility| match c {
        Compatibility::Good => 0,
        Compatibility::Risk => 1,
        Compatibility::LikelyBroken => 2,
    };
    if rank(to) > rank(*c) {
        *c = to;
    }
}

/// Whether the app can run on this system: missing libraries, glibc
/// version, CPU architecture. Adds the warnings and notes to the report.
fn check_compatibility(report: &mut DependencyReport, w: &Walk, links: &Links, opts: &AnalyzeOptions) -> Compatibility {
    let mut compat = Compatibility::Good;
    // Missing, by who needs them: the entry binary (it will not start),
    // another program (often a helper tool), or only libraries and Node
    // add-ons (an optional feature, often loaded only when used).
    let mut for_entry = Vec::new();
    let mut for_programs: Vec<(String, String)> = Vec::new();
    let mut for_libraries = Vec::new();
    let mut abi_sensitive = Vec::new();
    let is_library = |f: &str| f.rsplit('/').next().is_some_and(|n| n.contains(".so") || n.ends_with(".node"));
    for (name, by) in &links.needed {
        if w.bundled.contains(name) || name.starts_with("ld-linux") || name.starts_with("ld64") {
            continue;
        }
        let info = classify_library(name);
        let host = host_has_lib(&opts.host_lib_dirs, name);
        if !host {
            if links.entry.as_ref().is_some_and(|e| by.contains(e)) || links.at_start.contains(name) {
                for_entry.push(name.clone());
            } else if let Some(program) = by.iter().find(|f| !is_library(f)) {
                for_programs.push((name.clone(), program.clone()));
            } else {
                // Only tray libraries need it (their GTK 2): part of the tray feature.
                let for_tray = by.iter().all(|f| f.rsplit('/').next().is_some_and(|n| feature_of(n) == "tray"));
                for_libraries.push((name.clone(), for_tray, by.clone()));
            }
        } else if info.class == ResourceClass::Dangerous {
            abi_sensitive.push(name.clone());
        }
        report.missing.push(MissingLibrary { name: name.clone(), class: info.class, host_available: host, needed_by: by.clone() });
    }
    if !for_entry.is_empty() {
        worsen(&mut compat, Compatibility::LikelyBroken);
        report.warnings.push(Warning::danger(
            "libs-not-found",
            "Libraries not found",
            format!(
                "The app's main program needs libraries, directly or through the libraries it brings, that are neither bundled nor installed on this computer: {}. It will probably not start.",
                list(&for_entry)
            ),
        ));
    }
    if !for_programs.is_empty() {
        worsen(&mut compat, Compatibility::Risk);
        let names: Vec<String> = for_programs.iter().map(|(n, _)| n.clone()).collect();
        let mut programs: Vec<String> = for_programs.iter().map(|(_, p)| p.clone()).collect();
        programs.dedup();
        report.warnings.push(Warning::warn(
            "libs-not-found-program",
            "Libraries not found for a program inside the app",
            format!(
                "{} inside the app needs libraries that are neither bundled nor installed: {}. If the app uses that program, that part fails; often it is a helper tool the app does not need to start.",
                list(&programs),
                list(&names)
            ),
        ));
    }
    report.warnings.extend(optional_features(&for_libraries, &opts.host_lib_dirs, Path::new("/dev"), w.electron));
    if !abi_sensitive.is_empty() {
        report.warnings.push(Warning::info(
            "host-abi-libs",
            "Uses this computer's system libraries",
            format!(
                "Like most AppImages, it uses this computer's copy of {} instead of bringing its own. If it ever crashes right at the start after a system update, this is a likely cause.",
                list(&abi_sensitive)
            ),
        ));
    }

    if let (Some(need), Some(have)) = (links.glibc_max, host_glibc_version()) {
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
    if let Some(a) = links.arch {
        if a != opts.host_arch && !(a == "i686" && opts.host_arch == "x86_64") {
            worsen(&mut compat, Compatibility::LikelyBroken);
            report.warnings.push(Warning::danger(
                "arch-mismatch",
                "Wrong CPU architecture",
                format!("This AppImage is built for {a}, but this system is {}.", opts.host_arch),
            ));
        }
    }
    if links.parsed == 0 {
        worsen(&mut compat, Compatibility::LikelyBroken);
        report.warnings.push(Warning::warn("no-elf", "No executables found", "No ELF executables were found in the AppImage payload."));
    }
    if report.entry_is_script && report.entry_binary.is_none() {
        report.notes.push(sam_core::i18n::tr("AppRun is a script; the main binary could not be determined"));
    }
    if w.truncated {
        report.notes.push(sam_core::i18n::tr("analysis was truncated because the payload is very large"));
    }
    compat
}

/// What libraries that only bundled libraries need are for, by name
/// prefix: missing ones mean a feature is missing, not that the app fails.
const FEATURES: &[(&str, &[&str])] = &[
    (
        "cuda",
        &[
            "libcuda.",
            "libcudart.",
            "libcublas",
            "libcudnn",
            "libcufft",
            "libcurand",
            "libcusparse",
            "libcusolver",
            "libnvrtc",
            "libnvinfer",
            "libnccl",
            "libnvJitLink",
            "libcupti",
            "libnvToolsExt",
            "libnvonnxparser",
            "libnvparsers",
        ],
    ),
    (
        "rocm",
        &[
            "libamdhip64",
            "librocblas",
            "libhipblas",
            "libMIOpen",
            "librocm",
            "libhsa-runtime64",
            "librccl",
            "libhipfft",
            "librocfft",
            "librocsolver",
            "librocsparse",
        ],
    ),
    ("opencl", &["libOpenCL."]),
    ("tray", &["libdbusmenu", "libappindicator", "libindicator", "libayatana-appindicator", "libayatana-indicator"]),
];

/// The feature a library belongs to (`FEATURES`), or "other".
fn feature_of(name: &str) -> &'static str {
    FEATURES.iter().find(|(_, prefixes)| prefixes.iter().any(|p| name.starts_with(p))).map_or("other", |(f, _)| *f)
}

/// The bundled package a file belongs to: the Node package for files in
/// `node_modules` ("foundry-local-sdk", "@node-llama-cpp/linux-x64-cuda-ext"),
/// else the file's name.
fn component(path: &str) -> String {
    if let Some(i) = path.rfind("node_modules/") {
        let mut parts = path[i + "node_modules/".len()..].split('/');
        let first = parts.next().unwrap_or_default();
        return match (first.starts_with('@'), parts.next()) {
            (true, Some(second)) => format!("{first}/{second}"),
            _ => first.to_string(),
        };
    }
    path.rsplit('/').next().unwrap_or(path).to_string()
}

/// "12" for "libcudart.so.12".
fn major_version(name: &str) -> Option<String> {
    name.split_once(".so.").map(|(_, v)| v.split('.').next().unwrap_or(v).to_string()).filter(|v| !v.is_empty())
}

/// Other major versions of `name` this computer has ("13" for a missing
/// "libcudart.so.12" when libcudart.so.13 is installed).
fn installed_versions(name: &str, host_dirs: &[PathBuf]) -> BTreeSet<String> {
    let Some((stem, _)) = name.split_once(".so") else { return BTreeSet::new() };
    let prefix = format!("{stem}.so.");
    host_dirs
        .iter()
        .flat_map(|d| fs::read_dir(d).into_iter().flatten().flatten())
        .filter_map(|e| e.file_name().to_str().and_then(|f| f.strip_prefix(&prefix)).and_then(|v| v.split('.').next()).map(str::to_string))
        .filter(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit()))
        .collect()
}

/// Notices for libraries that only bundled libraries need: which feature
/// is missing and what that means on this computer. `dev` is where the
/// GPU devices are (`/dev`).
/// `electron`: Electron draws tray menus itself, so the tray libraries that
/// electron-builder bundles for old systems do not matter.
/// `missing`: name, whether only tray libraries need it, and who needs it.
fn optional_features(missing: &[(String, bool, Vec<String>)], host_dirs: &[PathBuf], dev: &Path, electron: bool) -> Vec<Warning> {
    let mut groups: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut users: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for (name, for_tray, by) in missing {
        let feature = if *for_tray { "tray" } else { feature_of(name) };
        if feature == "tray" && electron {
            continue;
        }
        groups.entry(feature).or_default().push(name.clone());
        users.entry(feature).or_default().extend(by.iter().map(|b| component(b)));
    }
    // "foundry-local-sdk", "@node-llama-cpp/linux-x64-cuda-ext and 1 more".
    let engines = |feature: &str| {
        let v: Vec<String> = users.get(feature).map(|s| s.iter().cloned().collect()).unwrap_or_default();
        list(&v)
    };
    let versions = |libs: &[String], key: &str| -> (BTreeSet<String>, BTreeSet<String>) {
        let wanted: BTreeSet<String> = libs.iter().filter(|n| n.starts_with(key)).filter_map(|n| major_version(n)).collect();
        let have = libs.iter().filter(|n| n.starts_with(key)).flat_map(|n| installed_versions(n, host_dirs)).collect();
        (wanted, have)
    };
    let join = |v: &BTreeSet<String>| v.iter().cloned().collect::<Vec<_>>().join(" or ");
    let mut out = Vec::new();
    for (feature, libs) in groups {
        let w = match feature {
            // Only the bundled engine that is built for it is affected:
            // the app may use the graphics card in other ways (a local
            // Ollama server brings its own CUDA), so these are notes.
            "cuda" => {
                let (wanted, have) = versions(&libs, "libcudart.");
                let cuda = if wanted.is_empty() { "CUDA".to_string() } else { format!("CUDA {}", join(&wanted)) };
                let who = engines("cuda");
                let msg = if !dev.join("nvidiactl").exists() {
                    sam_core::i18n::trf("{who}, bundled in this app, can use NVIDIA graphics cards ({cuda}). This computer has none, so it runs without one: if you use this part to run local AI models, they run on the processor, which is much slower.", &[("who", &who), ("cuda", &cuda)])
                } else if !have.is_empty() {
                    format!(
                        "{who}, bundled in this app, is built for {cuda}. This computer has CUDA {}, which it cannot load, so this part cannot use the graphics card. If you use this part to run local AI models, they run on the processor instead, which is much slower. Other ways the app uses the graphics card are not affected.",
                        join(&have)
                    )
                } else {
                    sam_core::i18n::trf("{who}, bundled in this app, is built for {cuda}, which is not installed, so this part cannot use the graphics card. If you use this part to run local AI models, they run on the processor instead, which is much slower. Other ways the app uses the graphics card are not affected.", &[("who", &who), ("cuda", &cuda)])
                };
                Warning::info("feature-cuda", &sam_core::i18n::trf("A bundled part needs {cuda}", &[("cuda", &cuda)]), msg)
            }
            "rocm" => {
                let who = engines("rocm");
                let msg = if !dev.join("kfd").exists() {
                    sam_core::i18n::trf("{who}, bundled in this app, can use AMD graphics cards (ROCm). This computer offers no AMD compute device, so it runs without one: if you use this part to run local AI models, they run on the processor, which is much slower.", &[("who", &who)])
                } else {
                    sam_core::i18n::trf("{who}, bundled in this app, needs ROCm, which is not installed, so this part cannot use the graphics card. If you use this part to run local AI models, they run on the processor instead, which is much slower. Other ways the app uses the graphics card are not affected.", &[("who", &who)])
                };
                Warning::info("feature-rocm", "A bundled part needs ROCm", msg)
            }
            "opencl" => Warning::info(
                "feature-opencl",
                "No OpenCL acceleration",
                "This app can speed up some work with OpenCL, which is not installed. Install the OpenCL loader (ocl-icd) and your graphics card's OpenCL driver to use it.",
            ),
            "tray" => Warning::info(
                "feature-tray-menu",
                "The tray icon may have no menu",
                format!("The libraries for menus on tray icons are not installed ({}). The app works; its tray icon may show without a menu.", list(&libs)),
            ),
            _ => Warning::info(
                "libs-not-found-optional",
                "Libraries for optional parts not found",
                format!(
                    "Only libraries bundled in the app need these, and they are often loaded only for one feature: {}. The app starts; the part that uses them may not work.",
                    list(&libs)
                ),
            ),
        };
        out.push(w);
    }
    out
}

/// How well a sandbox can isolate the app (None: no concerns).
fn isolation_verdict(
    report: &mut DependencyReport,
    w: &Walk,
    needed: &BTreeMap<String, Vec<String>>,
    compat: Compatibility,
    script_text: Option<&str>,
) -> Option<IsolationVerdict> {
    if let Some(tool) = script_text.and_then(script_privileged) {
        report.warnings.push(Warning::danger(
            "privileged",
            "Requires privileged access",
            sam_core::i18n::trf("The AppImage's launcher calls '{tool}'. It appears to require root access, which cannot be sandboxed.", &[("tool", &tool)]),
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
        report.notes.push(sam_core::i18n::tr("X11-only application: isolation between windows is limited"));
        Some(IsolationVerdict::WeaklyIsolated)
    } else {
        None
    }
}

/// The host resources the app's sandbox would use, and why.
fn host_resources(req: &Requirements) -> Vec<HostResource> {
    let mut resources = Vec::new();
    for (res, why) in SAFE_HOST_RESOURCES {
        let relevant = match *why {
            "TLS certificates" => req.certificates || req.network,
            _ => true,
        };
        if relevant {
            resources.push(HostResource { resource: res.to_string(), class: ResourceClass::Safe, reason: why.to_string(), auto: true });
        }
    }
    if req.gpu {
        for (res, why) in GRAPHICS_HOST_RESOURCES {
            resources.push(HostResource { resource: res.to_string(), class: ResourceClass::Graphics, reason: why.to_string(), auto: false });
        }
    }
    let controlled = [
        (req.wayland, "Wayland socket", "Wayland client libraries / toolkit support"),
        (req.x11, "X11 socket", "links X11 libraries"),
        (req.audio, "PipeWire / PulseAudio socket", "links audio libraries"),
        (req.dbus, "D-Bus session socket", "links D-Bus libraries"),
    ];
    for (needed, res, why) in controlled {
        if needed {
            resources.push(HostResource { resource: res.into(), class: ResourceClass::Controlled, reason: why.into(), auto: false });
        }
    }
    resources
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
    /// Programs that load graphics libraries only at run time are recognized as needing the GPU.
    #[test]
    fn programs_that_load_graphics_at_run_time() {
        let d = tempfile::tempdir().unwrap();
        let prog = d.path().join("wezterm-gui");
        let lib = d.path().join("libQt5Gui.so.5");
        std::fs::write(&prog, b"\x7fELF....with_egl_lib(libEGL.so.1)....").unwrap();
        std::fs::write(&lib, b"\x7fELF....libEGL.so.1....").unwrap();
        assert!(super::scan_programs(&super::programs(std::slice::from_ref(&prog)), &|_| {}).loads_graphics);
        assert!(!super::scan_programs(&super::programs(&[lib]), &|_| {}).loads_graphics, "bundled libraries do not count");
        let addon = d.path().join("bindings.linux-x64-gnu.node");
        std::fs::write(&addon, b"\x7fELF....libEGL.so.1....").unwrap();
        assert!(super::programs(&[addon]).is_empty(), "Node add-ons are libraries");
        std::fs::write(&prog, b"\x7fELF....nothing....").unwrap();
        assert!(!super::scan_programs(&super::programs(&[prog]), &|_| {}).loads_graphics);
    }

    /// A missing optional library is reported with the feature it provides, not as a broken app.
    #[test]
    fn missing_optional_libraries_name_the_feature() {
        let d = tempfile::tempdir().unwrap();
        let (dev, lib) = (d.path().join("dev"), d.path().join("lib"));
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::create_dir_all(&lib).unwrap();
        let engine = vec!["resources/node_modules/foundry-local-sdk/core/libonnxruntime_providers_cuda.so".to_string()];
        let mut missing: Vec<(String, bool, Vec<String>)> =
            ["libcudart.so.12", "libcublas.so.12", "libdbusmenu-gtk.so.4", "libfoo.so.1"].iter().map(|s| (s.to_string(), false, engine.clone())).collect();
        missing.push(("libgtk-x11-2.0.so.0".into(), true, vec!["usr/lib/libappindicator.so.1".into()]));
        let by_code = |w: &[Warning], c: &str| w.iter().find(|x| x.code == c).cloned();
        // No NVIDIA card.
        let w = super::optional_features(&missing, std::slice::from_ref(&lib), &dev, false);
        let cuda = by_code(&w, "feature-cuda").unwrap();
        assert_eq!(cuda.severity, sam_core::Severity::Info);
        assert_eq!(cuda.title, "A bundled part needs CUDA 12");
        assert!(cuda.message.starts_with("foundry-local-sdk, bundled in this app,") && cuda.message.contains("has none"), "{}", cuda.message);
        assert!(by_code(&w, "feature-tray-menu").is_some());
        let other = by_code(&w, "libs-not-found-optional").unwrap().message;
        assert!(other.contains("libfoo.so.1") && !other.contains("gtk-x11"), "GTK 2 of a tray library counts as the tray feature");
        // An NVIDIA card with CUDA 13: says why this part cannot use it, and
        // that the rest of the app is not affected.
        std::fs::write(dev.join("nvidiactl"), "").unwrap();
        std::fs::write(lib.join("libcudart.so.13"), "").unwrap();
        let cuda = by_code(&super::optional_features(&missing, std::slice::from_ref(&lib), &dev, false), "feature-cuda").unwrap();
        assert_eq!(cuda.severity, sam_core::Severity::Info, "a note: only one bundled part is affected");
        assert!(cuda.message.contains("This computer has CUDA 13, which it cannot load") && cuda.message.contains("not affected"), "{}", cuda.message);
        // The consequence for local AI models is named.
        assert!(cuda.message.contains("run on the processor instead, which is much slower"), "{}", cuda.message);
        assert_eq!(super::major_version("libcudart.so.12.4.1").as_deref(), Some("12"));
        assert_eq!(super::component("a/node_modules/@node-llama-cpp/linux-x64-cuda-ext/bins/x.so"), "@node-llama-cpp/linux-x64-cuda-ext");
        let electron = super::optional_features(&missing, std::slice::from_ref(&lib), &dev, true);
        assert!(by_code(&electron, "feature-tray-menu").is_none(), "Electron draws its own tray menus");
    }

    /// Programs that choose the Qt platform themselves (X11 or Wayland) are recognized.
    #[test]
    fn programs_that_choose_the_qt_platform() {
        let d = tempfile::tempdir().unwrap();
        let prog = d.path().join("mscore4portable");
        let scan = |data: &[u8]| {
            std::fs::write(&prog, data).unwrap();
            super::scan_programs(&super::programs(std::slice::from_ref(&prog)), &|_| {}).qt_platform_override
        };
        assert_eq!(scan(b"\x7fELF\0MU_QT_QPA_PLATFORM\0QT_QPA_PLATFORMTHEME\0xcb\0").as_deref(), Some("MU_QT_QPA_PLATFORM"));
        // Qt's own variable, read or set by many programs, does not count.
        assert_eq!(scan(b"\x7fELF\0QT_QPA_PLATFORM\0xcb\0"), None);
        // Neither does a longer string that merely ends like it.
        assert_eq!(scan(b"\x7fELF\0see MY_QT_QPA_PLATFORM\0"), None);
        assert_eq!(scan(b"\x7fELF\0lower_QT_QPA_PLATFORM\0"), None);
    }

    /// A bundled Qt Wayland plugin counts as usable only when its Wayland client library is present.
    #[test]
    fn qt_wayland_plugin_needs_its_client_library() {
        let d = tempfile::tempdir().unwrap();
        // Not an ELF file: cannot be checked, so it counts as usable.
        let unknown = d.path().join("libqwayland-generic.so");
        std::fs::write(&unknown, b"not elf").unwrap();
        assert!(super::qt_wayland_usable(std::slice::from_ref(&unknown), &Default::default()));
        assert!(!super::qt_wayland_usable(&[], &Default::default()));
    }

    /// Start scripts that force X11 are recognized, so SAM grants X11 to those apps.
    #[test]
    fn start_scripts_that_force_x11() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("AppRun"), "#!/bin/sh\nexec \"$APPDIR/usr/bin/app\"\n").unwrap();
        assert!(!super::start_scripts_force_x11(d.path()));
        std::fs::create_dir(d.path().join("apprun-hooks")).unwrap();
        std::fs::write(d.path().join("apprun-hooks/gtk.sh"), "# export GDK_BACKEND=x11 (commented)\nexport GDK_BACKEND=\"${GDK_BACKEND:-x11}\"\n").unwrap();
        assert!(!super::start_scripts_force_x11(d.path()), "comments and defaults do not count");
        std::fs::write(d.path().join("apprun-hooks/gtk.sh"), "export GDK_BACKEND=x11 # Crash with Wayland backend\n").unwrap();
        assert!(super::start_scripts_force_x11(d.path()));
        std::fs::remove_file(d.path().join("apprun-hooks/gtk.sh")).unwrap();
        std::fs::write(d.path().join("AppRun"), "export QT_QPA_PLATFORM=\"${FREECAD_QT_QPA_PLATFORM:-xcb}\"\n").unwrap();
        assert!(super::start_scripts_force_x11(d.path()), "FreeCAD's own override variable still forces X11");
        std::fs::write(d.path().join("AppRun"), "#!/bin/sh\n").unwrap();
        std::fs::write(d.path().join(".env"), "SDL_AUDIODRIVER=pulseaudio\nQT_QPA_PLATFORM=xcb\n").unwrap();
        assert!(super::start_scripts_force_x11(d.path()), "sharun's .env counts too");
        std::fs::remove_file(d.path().join(".env")).unwrap();
        std::fs::write(d.path().join("AppRun.env"), "QT_QPA_PLATFORMTHEME=xdgdesktopportal\nQT_QPA_PLATFORM=xcb\n").unwrap();
        assert!(super::start_scripts_force_x11(d.path()), "appimage-builder's AppRun.env (Cura)");
    }

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

    /// When the AppImage starts through a shell script, SAM finds the program the script starts.
    #[test]
    fn the_program_behind_a_start_script_is_found() {
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

    /// An AppImage that asks for administrator rights (pkexec) is marked as unsafe to sandbox.
    #[test]
    fn an_appimage_asking_for_admin_rights_is_unsafe_to_sandbox() {
        let d = fake_appdir("#!/bin/sh\npkexec \"$APPDIR/usr/bin/app\"\n");
        let r = analyze_appdir(d.path(), &AnalyzeOptions::default()).unwrap();
        assert_eq!(r.verdict, Some(IsolationVerdict::UnsafeToSandbox));
    }

    /// Electron apps are recognized by their markers, and bundled library symlinks are followed.
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

    /// Libraries an app finds relative to its own folder ($ORIGIN) are counted as bundled, not as missing.
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

    /// The C library version an app needs is read from its symbol versions.
    #[test]
    fn the_c_library_version_an_app_needs_is_read() {
        assert_eq!(parse_glibc_version("GLIBC_2.34"), Some((2, 34)));
        assert_eq!(parse_glibc_version("GLIBC_PRIVATE"), None);
        assert!(host_glibc_version().is_some());
    }
}
