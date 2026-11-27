//! The place check: whether a path names exactly the file, folder or
//! device SAM chose (same device, same inode), reached without following
//! any link, and, where SAM's sandbox mounted it, still the root of that
//! mount.
//!
//! One copy for every part of SAM that checks or holds a place: SAM's room
//! helper includes this file with `#[path]` (room-exec/main.rs is built
//! alone by rustc, statically, with the standard library only), and the
//! launcher's crates use it as `sam_core::place_check`. So this file uses
//! the standard library and the C library's `syscall` and `statx` only.
//!
//! Why the mount matters: a program outside a sandbox that can write the
//! folder holding one of its places can move the place away after
//! Bubblewrap mounted it (the mount goes with the name) and put the very
//! same file back at the name (a second name, a hard link, made before).
//! Device and inode still match, but the place is no longer shown through
//! the mount Bubblewrap made, so whatever that mount gave (read-only, the
//! object SAM held instead of a name) no longer holds.
//!
//! Kernel needs: `openat2` (Linux 5.6) and the mount-root attribute of
//! `statx` (Linux 5.8). Where the kernel does not report the attribute,
//! a place that must be a mount fails the check, with a message that says
//! why.

use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io;
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::raw::{c_char, c_int, c_long, c_uint};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn statx(
        dirfd: c_int,
        path: *const c_char,
        flags: c_int,
        mask: c_uint,
        buf: *mut Statx,
    ) -> c_int;
}

/// `openat2`: the same number on every architecture SAM is built for.
const SYS_OPENAT2: c_long = 437;
const AT_FDCWD: c_int = -100;
const AT_EMPTY_PATH: c_int = 0x1000;
const O_PATH: u64 = 0o10000000;
const O_CLOEXEC: u64 = 0o2000000;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const ELOOP: i32 = 40;
/// `statx`: the place is the root of a mount (Linux 5.8).
const STATX_ATTR_MOUNT_ROOT: u64 = 0x2000;

/// The start of the kernel's `struct statx` (256 bytes): the fields this
/// file reads, then room for the rest.
#[repr(C)]
struct Statx {
    mask: u32,
    blksize: u32,
    attributes: u64,
    nlink: u32,
    uid: u32,
    gid: u32,
    mode: u16,
    spare0: u16,
    ino: u64,
    size: u64,
    blocks: u64,
    attributes_mask: u64,
    rest: [u64; 24],
}

/// `struct open_how` of `openat2`.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// What a place must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// The root of a mount that shows the file, folder or device with
    /// this device and inode.
    MountOf { dev: u64, ino: u64 },
}

/// Why a place is not what SAM chose.
#[derive(Debug)]
pub enum Mismatch {
    /// It cannot be reached without following a link: a link lies on its
    /// way (`ELOOP`), it is missing, or it cannot be opened.
    NotReached(io::Error),
    /// Another file, folder or device is there (its device and inode).
    Other { dev: u64, ino: u64 },
    /// The file, folder or device SAM chose, but not the root of a mount
    /// where a mount was made.
    NotAMount,
    /// The kernel does not report whether a place is the root of a mount.
    MountUnknown,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mismatch::NotReached(e) if e.raw_os_error() == Some(ELOOP) => {
                write!(f, "a link lies on its way")
            }
            Mismatch::NotReached(e) => write!(f, "it cannot be reached without links: {e}"),
            Mismatch::Other { .. } => write!(f, "another file, folder or device is there"),
            Mismatch::NotAMount => write!(
                f,
                "it is no longer shown through the mount made there (moved away)"
            ),
            Mismatch::MountUnknown => write!(
                f,
                "this kernel does not report whether a place is a mount (Linux 5.8 or newer is needed)"
            ),
        }
    }
}

/// Checks that `at` is what `expect` says, reached without following any
/// link (not even in its last part).
pub fn check(at: &Path, expect: &Expect) -> Result<(), Mismatch> {
    let fd = open_no_link(at).map_err(Mismatch::NotReached)?;
    let found = identity(&fd).map_err(Mismatch::NotReached)?;
    let root = mount_root(&fd).map_err(Mismatch::NotReached)?;
    verdict(found, root, expect)
}

/// The verdict on what was found (device and inode, and whether it is the
/// root of a mount, `None` when the kernel does not say).
fn verdict(found: (u64, u64), root: Option<bool>, expect: &Expect) -> Result<(), Mismatch> {
    match *expect {
        Expect::MountOf { dev, ino } => {
            if found != (dev, ino) {
                return Err(Mismatch::Other {
                    dev: found.0,
                    ino: found.1,
                });
            }
            match root {
                Some(true) => Ok(()),
                Some(false) => Err(Mismatch::NotAMount),
                None => Err(Mismatch::MountUnknown),
            }
        }
    }
}

/// Device and inode of what the absolute path `p` names, opened without
/// following any link.
pub fn held_identity(p: &Path) -> io::Result<(u64, u64)> {
    identity(&open_no_link(p)?)
}

/// Device and inode of an open file, folder or device (also one opened
/// with `O_PATH`).
pub fn identity(fd: &OwnedFd) -> io::Result<(u64, u64)> {
    // SAFETY: a second owner of `fd` that never closes it (ManuallyDrop):
    // it only asks for the metadata while `fd` is borrowed.
    let file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd.as_raw_fd()) });
    let m = file.metadata()?;
    Ok((m.dev(), m.ino()))
}

/// Whether `fd` is the root of a mount; `None` when the kernel does not
/// report it.
fn mount_root(fd: &OwnedFd) -> io::Result<Option<bool>> {
    // SAFETY: an all-zero statx is a valid value of plain integers.
    let mut st: Statx = unsafe { std::mem::zeroed() };
    // SAFETY: statx of our own descriptor (an empty path with
    // AT_EMPTY_PATH) writes at most the 256 bytes of `st`.
    let r = unsafe { statx(fd.as_raw_fd(), c"".as_ptr(), AT_EMPTY_PATH, 0, &mut st) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((st.attributes_mask & STATX_ATTR_MOUNT_ROOT != 0)
        .then_some(st.attributes & STATX_ATTR_MOUNT_ROOT != 0))
}

/// Opens `p` (`O_PATH`, close-on-exec) and follows every link, as
/// Bubblewrap does with a path it binds.
pub fn open_path(p: &Path) -> io::Result<OwnedFd> {
    use std::os::unix::fs::OpenOptionsExt;
    // Read access is O_RDONLY, which is 0: the flags are O_PATH and
    // close-on-exec (the standard library adds it) only.
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_PATH as c_int)
        .open(p)
        .map(OwnedFd::from)
}

/// Opens the absolute path `p` (`O_PATH`, close-on-exec) without
/// following any link in it, also not in its last part: a link anywhere
/// refuses (`ELOOP`).
pub fn open_no_link(p: &Path) -> io::Result<OwnedFd> {
    if !p.is_absolute() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    openat2(AT_FDCWD, p, RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)
}

/// Opens `rel` strictly beneath the open folder `dir` (`O_PATH`,
/// close-on-exec), through no link at all.
pub fn open_beneath(dir: &OwnedFd, rel: &Path) -> io::Result<OwnedFd> {
    openat2(
        dir.as_raw_fd(),
        rel,
        RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    )
}

/// `openat2` of `path` from `dir` (`O_PATH`, close-on-exec) with `resolve`.
fn openat2(dir: RawFd, path: &Path, resolve: u64) -> io::Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let how = OpenHow {
        flags: O_PATH | O_CLOEXEC,
        mode: 0,
        resolve,
    };
    // SAFETY: openat2 with a valid descriptor (or AT_FDCWD), a C string
    // and a struct of the size given.
    let fd = unsafe {
        syscall(
            SYS_OPENAT2,
            dir,
            c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a new descriptor of our own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn of(p: &Path) -> (u64, u64) {
        let m = std::fs::symlink_metadata(p).unwrap();
        (m.dev(), m.ino())
    }

    fn mount_of(p: &Path) -> Expect {
        let (dev, ino) = of(p);
        Expect::MountOf { dev, ino }
    }

    /// The kernel's struct, as the C library describes it: the fields
    /// read here lie where the kernel writes them, and nothing is written
    /// past the end.
    #[test]
    fn the_statx_struct_is_the_kernels() {
        assert_eq!(
            std::mem::size_of::<Statx>(),
            std::mem::size_of::<libc::statx>()
        );
        assert_eq!(
            std::mem::offset_of!(Statx, attributes),
            std::mem::offset_of!(libc::statx, stx_attributes)
        );
        assert_eq!(
            std::mem::offset_of!(Statx, attributes_mask),
            std::mem::offset_of!(libc::statx, stx_attributes_mask)
        );
        assert_eq!(STATX_ATTR_MOUNT_ROOT, libc::STATX_ATTR_MOUNT_ROOT as u64);
        assert_eq!(SYS_OPENAT2, libc::SYS_openat2);
        assert_eq!(
            (O_PATH, O_CLOEXEC),
            (libc::O_PATH as u64, libc::O_CLOEXEC as u64)
        );
        assert_eq!(
            (AT_FDCWD, AT_EMPTY_PATH, ELOOP),
            (libc::AT_FDCWD, libc::AT_EMPTY_PATH, libc::ELOOP)
        );
    }

    /// The root of the file system is a mount in every mount namespace:
    /// the object SAM chose, as the root of a mount, passes.
    #[test]
    fn the_same_object_at_the_root_of_a_mount_passes() {
        let root = Path::new("/");
        check(root, &mount_of(root)).unwrap();
        assert_eq!(held_identity(root).unwrap(), of(root));
    }

    /// A link at the place, or on its way, is refused, even when it leads
    /// to exactly the object SAM chose.
    #[test]
    fn a_link_at_the_place_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let link = tmp.path().join("link");
        symlink("/", &link).unwrap();
        for at in [link.clone(), link.join("."), link.join("proc")] {
            let target = std::fs::canonicalize(&at).unwrap();
            match check(&at, &mount_of(&target)) {
                Err(Mismatch::NotReached(e)) => {
                    assert_eq!(e.raw_os_error(), Some(ELOOP), "{}", at.display())
                }
                other => panic!("{}: {other:?}", at.display()),
            }
        }
        let e = held_identity(&link).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(ELOOP));
        // Only the opener that follows links, as Bubblewrap does, reaches
        // the link's target.
        assert_eq!(
            identity(&open_path(&link).unwrap()).unwrap(),
            of(Path::new("/"))
        );
        assert!(
            Mismatch::NotReached(e).to_string().contains("a link"),
            "the message names the link"
        );
    }

    /// Another file, folder or device than SAM chose is refused, whatever
    /// differs (the inode, or the device).
    #[test]
    fn a_different_object_is_refused() {
        let root = Path::new("/");
        let (dev, ino) = of(root);
        for expect in [
            Expect::MountOf { dev, ino: ino + 1 },
            Expect::MountOf { dev: dev + 1, ino },
        ] {
            assert!(
                matches!(check(root, &expect), Err(Mismatch::Other { .. })),
                "{expect:?}"
            );
        }
    }

    /// The very object SAM chose is refused where a mount was made but
    /// the place is not the root of one (a folder or a file inside a
    /// mount), and so is any place when the kernel does not say: the check
    /// fails closed, with a message that names the cause.
    #[test]
    fn a_place_that_is_not_the_root_of_a_mount_is_refused_where_a_mount_is_expected() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("f");
        std::fs::write(&file, "x").unwrap();
        for at in [tmp.path(), file.as_path()] {
            match check(at, &mount_of(at)) {
                Err(Mismatch::NotAMount) => {}
                other => panic!("{}: {other:?}", at.display()),
            }
        }
        let found = of(Path::new("/"));
        let expect = Expect::MountOf {
            dev: found.0,
            ino: found.1,
        };
        assert!(verdict(found, Some(true), &expect).is_ok());
        let unknown = verdict(found, None, &expect).unwrap_err();
        assert!(matches!(unknown, Mismatch::MountUnknown));
        assert!(unknown.to_string().contains("Linux 5.8"), "{unknown}");
        assert!(matches!(
            verdict(found, Some(false), &expect),
            Err(Mismatch::NotAMount)
        ));
    }

    /// A path that is not absolute is never opened without links (it
    /// would depend on the current folder).
    #[test]
    fn only_absolute_paths_are_opened_without_links() {
        let e = open_no_link(Path::new("etc")).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }
}
