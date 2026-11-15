// SPDX-License-Identifier: GPL-3.0-or-later
//! A tiny D-Bus client for one question: "is this name reachable on the
//! bus at this address?". Used by the sandbox check, both on the host (what
//! exists) and inside the sandbox (what the filter lets through). It speaks
//! just enough of the wire protocol: EXTERNAL authentication, Hello and
//! GetNameOwner. No external tools or libraries.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{bail, Context, Result};

/// True if `name` has an owner that the bus at `address` lets us see.
pub fn name_reachable(address: &str, name: &str, timeout: Duration) -> Result<bool> {
    let path = address
        .split(';')
        .find_map(|a| a.strip_prefix("unix:").and_then(|rest| rest.split(',').find_map(|kv| kv.strip_prefix("path="))))
        .context("only unix:path= bus addresses are supported")?;
    let mut s = UnixStream::connect(path).with_context(|| format!("connecting to {path}"))?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;

    // Authentication: EXTERNAL with our uid as hex digits.
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() }.to_string();
    let hex: String = uid.bytes().map(|b| format!("{b:02x}")).collect();
    s.write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes())?;
    let mut reader = BufReader::new(s.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if !line.starts_with("OK") {
        bail!("authentication refused: {}", line.trim());
    }
    s.write_all(b"BEGIN\r\n")?;

    // Hello (required first), then GetNameOwner; read until its reply.
    s.write_all(&method_call(1, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello", None))?;
    s.write_all(&method_call(2, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", Some(name)))?;
    for _ in 0..64 {
        let (kind, reply_serial) = read_message(&mut reader)?;
        if reply_serial == Some(2) {
            return Ok(kind == 2); // 2 = method return, 3 = error
        }
    }
    bail!("no reply from the bus")
}

fn pad(buf: &mut Vec<u8>, align: usize) {
    while !buf.len().is_multiple_of(align) {
        buf.push(0);
    }
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    pad(buf, 4);
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
}

fn field(buf: &mut Vec<u8>, code: u8, sig: &str, value: &str) {
    pad(buf, 8);
    buf.push(code);
    buf.push(sig.len() as u8);
    buf.extend_from_slice(sig.as_bytes());
    buf.push(0);
    if sig == "g" {
        buf.push(value.len() as u8);
        buf.extend_from_slice(value.as_bytes());
        buf.push(0);
    } else {
        put_str(buf, value);
    }
}

/// A little-endian METHOD_CALL with an optional single string argument.
fn method_call(serial: u32, dest: &str, path: &str, iface: &str, member: &str, arg: Option<&str>) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some(a) = arg {
        put_str(&mut body, a);
    }
    // Header fields are laid out as if they started at offset 16.
    let mut fields = vec![0u8; 16];
    field(&mut fields, 1, "o", path);
    field(&mut fields, 2, "s", iface);
    field(&mut fields, 3, "s", member);
    field(&mut fields, 6, "s", dest);
    if arg.is_some() {
        field(&mut fields, 8, "g", "s");
    }
    let fields = fields.split_off(16);
    let mut msg = vec![b'l', 1, 0, 1];
    msg.extend_from_slice(&(body.len() as u32).to_le_bytes());
    msg.extend_from_slice(&serial.to_le_bytes());
    msg.extend_from_slice(&(fields.len() as u32).to_le_bytes());
    msg.extend_from_slice(&fields);
    pad(&mut msg, 8);
    msg.extend_from_slice(&body);
    msg
}

/// Reads one message: (message type, REPLY_SERIAL if any).
fn read_message(r: &mut impl Read) -> Result<(u8, Option<u32>)> {
    let mut head = [0u8; 16];
    r.read_exact(&mut head)?;
    let le = head[0] == b'l';
    let u32_at = |b: &[u8], i: usize| {
        let a = [b[i], b[i + 1], b[i + 2], b[i + 3]];
        if le {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        }
    };
    let kind = head[1];
    let body_len = u32_at(&head, 4) as usize;
    let fields_len = u32_at(&head, 12) as usize;
    if body_len > 1 << 24 || fields_len > 1 << 20 {
        bail!("message too large");
    }
    let padded = (16 + fields_len).div_ceil(8) * 8 - 16;
    let mut rest = vec![0u8; padded + body_len];
    r.read_exact(&mut rest)?;
    // Walk the header fields for REPLY_SERIAL (code 5, type u).
    let f = &rest[..fields_len];
    let mut i = 0usize;
    let align = |i: usize, a: usize| (16 + i).div_ceil(a) * a - 16;
    let mut reply = None;
    while i < f.len() {
        i = align(i, 8);
        if i + 2 > f.len() {
            break;
        }
        let code = f[i];
        let sig_len = f[i + 1] as usize;
        let sig = f.get(i + 2..i + 2 + sig_len).unwrap_or_default().to_vec();
        i += 2 + sig_len + 1;
        match sig.as_slice() {
            b"u" => {
                i = align(i, 4);
                if i + 4 > f.len() {
                    break;
                }
                if code == 5 {
                    reply = Some(u32_at(f, i));
                }
                i += 4;
            }
            b"s" | b"o" => {
                i = align(i, 4);
                if i + 4 > f.len() {
                    break;
                }
                let len = u32_at(f, i) as usize;
                i += 4 + len + 1;
            }
            b"g" => {
                let len = *f.get(i).unwrap_or(&0) as usize;
                i += 1 + len + 1;
            }
            _ => break,
        }
    }
    Ok((kind, reply))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SAM's own bus check reaches the session bus on a desktop.
    #[test]
    fn reaches_the_session_bus() {
        // Only where a session bus exists (desktop sessions, not CI).
        let Ok(addr) = std::env::var("DBUS_SESSION_BUS_ADDRESS") else { return };
        if !addr.contains("unix:path=") {
            return;
        }
        assert!(name_reachable(&addr, "org.freedesktop.DBus", Duration::from_secs(2)).unwrap());
        assert!(!name_reachable(&addr, "org.example.SamNoSuchName", Duration::from_secs(2)).unwrap());
    }

    /// SAM's own D-Bus message for the bus check has the correct wire format.
    #[test]
    fn the_bus_check_message_has_the_correct_wire_format() {
        let m = method_call(7, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", Some("x.y"));
        assert_eq!(&m[..4], &[b'l', 1, 0, 1]);
        assert_eq!(u32::from_le_bytes([m[8], m[9], m[10], m[11]]), 7);
        assert_eq!(m.len() % 8, (4 + 3 + 1) % 8, "body is one string: len(4) + 'x.y' + nul");
    }
}
