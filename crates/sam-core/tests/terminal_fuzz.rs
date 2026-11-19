//! Fuzzing of the terminal filter against a model of a terminal written
//! apart from it (audit L-F1: the filter was never fuzzed, and doubled
//! escapes, escapes inside sequences and extra parameters got past it).
//!
//! The model reads bytes the way terminals do (the DEC parser of ECMA-48),
//! and assumes the worst where terminals differ: 8-bit control codes count,
//! as raw bytes and in their UTF-8 form; a string sequence cut short by ESC
//! is still carried out; a number counts as itself and as what it becomes
//! when a terminal wraps it at 16 or 32 bits.
//!
//! Random inputs are built from pieces that broke filters before, cut into
//! random reads, and filtered. Then:
//! - the model finds nothing in the output that reaches past the terminal
//!   (clipboard, notifications, title reports, programmable keys,
//!   graphics, 8-bit controls; without SAM's relay also no requests the
//!   terminal answers into the shell);
//! - the output passes the filter again unchanged: only whole pieces from
//!   the allow-list come out;
//! - two output streams filtered apart and mixed stay harmless.
//!
//! Deterministic (a fixed seed). `SAM_FUZZ_ITERS=N` runs more rounds,
//! `SAM_FUZZ_SEED=N` mixes N into the seed.
#![allow(clippy::unwrap_used, clippy::panic)] // a test: a panic is a failed test

use sam_core::terminal::Filter;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// What a terminal does with a piece of output.
#[derive(Debug, Clone)]
enum Action {
    Execute(u32),
    Esc(Vec<u8>, u8),
    Csi(Vec<u8>, Vec<u8>, u8),
    Osc(Vec<u8>),
    Dcs(Vec<u8>, u8),
    /// SOS, PM or APC.
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum S {
    Ground,
    Escape,
    EscInter,
    CsiEntry,
    CsiParam,
    CsiInter,
    CsiIgnore,
    DcsEntry,
    DcsParam,
    DcsInter,
    DcsPass,
    DcsIgnore,
    Osc,
    SosPmApc,
}

/// A terminal that assumes the worst.
struct Model {
    s: S,
    params: Vec<u8>,
    inter: Vec<u8>,
    data: Vec<u8>,
    dcs: Option<(Vec<u8>, u8)>,
    actions: Vec<Action>,
}

impl Model {
    fn read(bytes: &[u8]) -> Vec<Action> {
        let mut m = Model {
            s: S::Ground,
            params: vec![],
            inter: vec![],
            data: vec![],
            dcs: None,
            actions: vec![],
        };
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b < 0x80 {
                m.code(u32::from(b));
                i += 1;
                continue;
            }
            // UTF-8 where it is valid, the raw byte where not: both count.
            let end = (i + 4).min(bytes.len());
            let ch =
                (i + 1..=end).find_map(|j| std::str::from_utf8(&bytes[i..j]).ok().map(|s| (s, j)));
            match ch {
                Some((s, j)) => {
                    m.code(s.chars().next().unwrap() as u32);
                    i = j;
                }
                None => {
                    m.code(u32::from(b));
                    i += 1;
                }
            }
        }
        // Whatever a terminal holds unfinished at the end may still be
        // carried out with the next output: counted as carried out.
        m.flush_string();
        m.actions
    }

    fn flush_string(&mut self) {
        match self.s {
            S::Osc => self
                .actions
                .push(Action::Osc(std::mem::take(&mut self.data))),
            S::DcsPass => {
                if let Some((inter, fin)) = self.dcs.take() {
                    self.actions.push(Action::Dcs(inter, fin));
                }
            }
            _ => {}
        }
    }

    fn enter(&mut self, s: S) {
        self.s = s;
        self.params.clear();
        self.inter.clear();
        self.data.clear();
    }

    fn code(&mut self, c: u32) {
        // From anywhere.
        match c {
            0x18 | 0x1a => {
                self.flush_string();
                self.actions.push(Action::Execute(c));
                self.enter(S::Ground);
                return;
            }
            0x1b => {
                // Worst case: a string ended by any ESC is carried out.
                self.flush_string();
                self.enter(S::Escape);
                return;
            }
            0x80..=0x9f => {
                self.flush_string();
                match c {
                    0x90 => self.enter(S::DcsEntry),
                    0x9b => self.enter(S::CsiEntry),
                    0x9d => self.enter(S::Osc),
                    0x98 | 0x9e | 0x9f => {
                        self.actions.push(Action::Other);
                        self.enter(S::SosPmApc);
                    }
                    0x9c => self.enter(S::Ground),
                    _ => {
                        self.actions.push(Action::Execute(c));
                        self.enter(S::Ground);
                    }
                }
                return;
            }
            _ => {}
        }
        let b = u8::try_from(c).unwrap_or(b'a');
        let c0 = c < 0x20;
        match self.s {
            S::Ground => {
                if c0 {
                    self.actions.push(Action::Execute(c));
                }
            }
            S::Escape | S::EscInter => {
                if c0 {
                    self.actions.push(Action::Execute(c));
                } else if (0x20..=0x2f).contains(&b) {
                    self.inter.push(b);
                    self.s = S::EscInter;
                } else if self.s == S::Escape && b == b'[' {
                    self.enter(S::CsiEntry);
                } else if self.s == S::Escape && b == b']' {
                    self.enter(S::Osc);
                } else if self.s == S::Escape && b == b'P' {
                    self.enter(S::DcsEntry);
                } else if self.s == S::Escape && matches!(b, b'X' | b'^' | b'_') {
                    self.actions.push(Action::Other);
                    self.enter(S::SosPmApc);
                } else if (0x30..=0x7e).contains(&b) {
                    self.actions.push(Action::Esc(self.inter.clone(), b));
                    self.enter(S::Ground);
                }
            }
            S::CsiEntry | S::CsiParam | S::CsiInter | S::CsiIgnore => {
                if c0 {
                    self.actions.push(Action::Execute(c));
                } else if (0x40..=0x7e).contains(&b) {
                    if self.s != S::CsiIgnore {
                        self.actions
                            .push(Action::Csi(self.params.clone(), self.inter.clone(), b));
                    }
                    self.enter(S::Ground);
                } else if self.s == S::CsiIgnore || b == 0x7f {
                } else if (0x20..=0x2f).contains(&b) {
                    self.inter.push(b);
                    self.s = S::CsiInter;
                } else if (0x30..=0x3f).contains(&b) {
                    if self.s == S::CsiInter
                        || (self.s == S::CsiParam && (0x3c..=0x3f).contains(&b))
                    {
                        self.s = S::CsiIgnore;
                    } else {
                        self.params.push(b);
                        self.s = S::CsiParam;
                    }
                }
            }
            S::DcsEntry | S::DcsParam | S::DcsInter | S::DcsIgnore => {
                if c0 || b == 0x7f || self.s == S::DcsIgnore {
                } else if (0x40..=0x7e).contains(&b) {
                    self.dcs = Some((self.inter.clone(), b));
                    self.s = S::DcsPass;
                } else if (0x20..=0x2f).contains(&b) {
                    self.inter.push(b);
                    self.s = S::DcsInter;
                } else if (0x30..=0x3f).contains(&b) {
                    if self.s == S::DcsInter {
                        self.s = S::DcsIgnore;
                    } else {
                        self.params.push(b);
                        self.s = S::DcsParam;
                    }
                }
            }
            S::DcsPass => {}
            S::Osc => {
                if c == 0x07 {
                    self.actions
                        .push(Action::Osc(std::mem::take(&mut self.data)));
                    self.enter(S::Ground);
                } else if !c0 {
                    self.data.push(b);
                }
            }
            S::SosPmApc => {}
        }
    }
}

/// A number as written, and as a terminal wrapping it at 16 or 32 bits
/// reads it.
fn readings(digits: &[u8]) -> Vec<u128> {
    let d: Vec<u8> = digits.iter().copied().filter(u8::is_ascii_digit).collect();
    let d = &d[d.len().saturating_sub(36)..];
    let n = std::str::from_utf8(d)
        .ok()
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(0);
    vec![n, n % 65536, n % (1 << 32)]
}

fn first_param(params: &[u8]) -> Vec<u128> {
    let p: Vec<u8> = params
        .iter()
        .copied()
        .skip_while(|b| matches!(b, b'<' | b'=' | b'>' | b'?'))
        .take_while(|b| *b != b';' && *b != b':')
        .collect();
    readings(&p)
}

/// Why an action reaches past the terminal, if it does.
fn danger(a: &Action, relay: bool) -> Option<&'static str> {
    match a {
        Action::Execute(c) if (0x80..=0x9f).contains(c) => Some("8-bit control"),
        Action::Execute(0x05) if !relay => Some("answerback request"),
        Action::Execute(_) => None,
        Action::Esc(inter, fin) => match (inter.as_slice(), *fin) {
            ([b' '], b'F' | b'G') => Some("8-bit controls switched on"),
            ([b'%'], _) => Some("UTF-8 switched off"),
            ([], b'Z') if !relay => Some("identification request"),
            _ => None,
        },
        Action::Csi(params, inter, fin) => {
            let first = first_param(params);
            let private = params.first().copied();
            if *fin == b't' && first.iter().any(|n| *n == 20 || *n == 21) {
                return Some("title report");
            }
            if relay {
                return None;
            }
            let ask = matches!(fin, b'n' | b'c')
                || (*fin == b'p' && inter.contains(&b'$'))
                || (*fin == b'u' && private == Some(b'?'))
                || (*fin == b'q' && private == Some(b'>'))
                || (*fin == b't' && first.iter().any(|n| (11..=19).contains(n)));
            ask.then_some("a request answered into the shell")
        }
        Action::Osc(data) => {
            let num: Vec<u8> = data
                .iter()
                .copied()
                .take_while(u8::is_ascii_digit)
                .collect();
            if num.is_empty() {
                return Some("an OSC without a number");
            }
            let rest = &data[num.len()..];
            for n in readings(&num) {
                let ok = matches!(n, 0..=2 | 4 | 8 | 10..=19 | 104 | 110..=119 | 133);
                if !ok {
                    return Some("an OSC code off the allow-list");
                }
                let colour = matches!(n, 4 | 10..=19 | 104 | 110..=119);
                if colour && !relay && rest.contains(&b'?') {
                    return Some("a colour request answered into the shell");
                }
            }
            None
        }
        Action::Dcs(inter, fin) => {
            let known = *fin == b'q' && matches!(inter.as_slice(), [b'+'] | [b'$']);
            (!(relay && known)).then_some("a device control string")
        }
        Action::Other => Some("SOS, PM or APC"),
    }
}

const PIECES: &[&[u8]] = &[
    b"\x1b",
    b"\x1b\x1b",
    b"[",
    b"]",
    b"P",
    b"_",
    b"^",
    b"X",
    b"\\",
    b"\x07",
    b"\x18",
    b"\x1a",
    b"\x00",
    b"\x7f",
    b"52",
    b"5522",
    b"21",
    b"20",
    b"t",
    b";",
    b"0",
    b"1337",
    b"9",
    b":",
    b"?",
    b">",
    b"$",
    b"+q",
    b"tmux;",
    b"c;",
    b"eA==",
    "\u{9b}".as_bytes(),
    "\u{9d}".as_bytes(),
    "\u{9c}".as_bytes(),
    "\u{90}".as_bytes(),
    b"\x9b",
    b"\x9d",
    b"\x9c",
    b"\x90",
    b"\xc2",
    b"\xe2\x82",
    b"a",
    "é".as_bytes(),
    "€".as_bytes(),
    b"\r\n",
    b"m",
    b"q",
    b" ",
    b"%",
    b"G",
    b"n",
    b"6",
    b"999999999999",
    b"4294967317",
    b"65557",
    b"2;title",
    b"8;;http://x",
    b"u",
    b"h",
    b"l",
    b"?2004",
    b"1000",
    b"\x05",
    b"Z",
    b"4;1;?",
    b"11;?",
    b"|",
    b"G",
    b"f=100",
    b"\x1b]",
    b"\x1b[",
    b"\x1bP",
    b"\x1b\\",
];

fn input(rng: &mut Rng) -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..1 + rng.below(40) {
        if rng.below(10) == 0 {
            v.push(rng.next() as u8);
        } else {
            v.extend_from_slice(PIECES[rng.below(PIECES.len())]);
        }
    }
    v
}

/// The input cut into random reads, through one filter.
fn filtered(f: &mut Filter, data: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let n = 1 + rng.below(data.len() - at);
        out.extend(f.filter(&data[at..at + n]));
        at += n;
    }
    out
}

#[test]
fn nothing_past_the_filter_reaches_past_the_terminal() {
    let iters: usize = std::env::var("SAM_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20000);
    let seed: u64 = std::env::var("SAM_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut rng = Rng(0x5a17_7e2d_1f00_d00d ^ seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    for round in 0..iters {
        let data = input(&mut rng);
        for relay in [false, true] {
            let new = || {
                if relay {
                    Filter::for_relay()
                } else {
                    Filter::for_pipe()
                }
            };
            let mut f = new();
            let mut out = filtered(&mut f, &data, &mut rng);
            let body = out.clone();
            out.extend(f.finish());
            for a in Model::read(&out) {
                if let Some(why) = danger(&a, relay) {
                    panic!(
                        "round {round}, relay {relay}: {why} ({a:?}) passed\n input {data:?}\n output {out:?}"
                    );
                }
            }
            // Only whole, allowed pieces came out.
            let mut again = new();
            assert_eq!(
                again.filter(&body),
                body,
                "round {round}, relay {relay}: the output changes when filtered again\n input {data:?}"
            );
            assert!(
                again.blocked.is_empty(),
                "round {round}: {:?}",
                again.blocked
            );
        }
        // Two streams, filtered apart, mixed on the same terminal.
        let other = input(&mut rng);
        let (mut a, mut b) = (Filter::for_pipe(), Filter::for_pipe());
        let mut mixed = Vec::new();
        let (mut i, mut j) = (0, 0);
        while i < data.len() || j < other.len() {
            if i < data.len() && (j >= other.len() || rng.below(2) == 0) {
                let n = 1 + rng.below(data.len() - i);
                mixed.extend(a.filter(&data[i..i + n]));
                i += n;
            } else {
                let n = 1 + rng.below(other.len() - j);
                mixed.extend(b.filter(&other[j..j + n]));
                j += n;
            }
        }
        mixed.extend(a.finish());
        mixed.extend(b.finish());
        for act in Model::read(&mixed) {
            if let Some(why) = danger(&act, false) {
                panic!("round {round}, two streams: {why} ({act:?})\n {data:?}\n {other:?}");
            }
        }
    }
}

/// The model itself finds what it should: each known way past a filter,
/// read without SAM's filter, counts as dangerous (so a passing fuzz run
/// means something).
#[test]
fn the_model_recognizes_the_known_attacks() {
    for (code, relay) in [
        (&b"\x1b]52;c;eA==\x07"[..], true),
        (b"\x1b\x1b]52;c;x\x07", true),
        (b"\x1b[\x1b]52;c;x\x07", true),
        (b"\x1b[21;0t", true),
        (b"\x1b[4294967317t", true),
        ("\u{9b}21t".as_bytes(), true),
        (b"\x1bPtmux;\x1b\x1b]52;c;x\x07\x1b\\", true),
        (b"\x1bP0;1|17/72\x1b\\", true),
        (b"\x1b_Gf=100\x1b\\", true),
        (b"\x1b G", true),
        (b"\x1b]52;c;x\x1b[31m", true),
        (b"\x1b[6n", false),
        (b"\x05", false),
    ] {
        assert!(
            Model::read(code).iter().any(|a| danger(a, relay).is_some()),
            "{code:?} not recognized"
        );
    }
}
