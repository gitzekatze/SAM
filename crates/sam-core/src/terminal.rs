// SPDX-License-Identifier: GPL-3.0-or-later
//! Terminal output: one parser, and the filter built on it.
//!
//! [`Parser`] cuts a byte stream into whole pieces the way a terminal reads
//! it (ECMA-48 and the DEC parser): text, single control characters and
//! escape sequences. Where terminals differ it is cautious: a sequence
//! broken by another control character, an over-long one, invalid UTF-8,
//! or the UTF-8 form of an 8-bit control code (U+0080 to U+009F, which some
//! terminals act on) is [`Piece::Malformed`], never text.
//!
//! [`Filter`] passes on only pieces from its allow-list of known, harmless
//! sequences; everything else is removed and named in `blocked`. Before,
//! a filter removed what it recognized as harmful and passed the rest, and
//! a doubled escape, an escape inside a sequence or an extra parameter
//! slipped a clipboard code or a title report past it (audit L-F1).
//! [`PlainText`] keeps only the text, for logs.

use std::collections::BTreeSet;

/// The longest control sequence (parameters and intermediates) taken as
/// valid. Real ones are far shorter.
pub const MAX_SEQUENCE: usize = 64;
/// The longest string sequence (a title, a link) taken as valid.
pub const MAX_STRING: usize = 4096;

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1a;

/// One piece of terminal output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece {
    /// Printable text (valid UTF-8, no control characters).
    Text(String),
    /// One control character other than ESC (0x00–0x1F, 0x7F).
    Control(u8),
    /// ESC, intermediate bytes, a final byte (`ESC ( B`, `ESC 7`).
    Esc { inter: Vec<u8>, fin: u8 },
    /// ESC [ parameters, intermediates, a final byte.
    Csi {
        params: Vec<u8>,
        inter: Vec<u8>,
        fin: u8,
    },
    /// ESC ] … ended by BEL (`st` false) or ESC \ (`st` true).
    Osc { data: Vec<u8>, st: bool },
    /// ESC P (device control), ESC _ (application), ESC ^ (privacy
    /// message) or ESC X (string), ended by ESC \.
    Str { kind: u8, data: Vec<u8> },
    /// Something a terminal could read in more than one way.
    Malformed,
}

impl Piece {
    /// The bytes of a well-formed piece, as they came in.
    pub fn bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        match self {
            Piece::Text(t) => v.extend_from_slice(t.as_bytes()),
            Piece::Control(b) => v.push(*b),
            Piece::Esc { inter, fin } => {
                v.push(ESC);
                v.extend_from_slice(inter);
                v.push(*fin);
            }
            Piece::Csi { params, inter, fin } => {
                v.extend_from_slice(b"\x1b[");
                v.extend_from_slice(params);
                v.extend_from_slice(inter);
                v.push(*fin);
            }
            Piece::Osc { data, st } => {
                v.extend_from_slice(b"\x1b]");
                v.extend_from_slice(data);
                v.extend_from_slice(if *st { b"\x1b\\" } else { b"\x07" });
            }
            Piece::Str { kind, data } => {
                v.extend_from_slice(&[ESC, *kind]);
                v.extend_from_slice(data);
                v.extend_from_slice(b"\x1b\\");
            }
            Piece::Malformed => {}
        }
        v
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum State {
    #[default]
    Ground,
    Esc,
    Csi,
    Str,
}

/// Cuts terminal output into [`Piece`]s. Pieces may be split across calls.
#[derive(Debug, Default)]
pub struct Parser {
    state: State,
    /// Intermediates (ESC), parameters (CSI) or the content (strings).
    a: Vec<u8>,
    /// Intermediates of a CSI.
    b: Vec<u8>,
    /// The kind of a string sequence (`]`, `P`, `_`, `^`, `X`).
    kind: u8,
    /// In a string: the last byte was ESC.
    esc: bool,
    /// The sequence is malformed; it is still read to its end.
    bad: bool,
    text: String,
    /// The start of a UTF-8 character split across calls.
    utf8: Vec<u8>,
    need: usize,
}

impl Parser {
    pub fn feed(&mut self, data: &[u8], out: &mut Vec<Piece>) {
        for &b in data {
            self.byte(b, out);
        }
        self.flush_text(out);
    }

    /// The end of the stream: an unfinished piece is malformed. (`feed`
    /// has passed on all text already.)
    pub fn finish(&mut self, out: &mut Vec<Piece>) {
        if self.state != State::Ground || self.need > 0 {
            out.push(Piece::Malformed);
        }
        *self = Parser::default();
    }

    fn flush_text(&mut self, out: &mut Vec<Piece>) {
        if !self.text.is_empty() {
            out.push(Piece::Text(std::mem::take(&mut self.text)));
        }
    }

    fn start(&mut self, state: State) {
        self.state = state;
        self.a.clear();
        self.b.clear();
        self.esc = false;
        self.bad = false;
    }

    fn byte(&mut self, b: u8, out: &mut Vec<Piece>) {
        match self.state {
            State::Ground => self.ground(b, out),
            State::Esc => match b {
                0x20..=0x2f => {
                    if self.a.len() < MAX_SEQUENCE {
                        self.a.push(b);
                    } else {
                        self.bad = true;
                    }
                }
                0x30..=0x7e => {
                    if self.a.is_empty() && matches!(b, b'[' | b']' | b'P' | b'_' | b'^' | b'X') {
                        let kind = b;
                        if kind == b'[' {
                            self.start(State::Csi);
                        } else {
                            self.start(State::Str);
                            self.kind = kind;
                        }
                    } else {
                        out.push(if self.bad {
                            Piece::Malformed
                        } else {
                            Piece::Esc {
                                inter: std::mem::take(&mut self.a),
                                fin: b,
                            }
                        });
                        self.start(State::Ground);
                    }
                }
                // Anything else ends it unfinished and is read anew: a
                // doubled ESC starts again (the first one is dropped), CAN
                // and SUB cancel, other controls act.
                _ => {
                    out.push(Piece::Malformed);
                    self.start(State::Ground);
                    self.ground(b, out);
                }
            },
            State::Csi => match b {
                0x30..=0x3f => {
                    if !self.b.is_empty() || self.a.len() >= MAX_SEQUENCE {
                        self.bad = true;
                    } else {
                        self.a.push(b);
                    }
                }
                0x20..=0x2f => {
                    if self.b.len() >= MAX_SEQUENCE {
                        self.bad = true;
                    } else {
                        self.b.push(b);
                    }
                }
                0x40..=0x7e => {
                    out.push(if self.bad {
                        Piece::Malformed
                    } else {
                        Piece::Csi {
                            params: std::mem::take(&mut self.a),
                            inter: std::mem::take(&mut self.b),
                            fin: b,
                        }
                    });
                    self.start(State::Ground);
                }
                // Anything else ends it unfinished, as in terminals, and is
                // read anew (an ESC starts a new sequence).
                _ => {
                    out.push(Piece::Malformed);
                    self.start(State::Ground);
                    self.ground(b, out);
                }
            },
            State::Str => {
                if self.esc {
                    if b == b'\\' {
                        out.push(self.string_piece(true));
                        self.start(State::Ground);
                    } else if b == ESC && self.kind == b'P' && self.a.starts_with(b"tmux;") {
                        // tmux passthrough doubles each ESC it carries:
                        // kept as content, so it is named as what it is.
                        self.esc = false;
                        self.keep(ESC);
                    } else {
                        // ESC without \ ends the string unfinished and
                        // starts a new sequence.
                        out.push(Piece::Malformed);
                        self.start(State::Esc);
                        self.byte(b, out);
                    }
                    return;
                }
                match b {
                    ESC => self.esc = true,
                    BEL if self.kind == b']' => {
                        out.push(self.string_piece(false));
                        self.start(State::Ground);
                    }
                    CAN | SUB => {
                        out.push(Piece::Malformed);
                        self.start(State::Ground);
                    }
                    // Kept and judged when the string ends (other control
                    // characters are allowed only in tmux passthrough).
                    _ => self.keep(b),
                }
            }
        }
    }

    /// Content of a string sequence, up to its limit.
    fn keep(&mut self, b: u8) {
        if self.a.len() < MAX_STRING {
            self.a.push(b);
        } else {
            self.bad = true;
        }
    }

    /// A finished string sequence: its content must be text a terminal
    /// reads one way only.
    fn string_piece(&mut self, st: bool) -> Piece {
        let data = std::mem::take(&mut self.a);
        let clean = std::str::from_utf8(&data)
            .is_ok_and(|s| !s.chars().any(|c| ('\u{80}'..='\u{9f}').contains(&c)))
            && (self.kind == b'P' && data.starts_with(b"tmux;")
                || !data.iter().any(|b| *b < 0x20 || *b == 0x7f));
        if self.bad || !clean {
            return Piece::Malformed;
        }
        if self.kind == b']' {
            Piece::Osc { data, st }
        } else {
            Piece::Str {
                kind: self.kind,
                data,
            }
        }
    }

    fn ground(&mut self, b: u8, out: &mut Vec<Piece>) {
        if self.need > 0 {
            if (0x80..=0xbf).contains(&b) {
                self.utf8.push(b);
                self.need -= 1;
                if self.need == 0 {
                    let bytes = std::mem::take(&mut self.utf8);
                    match std::str::from_utf8(&bytes)
                        .ok()
                        .and_then(|s| s.chars().next())
                    {
                        Some(c) if !('\u{80}'..='\u{9f}').contains(&c) => self.text.push(c),
                        _ => {
                            self.flush_text(out);
                            out.push(Piece::Malformed);
                        }
                    }
                }
                return;
            }
            // A character cut short.
            self.utf8.clear();
            self.need = 0;
            self.flush_text(out);
            out.push(Piece::Malformed);
        }
        match b {
            ESC => {
                self.flush_text(out);
                self.start(State::Esc);
            }
            0x00..=0x1f | 0x7f => {
                self.flush_text(out);
                out.push(Piece::Control(b));
            }
            0x20..=0x7e => self.text.push(b as char),
            0xc2..=0xf4 => {
                self.utf8.clear();
                self.utf8.push(b);
                self.need = match b {
                    0xc2..=0xdf => 1,
                    0xe0..=0xef => 2,
                    _ => 3,
                };
            }
            _ => {
                self.flush_text(out);
                out.push(Piece::Malformed);
            }
        }
    }
}

/// The parameters of a control sequence: an optional private marker
/// (`<`, `=`, `>`, `?`) and numbers separated by `;` or `:`. `None` when
/// they are malformed or a number is larger than any real one.
pub fn numbers(params: &[u8]) -> Option<(Option<u8>, Vec<u32>)> {
    let (mark, rest) = match params.first() {
        Some(m @ (b'<' | b'=' | b'>' | b'?')) => (Some(*m), &params[1..]),
        _ => (None, params),
    };
    let mut nums = Vec::new();
    if rest.is_empty() {
        return Some((mark, nums));
    }
    for part in rest.split(|b| *b == b';' || *b == b':') {
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        // By value: terminals read "00021" as 21.
        let digits = std::str::from_utf8(part).ok()?.trim_start_matches('0');
        if digits.len() > 5 {
            return None;
        }
        let n: u32 = if digits.is_empty() {
            0
        } else {
            digits.parse().ok()?
        };
        if n > 65535 {
            return None;
        }
        nums.push(n);
    }
    Some((mark, nums))
}

/// Terminal modes an app may switch on that change how the terminal
/// behaves for the shell afterwards: SAM switches them off when the app
/// ends (audit L-F11). 25 is the cursor, which is shown again.
const RESET_MODES: &[u32] = &[
    25, 47, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1015, 1016, 1047, 1049, 2004,
];

enum Verdict {
    Pass,
    /// A request the terminal answers by sending bytes to the input.
    Query,
    Block(&'static str),
}

/// Passes on only well-formed, known harmless pieces of terminal output.
/// Sequences may be split across calls.
#[derive(Debug)]
pub struct Filter {
    parser: Parser,
    /// Requests the terminal answers pass (on SAM's terminal relay, where
    /// the answer goes to the app). Without the relay the answer would land
    /// in the shell: they are removed.
    queries: bool,
    /// What was removed, for the launch log.
    pub blocked: BTreeSet<&'static str>,
    modes: BTreeSet<u32>,
    keyboard_pushes: u32,
    styled: bool,
}

impl Filter {
    /// For SAM's terminal relay: the terminal's answers go to the app.
    pub fn for_relay() -> Filter {
        Filter {
            queries: true,
            ..Filter::for_pipe()
        }
    }

    /// For output shown in a terminal without the relay: the terminal's
    /// answers would reach the shell, so requests are removed too.
    pub fn for_pipe() -> Filter {
        Filter {
            parser: Parser::default(),
            queries: false,
            blocked: BTreeSet::new(),
            modes: BTreeSet::new(),
            keyboard_pushes: 0,
            styled: false,
        }
    }

    pub fn filter(&mut self, data: &[u8]) -> Vec<u8> {
        let mut pieces = Vec::new();
        self.parser.feed(data, &mut pieces);
        self.emit(pieces)
    }

    /// The end of the output: an unfinished sequence is removed, and modes
    /// the app left on that would change the shell's terminal are switched
    /// off (mouse reporting, bracketed paste, the alternate screen, a
    /// hidden cursor, colours, keyboard modes).
    pub fn finish(&mut self) -> Vec<u8> {
        let mut pieces = Vec::new();
        self.parser.finish(&mut pieces);
        let mut out = self.emit(pieces);
        for m in std::mem::take(&mut self.modes) {
            if m == 25 {
                out.extend_from_slice(b"\x1b[?25h");
            } else {
                out.extend_from_slice(format!("\x1b[?{m}l").as_bytes());
            }
        }
        if self.keyboard_pushes > 0 {
            out.extend_from_slice(format!("\x1b[<{}u", self.keyboard_pushes).as_bytes());
            self.keyboard_pushes = 0;
        }
        if std::mem::take(&mut self.styled) {
            out.extend_from_slice(b"\x1b[0m");
        }
        out
    }

    fn emit(&mut self, pieces: Vec<Piece>) -> Vec<u8> {
        let mut out = Vec::new();
        for p in pieces {
            let verdict = self.judge(&p);
            match verdict {
                Verdict::Pass => out.extend(p.bytes()),
                Verdict::Query if self.queries => out.extend(p.bytes()),
                Verdict::Query => {
                    self.blocked.insert("terminal queries");
                }
                Verdict::Block(why) => {
                    self.blocked.insert(why);
                }
            }
        }
        out
    }

    fn judge(&mut self, p: &Piece) -> Verdict {
        match p {
            Piece::Text(_) => Verdict::Pass,
            Piece::Control(b) => match b {
                0x07..=0x0f => Verdict::Pass,
                // ENQ: the terminal answers with its answerback text.
                0x05 => Verdict::Query,
                _ => Verdict::Block("control characters"),
            },
            Piece::Esc { inter, fin } => match (inter.as_slice(), *fin) {
                (
                    [],
                    b'7' | b'8' | b'=' | b'>' | b'D' | b'E' | b'H' | b'M' | b'N' | b'O' | b'c',
                ) => Verdict::Pass,
                // Terminal identification: answered.
                ([], b'Z') => Verdict::Query,
                // Character sets (line drawing).
                ([b'(' | b')' | b'*' | b'+' | b'-' | b'.' | b'/'], _) => Verdict::Pass,
                // Double-width and double-height lines.
                ([b'#'], b'3'..=b'8') => Verdict::Pass,
                // Among others: 8-bit control codes on (ESC SP G) and
                // leaving UTF-8 (ESC % @), after which 8-bit codes count.
                _ => Verdict::Block("unknown control codes"),
            },
            Piece::Csi { params, inter, fin } => self.judge_csi(params, inter, *fin),
            Piece::Osc { data, .. } => judge_osc(data),
            Piece::Str { kind, data } => match kind {
                b'P' if data.starts_with(b"tmux;") => Verdict::Block("tmux passthrough"),
                // Terminal capabilities and settings: answered.
                b'P' if data.starts_with(b"+q") || data.starts_with(b"$q") => Verdict::Query,
                b'P' => Verdict::Block("device control strings (programmable keys, graphics)"),
                b'_' if data.starts_with(b"G") => Verdict::Block("kitty graphics"),
                _ => Verdict::Block("unknown control codes"),
            },
            Piece::Malformed => Verdict::Block("malformed control codes"),
        }
    }

    fn judge_csi(&mut self, params: &[u8], inter: &[u8], fin: u8) -> Verdict {
        let Some((mark, nums)) = numbers(params) else {
            return Verdict::Block("malformed control codes");
        };
        let first = nums.first().copied().unwrap_or(0);
        match (mark, inter, fin) {
            // Cursor, editing, scrolling, tabs, margins, colours.
            (
                None,
                [],
                b'@'
                | b'A'..=b'H'
                | b'I'
                | b'J'
                | b'K'
                | b'L'
                | b'M'
                | b'P'
                | b'S'
                | b'T'
                | b'X'
                | b'Z'
                | b'`'
                | b'a'
                | b'b'
                | b'd'
                | b'e'
                | b'f'
                | b'g'
                | b'r'
                | b's'
                | b'u',
            ) => Verdict::Pass,
            (None, [], b'm') => {
                self.styled = true;
                Verdict::Pass
            }
            (Some(b'>'), [], b'm') | (Some(b'?'), [], b'J' | b'K') => Verdict::Pass,
            (None | Some(b'?'), [], b'h' | b'l') => {
                if mark == Some(b'?') {
                    for n in nums.iter().filter(|n| RESET_MODES.contains(n)) {
                        // On means: switched on (25: cursor hidden).
                        let on = (fin == b'h') != (*n == 25);
                        if on {
                            self.modes.insert(*n);
                        } else {
                            self.modes.remove(n);
                        }
                    }
                }
                Verdict::Pass
            }
            // Keyboard modes (kitty): set, push, pop.
            (Some(b'='), [], b'u') => Verdict::Pass,
            (Some(b'>'), [], b'u') => {
                self.keyboard_pushes = self.keyboard_pushes.saturating_add(1).min(64);
                Verdict::Pass
            }
            (Some(b'<'), [], b'u') => {
                self.keyboard_pushes = self.keyboard_pushes.saturating_sub(first.max(1));
                Verdict::Pass
            }
            // Cursor shape, soft reset.
            (None, [b' '], b'q') | (None, [b'!'], b'p') => Verdict::Pass,
            // Answered with numbers or the terminal's own name: status
            // and cursor position, device attributes, modes, keyboard
            // flags, version.
            (None | Some(b'?'), [], b'n')
            | (None | Some(b'>') | Some(b'='), [], b'c')
            | (None | Some(b'?'), [b'$'], b'p')
            | (Some(b'?'), [], b'u')
            | (Some(b'>'), [], b'q') => Verdict::Query,
            (None, [], b't') => match first {
                // The title stack, the size of the text area.
                8 | 22 | 23 => Verdict::Pass,
                // Sizes, answered with numbers.
                14 | 16 | 18 | 19 => Verdict::Query,
                // The window title or icon label, "typed" back.
                20 | 21 => Verdict::Block("title reports"),
                _ => Verdict::Block("window operations"),
            },
            _ => Verdict::Block("unknown control codes"),
        }
    }
}

fn judge_osc(data: &[u8]) -> Verdict {
    let num = data.split(|b| *b == b';').next().unwrap_or_default();
    let Some((None, n)) = numbers(num) else {
        return Verdict::Block("malformed control codes");
    };
    if n.len() != 1 {
        return Verdict::Block("malformed control codes");
    }
    match n[0] {
        // Window title and icon label (asking for them back is removed).
        0..=2 => Verdict::Pass,
        // Colours; "?" asks for one, answered with numbers.
        4 | 10..=19 | 104 | 110..=119 => {
            if data.contains(&b'?') {
                Verdict::Query
            } else {
                Verdict::Pass
            }
        }
        // Links, prompt marks.
        8 | 133 => Verdict::Pass,
        52 | 5522 => Verdict::Block("clipboard"),
        1337 => Verdict::Block("terminal extensions (iTerm2/WezTerm: clipboard, files)"),
        9 | 99 | 777 => Verdict::Block("desktop notifications"),
        50 => Verdict::Block("fonts"),
        7 => Verdict::Block("working folder"),
        5113 => Verdict::Block("file transfer"),
        _ => Verdict::Block("unknown control codes"),
    }
}

/// The text of terminal output, for logs: escape sequences and control
/// characters removed, line breaks and tabs kept. Sequences may be split
/// across calls.
#[derive(Debug, Default)]
pub struct PlainText {
    parser: Parser,
}

impl PlainText {
    pub fn feed(&mut self, data: &[u8]) -> String {
        let mut pieces = Vec::new();
        self.parser.feed(data, &mut pieces);
        text_of(pieces)
    }
}

fn text_of(pieces: Vec<Piece>) -> String {
    let mut s = String::new();
    for p in pieces {
        match p {
            Piece::Text(t) => s.push_str(&t),
            Piece::Control(b'\n') => s.push('\n'),
            Piece::Control(b'\t') => s.push('\t'),
            _ => {}
        }
    }
    s
}

/// [`PlainText`] for a whole piece of output at once.
pub fn plain_text(data: &[u8]) -> String {
    PlainText::default().feed(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pipe(data: &[u8]) -> (Vec<u8>, Filter) {
        let mut f = Filter::for_pipe();
        let mut out = f.filter(data);
        out.extend(f.finish());
        (out, f)
    }

    fn has(out: &[u8], needle: &[u8]) -> bool {
        out.windows(needle.len()).any(|w| w == needle)
    }

    /// Each way past the old filter that the audit found (L-F1 a–h): none
    /// of them brings a clipboard code or a title report to the terminal.
    #[test]
    fn the_known_ways_past_the_old_filter_are_closed() {
        // (a) A doubled ESC: the old filter sent one ESC on and stayed in
        // the escape state, so the next code was clean.
        let (out, _) = pipe(b"\x1b\x1b]52;c;x\x07]52;c;ZGF0YQ==\x07");
        assert!(!has(&out, b"\x1b]"), "{out:?}");
        // (b) An ESC inside a control sequence starts a new one.
        let (out, f) = pipe(b"\x1b[\x1b]52;c;ZGF0YQ==\x07");
        assert!(!has(&out, b"\x1b"), "{out:?}");
        assert!(f.blocked.contains("clipboard"));
        // (c) Extra parameters: terminals use the first one.
        let (out, f) = pipe(b"\x1b[21;0t\x1b[20;5;5t");
        assert!(out.is_empty(), "{out:?}");
        assert!(f.blocked.contains("title reports"));
        // (d) NUL or DEL inside a sequence.
        let (out, _) = pipe(b"\x1b]52;c;x\x00y\x07\x1b[2\x7f1t");
        assert!(!has(&out, b"\x1b"), "{out:?}");
        // (e) A sequence longer than the limit is removed whole, never
        // passed on half.
        let mut long = b"\x1b[".to_vec();
        long.extend(std::iter::repeat_n(b'1', 300));
        long.extend_from_slice(b";21t");
        let (out, _) = pipe(&long);
        assert!(out.is_empty(), "{} bytes passed", out.len());
        // (f) A number past 32 bits (2^32 + 21) does not wrap to 21, and
        // is not passed on either.
        let (out, _) = pipe(b"\x1b[4294967317t");
        assert!(out.is_empty(), "{out:?}");
        // (g) The UTF-8 form of an 8-bit CSI (U+009B), and the raw byte.
        let (out, _) = pipe("\u{9b}21t".as_bytes());
        assert!(!has(&out, &[0xc2, 0x9b]), "{out:?}");
        let (out, _) = pipe(b"\x9b21t\x9d52;c;x\x07");
        assert!(!out.iter().any(|b| (0x80..=0x9f).contains(b)), "{out:?}");
        // (h) One code split over two streams: each stream's filter keeps
        // an unfinished piece to itself, so nothing reaches the terminal.
        let (mut stdout, mut stderr) = (Filter::for_pipe(), Filter::for_pipe());
        let mut seen = stdout.filter(b"a\x1b");
        seen.extend(stderr.filter(b"]52;c;ZGF0YQ==\x07"));
        seen.extend(stdout.finish());
        assert!(!has(&seen, b"\x1b]"), "{seen:?}");
    }

    /// Ordinary output passes unchanged, also split at every point.
    #[test]
    fn ordinary_output_passes_unchanged_at_every_split() {
        let s = "plain é ✓ text\r\n\x1b[1;31mred\x1b[0m \x1b[2J\x1b[H\x1b(0q\x1b(B\x1b]0;título\x07\x1b]8;;https://x\x1b\\link\x1b]8;;\x1b\\\t€".as_bytes();
        for cut in 0..=s.len() {
            let mut f = Filter::for_pipe();
            let mut out = f.filter(&s[..cut]);
            out.extend(f.filter(&s[cut..]));
            assert!(f.blocked.is_empty(), "cut at {cut}: {:?}", f.blocked);
            assert!(out.starts_with(s) || out == s, "cut at {cut}");
        }
    }

    /// Requests the terminal answers pass only on SAM's relay, where the
    /// answer goes to the app; without it the answer would land in the
    /// shell.
    #[test]
    fn requests_pass_only_on_the_relay() {
        let asks: &[&[u8]] = &[
            b"\x1b[6n",
            b"\x1b[c",
            b"\x1b[>c",
            b"\x1b[?2004$p",
            b"\x1b[?u",
            b"\x1b[>q",
            b"\x1b[18t",
            b"\x1b]11;?\x07",
            b"\x1bP+q544e\x1b\\",
            b"\x05",
            b"\x1bZ",
        ];
        for ask in asks {
            let mut relay = Filter::for_relay();
            assert_eq!(relay.filter(ask), ask.to_vec(), "{ask:?} on the relay");
            let (out, f) = pipe(ask);
            assert!(out.is_empty(), "{ask:?} without the relay: {out:?}");
            assert!(f.blocked.contains("terminal queries"));
        }
    }

    /// What reaches past the terminal or changes it for good is removed;
    /// unknown codes are removed too (an allow-list).
    #[test]
    fn what_reaches_past_the_terminal_is_removed() {
        for (code, why) in [
            (&b"\x1b]52;c;eA==\x07"[..], "clipboard"),
            (b"\x1b]5522;type=write\x07", "clipboard"),
            (
                b"\x1b]1337;File=x\x07",
                "terminal extensions (iTerm2/WezTerm: clipboard, files)",
            ),
            (b"\x1b]9;hi\x07", "desktop notifications"),
            (b"\x1b]50;?\x07", "fonts"),
            (b"\x1b]7;file:///etc\x07", "working folder"),
            (b"\x1b]5113;ac=send\x07", "file transfer"),
            (b"\x1b_Gf=100,t=f;L2V0Yy9zaGFkb3c=\x1b\\", "kitty graphics"),
            (
                b"\x1bP0;1|17/726d\x1b\\",
                "device control strings (programmable keys, graphics)",
            ),
            (b"\x1b G", "unknown control codes"),
            (b"\x1b%@", "unknown control codes"),
            (b"\x1b[4i", "unknown control codes"),
            (b"\x1b]4242;x\x07", "unknown control codes"),
            (b"\x00", "control characters"),
        ] {
            let (out, f) = pipe(code);
            assert!(out.is_empty(), "{code:?}: {out:?}");
            assert!(f.blocked.contains(why), "{code:?}: {:?}", f.blocked);
        }
    }

    /// Modes the app switched on that would stay on for the shell are
    /// switched off at the end (audit L-F11: mouse reporting and bracketed
    /// paste stayed on); nothing is added for an app that set none.
    #[test]
    fn modes_left_on_are_switched_off_at_the_end() {
        let mut f = Filter::for_relay();
        f.filter(b"\x1b[?1000;1006h\x1b[?2004h\x1b[?25l\x1b[>1u\x1b[31m\x1b[?1006l");
        let end = String::from_utf8(f.finish()).unwrap();
        for want in [
            "\x1b[?1000l",
            "\x1b[?2004l",
            "\x1b[?25h",
            "\x1b[<1u",
            "\x1b[0m",
        ] {
            assert!(end.contains(want), "{want:?} in {end:?}");
        }
        assert!(!end.contains("1006"), "switched off by the app itself");
        let mut quiet = Filter::for_relay();
        quiet.filter(b"just text\n");
        assert!(quiet.finish().is_empty());
    }

    /// The log keeps only the text, also when a sequence is split across
    /// reads (the old one was cut per read and could keep half a code).
    #[test]
    fn the_log_keeps_only_text_across_reads() {
        let s = b"a\x1b]0;title\x07b\x1b[31mc\r\n\td\x1b]52;c;x\x07e";
        for cut in 0..=s.len() {
            let mut p = PlainText::default();
            let mut t = p.feed(&s[..cut]);
            t.push_str(&p.feed(&s[cut..]));
            assert_eq!(t, "abc\n\tde", "cut at {cut}");
        }
    }

    fn pieces(data: &[u8]) -> Vec<Piece> {
        let mut p = Parser::default();
        let mut out = Vec::new();
        p.feed(data, &mut out);
        p.finish(&mut out);
        out
    }

    /// A piece still unfinished when the output ends is removed and named.
    #[test]
    fn unfinished_pieces_are_named_at_the_end() {
        for tail in [&b"\x1b[3"[..], b"\x1b", b"\x1b]0;t", b"\xc3"] {
            let mut f = Filter::for_pipe();
            let mut data = b"a".to_vec();
            data.extend_from_slice(tail);
            assert_eq!(f.filter(&data), b"a");
            assert!(f.finish().is_empty(), "{tail:?}");
            assert!(f.blocked.contains("malformed control codes"), "{tail:?}");
        }
    }

    /// Every kind of harmless sequence on the allow-list passes unchanged,
    /// also without the relay.
    #[test]
    fn the_allowed_kinds_pass_unchanged() {
        for code in [
            &b"\x1b7"[..],
            b"\x1b8",
            b"\x1b=",
            b"\x1b>",
            b"\x1bD",
            b"\x1bE",
            b"\x1bH",
            b"\x1bM",
            b"\x1bN",
            b"\x1bO",
            b"\x1bc",
            b"\x1b#8",
            b"\x1b(0",
            b"\x1b)B",
            b"\x1b[>4;1m",
            b"\x1b[?2J",
            b"\x1b[?1K",
            b"\x1b[=1u",
            b"\x1b[>1u",
            b"\x1b[<1u",
            b"\x1b[2 q",
            b"\x1b[!p",
            b"\x1b[8;24;80t",
            b"\x1b[22;0t",
            b"\x1b[23;0t",
            b"\x1b[1;24r",
            b"\x1b[s",
            b"\x1b[u",
            b"\x1b[5@",
            b"\x1b[3X",
            b"\x1b[?25l",
            b"\x1b[38:2:1:2:3m",
            b"\x07",
            b"\x08",
            b"\x0e",
            b"\x0f",
            b"\x1b]4;1;rgb:ff/00/00\x07",
            b"\x1b]133;A\x07",
            b"\x1b]104\x07",
            b"\x1b]1;icon\x1b\\",
        ] {
            let mut f = Filter::for_pipe();
            assert_eq!(f.filter(code), code.to_vec(), "{code:?}");
            assert!(f.blocked.is_empty(), "{code:?}: {:?}", f.blocked);
        }
    }

    /// The limits hold exactly: a sequence at the limit is read, one byte
    /// more makes it malformed; numbers go up to 65535.
    #[test]
    fn limits_hold_at_their_edge() {
        let at = |head: &[u8], fill: u8, n: usize, tail: &[u8]| {
            let mut v = head.to_vec();
            v.extend(std::iter::repeat_n(fill, n));
            v.extend_from_slice(tail);
            pieces(&v)
        };
        let whole = |p: &[Piece]| p.len() == 1 && p[0] != Piece::Malformed;
        assert!(whole(&at(b"\x1b", b'(', MAX_SEQUENCE, b"B")));
        assert!(!whole(&at(b"\x1b", b'(', MAX_SEQUENCE + 1, b"B")));
        assert!(whole(&at(b"\x1b[", b'1', MAX_SEQUENCE, b"m")));
        assert!(!whole(&at(b"\x1b[", b'1', MAX_SEQUENCE + 1, b"m")));
        assert!(whole(&at(b"\x1b[", b' ', MAX_SEQUENCE, b"q")));
        assert!(!whole(&at(b"\x1b[", b' ', MAX_SEQUENCE + 1, b"q")));
        assert!(whole(&at(b"\x1b]0;", b'a', MAX_STRING - 2, b"\x07")));
        assert!(!whole(&at(b"\x1b]0;", b'a', MAX_STRING - 1, b"\x07")));
        assert_eq!(numbers(b"65535"), Some((None, vec![65535])));
        assert_eq!(numbers(b"0000065535"), Some((None, vec![65535])));
        assert_eq!(numbers(b"65536"), None);
        assert_eq!(numbers(b"123456"), None);
        assert_eq!(numbers(b"?1;;2"), Some((Some(b'?'), vec![1, 0, 2])));
        assert_eq!(numbers(b"1?2"), None);
    }

    /// Malformed strings and sequences: a parameter after an intermediate;
    /// BEL ends only title-type strings; control characters, 8-bit
    /// controls and invalid UTF-8 inside a string; an ESC inside a string
    /// starts a new code that is judged on its own.
    #[test]
    fn malformed_pieces_are_recognized() {
        assert_eq!(pieces(b"\x1b[ 1q"), vec![Piece::Malformed]);
        for s in [
            &b"\x1b]0;a\x01b\x07"[..],
            "\x1b]0;\u{9b}\x07".as_bytes(),
            b"\x1b]0;\xff\x07",
            b"\x1bP+q\x07x\x1b\\",
        ] {
            assert_eq!(pieces(s), vec![Piece::Malformed], "{s:?}");
        }
        let mut f = Filter::for_relay();
        assert_eq!(
            f.filter(b"\x1bP+q\x07x\x1b\\y"),
            b"y",
            "BEL ends no device string"
        );
        let (out, f) = pipe(b"\x1b]0;a\x1b\x1b]52;c;x\x07z");
        assert_eq!(out, b"z");
        assert!(f.blocked.contains("clipboard"), "{:?}", f.blocked);
        // A device string broken by a doubled ESC (not tmux): the code
        // after it is read on its own.
        let (out, f) = pipe(b"\x1bP+q\x1b\x1b]52;c;x\x07z");
        assert_eq!(out, b"z");
        assert!(f.blocked.contains("clipboard"), "{:?}", f.blocked);
        let (_, f) = pipe(b"\x1b_Xyz\x1b\\");
        assert!(
            f.blocked.contains("unknown control codes") && !f.blocked.contains("kitty graphics")
        );
    }
}
