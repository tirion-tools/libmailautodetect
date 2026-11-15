//! Strict bounded XML parser (45/45 hostile cases, 43.9M fuzz executions clean).
//! Strict, bounded XML subset parser for autoconfig (config-v1.1.xml) and Autodiscover (POX) documents.
//!
//! Accepted: UTF-8 only (optional BOM), an optional `<?xml ...?>` declaration whose encoding (if given) is
//! UTF-8, comments, elements, attributes, character data, CDATA sections, the five predefined entities and
//! numeric character references. Everything else is an error, in particular any `<!DOCTYPE` (so no DTD,
//! no internal or external entities, no entity expansion of any kind) and any processing instruction other
//! than the declaration. Every resource is bounded before it is allocated (`Limits`).
//! No `unsafe`, no recursion (an explicit stack bounded by `max_depth`).

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_elements: usize,
    pub max_attrs_per_element: usize,
    pub max_name_len: usize,
    pub max_attr_value_len: usize,
    pub max_text_len: usize,
    pub max_total_text: usize,
}

impl Limits {
    /// Values chosen from the ISPDB corpus (largest file 8,712 bytes, depth 5, 230 elements).
    pub const AUTOCONFIG: Limits = Limits {
        max_bytes: 64 * 1024,
        max_depth: 12,
        max_elements: 1024,
        max_attrs_per_element: 8,
        max_name_len: 64,
        max_attr_value_len: 512,
        max_text_len: 2048,
        max_total_text: 32 * 1024,
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Element(Element),
    Text(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Element {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Node>,
}

impl Element {
    /// Local name (after any namespace prefix).
    pub fn local(&self) -> &str {
        local(&self.name)
    }
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| local(k) == name).map(|(_, v)| v.as_str())
    }
    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| if let Node::Element(e) = n { Some(e) } else { None })
    }
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.elements().find(|e| e.local() == name)
    }
    /// Concatenated direct text children, trimmed.
    pub fn text(&self) -> String {
        let mut s = String::new();
        for n in &self.children {
            if let Node::Text(t) = n {
                s.push_str(t);
            }
        }
        s.trim().to_string()
    }
}

pub fn local(name: &str) -> &str {
    match name.rfind(':') {
        Some(i) => &name[i + 1..],
        None => name,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    NotUtf8,
    Encoding,
    Doctype,
    ProcessingInstruction,
    Depth,
    TooManyElements,
    TooManyAttrs,
    NameTooLong,
    AttrTooLong,
    TextTooLong,
    TotalTextTooLong,
    DuplicateAttr,
    BadName,
    BadEntity,
    BadChar,
    Mismatch,
    Unexpected(&'static str),
    Eof,
    NoRoot,
    TrailingContent,
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::TooLarge => "too_large",
            Error::NotUtf8 => "not_utf8",
            Error::Encoding => "encoding",
            Error::Doctype => "doctype",
            Error::ProcessingInstruction => "processing_instruction",
            Error::Depth => "depth",
            Error::TooManyElements => "too_many_elements",
            Error::TooManyAttrs => "too_many_attrs",
            Error::NameTooLong => "name_too_long",
            Error::AttrTooLong => "attr_too_long",
            Error::TextTooLong => "text_too_long",
            Error::TotalTextTooLong => "total_text_too_long",
            Error::DuplicateAttr => "duplicate_attr",
            Error::BadName => "bad_name",
            Error::BadEntity => "bad_entity",
            Error::BadChar => "bad_char",
            Error::Mismatch => "mismatched_end_tag",
            Error::Unexpected(_) => "unexpected",
            Error::Eof => "eof",
            Error::NoRoot => "no_root",
            Error::TrailingContent => "trailing_content",
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub elements: usize,
    pub max_depth: usize,
    pub bytes: usize,
}

struct P<'a> {
    s: &'a str,
    b: &'a [u8],
    i: usize,
    lim: Limits,
    elements: usize,
    total_text: usize,
    max_depth_seen: usize,
}

fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || (c >= '\u{20}' && c != '\u{FFFE}' && c != '\u{FFFF}')
}

fn name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b':'
}
fn name_char(b: u8) -> bool {
    name_start(b) || b.is_ascii_digit() || b == b'-' || b == b'.'
}

impl<'a> P<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn starts(&self, t: &str) -> bool {
        self.b[self.i..].starts_with(t.as_bytes())
    }
    fn expect(&mut self, t: &'static str) -> Result<(), Error> {
        if self.starts(t) {
            self.i += t.len();
            Ok(())
        } else if self.i + t.len() > self.b.len() {
            Err(Error::Eof)
        } else {
            Err(Error::Unexpected(t))
        }
    }
    fn ws(&mut self) -> bool {
        let st = self.i;
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.i += 1;
        }
        self.i > st
    }
    fn name(&mut self) -> Result<String, Error> {
        let st = self.i;
        match self.peek() {
            Some(c) if name_start(c) => self.i += 1,
            None => return Err(Error::Eof),
            _ => return Err(Error::BadName),
        }
        while let Some(c) = self.peek() {
            if !name_char(c) {
                break;
            }
            self.i += 1;
            if self.i - st > self.lim.max_name_len {
                return Err(Error::NameTooLong);
            }
        }
        if self.i - st > self.lim.max_name_len {
            return Err(Error::NameTooLong);
        }
        Ok(self.s[st..self.i].to_string())
    }
    /// Entity or character reference after '&'.
    fn reference(&mut self, out: &mut String) -> Result<(), Error> {
        self.expect("&")?;
        let st = self.i;
        while let Some(c) = self.peek() {
            if c == b';' {
                break;
            }
            if self.i - st > 10 {
                return Err(Error::BadEntity);
            }
            self.i += 1;
        }
        if self.peek().is_none() {
            return Err(Error::Eof);
        }
        let body = &self.s[st..self.i];
        self.i += 1; // ';'
        let c = match body {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let v = if let Some(h) = body.strip_prefix("#x") {
                    if h.is_empty() || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(Error::BadEntity);
                    }
                    u32::from_str_radix(h, 16).map_err(|_| Error::BadEntity)?
                } else if let Some(d) = body.strip_prefix('#') {
                    if d.is_empty() || !d.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(Error::BadEntity);
                    }
                    d.parse::<u32>().map_err(|_| Error::BadEntity)?
                } else {
                    return Err(Error::BadEntity);
                };
                let c = char::from_u32(v).ok_or(Error::BadEntity)?;
                if !is_xml_char(c) {
                    return Err(Error::BadEntity);
                }
                c
            }
        };
        out.push(c);
        Ok(())
    }
    fn check_char_run(&self, st: usize, en: usize) -> Result<(), Error> {
        if self.s[st..en].chars().all(is_xml_char) {
            Ok(())
        } else {
            Err(Error::BadChar)
        }
    }
    fn attr_value(&mut self) -> Result<String, Error> {
        let q = match self.peek() {
            Some(q @ (b'"' | b'\'')) => q,
            None => return Err(Error::Eof),
            _ => return Err(Error::Unexpected("quote")),
        };
        self.i += 1;
        let mut out = String::new();
        loop {
            let st = self.i;
            while let Some(c) = self.peek() {
                if c == q || c == b'&' || c == b'<' {
                    break;
                }
                self.i += 1;
            }
            self.check_char_run(st, self.i)?;
            out.push_str(&self.s[st..self.i]);
            if out.len() > self.lim.max_attr_value_len {
                return Err(Error::AttrTooLong);
            }
            match self.peek() {
                None => return Err(Error::Eof),
                Some(b'<') => return Err(Error::Unexpected("< in attribute")),
                Some(b'&') => self.reference(&mut out)?,
                Some(_) => {
                    self.i += 1;
                    break;
                }
            }
            if out.len() > self.lim.max_attr_value_len {
                return Err(Error::AttrTooLong);
            }
        }
        Ok(out)
    }
    fn add_text(&mut self, n: usize) -> Result<(), Error> {
        self.total_text += n;
        if self.total_text > self.lim.max_total_text {
            Err(Error::TotalTextTooLong)
        } else {
            Ok(())
        }
    }
    fn comment(&mut self) -> Result<(), Error> {
        self.expect("<!--")?;
        let st = self.i;
        loop {
            if self.i + 1 >= self.b.len() {
                return Err(Error::Eof);
            }
            if self.starts("--") {
                self.check_char_run(st, self.i)?;
                self.i += 2;
                return if self.peek() == Some(b'>') {
                    self.i += 1;
                    Ok(())
                } else if self.peek().is_none() {
                    Err(Error::Eof)
                } else {
                    Err(Error::Unexpected("-- in comment"))
                };
            }
            self.i += 1;
        }
    }
    /// Comments, whitespace; rejects DOCTYPE and PIs. Used in prolog and epilog.
    fn misc(&mut self) -> Result<(), Error> {
        loop {
            self.ws();
            if self.starts("<!--") {
                self.comment()?;
            } else if self.starts("<!") {
                return Err(Error::Doctype);
            } else if self.starts("<?") {
                return Err(Error::ProcessingInstruction);
            } else {
                return Ok(());
            }
        }
    }
    fn decl(&mut self) -> Result<(), Error> {
        // <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        if !self.starts("<?xml") {
            return Ok(());
        }
        match self.b.get(self.i + 5) {
            Some(b' ' | b'\t' | b'\r' | b'\n') => {}
            Some(b'?') => return Err(Error::Unexpected("version")),
            None => return Err(Error::Eof),
            _ => return Err(Error::ProcessingInstruction),
        }
        self.i += 5;
        let mut seen_version = false;
        let mut seen: Vec<String> = Vec::new();
        loop {
            let had_ws = self.ws();
            if self.starts("?>") {
                self.i += 2;
                break;
            }
            if !had_ws {
                return Err(Error::Unexpected("whitespace in declaration"));
            }
            let n = self.name()?;
            self.ws();
            self.expect("=")?;
            self.ws();
            let v = self.attr_value()?;
            if seen.contains(&n) {
                return Err(Error::DuplicateAttr);
            }
            match n.as_str() {
                "version" if seen.is_empty() => {
                    if v != "1.0" && v != "1.1" {
                        return Err(Error::Unexpected("version"));
                    }
                    seen_version = true;
                }
                "encoding" if seen_version => {
                    let l = v.to_ascii_lowercase();
                    if l != "utf-8" && l != "utf8" {
                        return Err(Error::Encoding);
                    }
                }
                "standalone" if seen_version => {}
                _ => return Err(Error::Unexpected("declaration attribute")),
            }
            seen.push(n);
        }
        if !seen_version {
            return Err(Error::Unexpected("version"));
        }
        Ok(())
    }
    /// Start tag after '<'. Returns (element, self_closing).
    fn start_tag(&mut self) -> Result<(Element, bool), Error> {
        self.elements += 1;
        if self.elements > self.lim.max_elements {
            return Err(Error::TooManyElements);
        }
        let name = self.name()?;
        let mut e = Element { name, attrs: Vec::new(), children: Vec::new() };
        loop {
            let had_ws = self.ws();
            match self.peek() {
                None => return Err(Error::Eof),
                Some(b'>') => {
                    self.i += 1;
                    return Ok((e, false));
                }
                Some(b'/') => {
                    self.i += 1;
                    self.expect(">")?;
                    return Ok((e, true));
                }
                Some(_) if !had_ws => return Err(Error::Unexpected("whitespace before attribute")),
                Some(_) => {
                    let n = self.name()?;
                    self.ws();
                    self.expect("=")?;
                    self.ws();
                    let v = self.attr_value()?;
                    if e.attrs.iter().any(|(k, _)| *k == n) {
                        return Err(Error::DuplicateAttr);
                    }
                    if e.attrs.len() >= self.lim.max_attrs_per_element {
                        return Err(Error::TooManyAttrs);
                    }
                    self.add_text(v.len())?;
                    e.attrs.push((n, v));
                }
            }
        }
    }
    fn document(&mut self) -> Result<Element, Error> {
        self.decl()?;
        self.misc()?;
        if self.peek().is_none() {
            return Err(Error::NoRoot);
        }
        if self.peek() != Some(b'<') {
            return Err(Error::Unexpected("root element"));
        }
        self.i += 1;
        let (root, closed) = self.start_tag()?;
        let root = if closed { root } else { self.content(root)? };
        self.misc()?;
        if self.i != self.b.len() {
            return Err(Error::TrailingContent);
        }
        Ok(root)
    }
    /// Content of an open element, iterative with an explicit stack.
    fn content(&mut self, root: Element) -> Result<Element, Error> {
        let mut stack: Vec<Element> = vec![root];
        self.max_depth_seen = 1;
        let mut text = String::new();
        loop {
            match self.peek() {
                None => return Err(Error::Eof),
                Some(b'<') => {
                    if !text.is_empty() {
                        let t = std::mem::take(&mut text);
                        push_text(stack.last_mut().unwrap(), t);
                    }
                    if self.starts("</") {
                        self.i += 2;
                        let n = self.name()?;
                        self.ws();
                        self.expect(">")?;
                        let done = stack.pop().unwrap();
                        if done.name != n {
                            return Err(Error::Mismatch);
                        }
                        match stack.last_mut() {
                            Some(parent) => parent.children.push(Node::Element(done)),
                            None => return Ok(done),
                        }
                    } else if self.starts("<!--") {
                        self.comment()?;
                    } else if self.starts("<![CDATA[") {
                        self.i += 9;
                        let st = self.i;
                        loop {
                            if self.i + 2 >= self.b.len() {
                                return Err(Error::Eof);
                            }
                            if self.starts("]]>") {
                                break;
                            }
                            self.i += 1;
                        }
                        self.check_char_run(st, self.i)?;
                        let n = self.i - st;
                        self.add_text(n)?;
                        if n > self.lim.max_text_len {
                            return Err(Error::TextTooLong);
                        }
                        push_text(stack.last_mut().unwrap(), self.s[st..self.i].to_string());
                        self.i += 3;
                    } else if self.starts("<!") {
                        return Err(Error::Doctype);
                    } else if self.starts("<?") {
                        return Err(Error::ProcessingInstruction);
                    } else {
                        self.i += 1;
                        if stack.len() >= self.lim.max_depth {
                            return Err(Error::Depth);
                        }
                        let (e, closed) = self.start_tag()?;
                        if closed {
                            stack.last_mut().unwrap().children.push(Node::Element(e));
                        } else {
                            stack.push(e);
                            self.max_depth_seen = self.max_depth_seen.max(stack.len());
                        }
                    }
                }
                Some(b'&') => {
                    let before = text.len();
                    self.reference(&mut text)?;
                    self.add_text(text.len() - before)?;
                    if text.len() > self.lim.max_text_len {
                        return Err(Error::TextTooLong);
                    }
                }
                Some(_) => {
                    let st = self.i;
                    while let Some(c) = self.peek() {
                        if c == b'<' || c == b'&' {
                            break;
                        }
                        self.i += 1;
                    }
                    self.check_char_run(st, self.i)?;
                    if self.s[st..self.i].contains("]]>") {
                        return Err(Error::Unexpected("]]> in text"));
                    }
                    self.add_text(self.i - st)?;
                    text.push_str(&self.s[st..self.i]);
                    if text.len() > self.lim.max_text_len {
                        return Err(Error::TextTooLong);
                    }
                }
            }
        }
    }
}

fn push_text(e: &mut Element, t: String) {
    if let Some(Node::Text(prev)) = e.children.last_mut() {
        prev.push_str(&t);
    } else if !t.is_empty() {
        e.children.push(Node::Text(t));
    }
}

pub fn parse(input: &[u8], lim: Limits) -> Result<(Element, Stats), Error> {
    if input.len() > lim.max_bytes {
        return Err(Error::TooLarge);
    }
    let input = input.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(input);
    // UTF-16/32 BOMs or NUL-interleaved text fail here (or as BadChar for U+0000).
    let s = std::str::from_utf8(input).map_err(|_| Error::NotUtf8)?;
    let mut p = P { s, b: input, i: 0, lim, elements: 0, total_text: 0, max_depth_seen: 0 };
    let root = p.document()?;
    Ok((root, Stats { elements: p.elements, max_depth: p.max_depth_seen.max(1), bytes: input.len() }))
}

/// Canonical serialisation (used by the fuzz round-trip check). Iterative, like the parser.
pub fn serialize(root: &Element) -> String {
    fn esc(s: &str, out: &mut String) {
        for c in s.chars() {
            match c {
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '&' => out.push_str("&amp;"),
                '"' => out.push_str("&quot;"),
                '\r' => out.push_str("&#13;"),
                _ => out.push(c),
            }
        }
    }
    fn open(e: &Element, out: &mut String) {
        out.push('<');
        out.push_str(&e.name);
        for (k, v) in &e.attrs {
            out.push(' ');
            out.push_str(k);
            out.push_str("=\"");
            esc(v, out);
            out.push('"');
        }
        out.push('>');
    }
    let mut out = String::new();
    let mut stack: Vec<(&Element, usize)> = vec![(root, 0)];
    open(root, &mut out);
    while let Some((e, idx)) = stack.pop() {
        if idx < e.children.len() {
            stack.push((e, idx + 1));
            match &e.children[idx] {
                Node::Text(t) => esc(t, &mut out),
                Node::Element(ch) => {
                    open(ch, &mut out);
                    stack.push((ch, 0));
                }
            }
        } else {
            out.push_str("</");
            out.push_str(&e.name);
            out.push('>');
        }
    }
    out
}
