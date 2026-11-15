//! Mail account auto-detection.
//! The strict bounded XML parser ([`xml`]), the Mozilla `clientConfig` v1.1 mapper ([`parse`]) and the
//! redirect rule ([`next_hop`]). Only validated connection metadata leaves the parser:
//! hosts, ports, socket types, username templates, the OAuth2 flag. Display names and documentation
//! URLs are dropped. Confirming a cross-domain answer ("Your mail is hosted by X") is the caller's: it sees
//! every hop's host and every server host in the result, and owns the PSL.

pub mod xml;

use url::{Host, Url};

pub use xml::{Error as XmlError, Limits};

/// R4: at most 3 redirects per autoconfig lookup.
pub const MAX_REDIRECTS: u32 = 3;
/// Largest autoconfig body read from the network (= the parser's byte limit).
pub const MAX_BODY: usize = Limits::AUTOCONFIG.max_bytes;
/// Servers kept per protocol.
pub const MAX_SERVERS: usize = 16;
/// Dropped-entry reason codes kept.
pub const MAX_DROPPED: usize = 64;
/// Ports accepted, per protocol.
pub const IMAP_PORTS: [u16; 2] = [993, 143];
pub const SMTP_PORTS: [u16; 2] = [465, 587];
pub const MAIL_PORTS: [u16; 4] = [993, 143, 465, 587];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Imap,
    Smtp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sock {
    Ssl,
    StartTls,
    Plain,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Server {
    pub proto: Proto,
    /// Lower-case LDH, `%EMAILDOMAIN%` substituted, never an IP literal.
    pub host: String,
    pub port: u16,
    pub sock: Sock,
    /// Template (`%EMAILADDRESS%`, `%EMAILLOCALPART%`) or literal; ≤ 256 bytes, no controls.
    pub username: Option<String>,
    pub oauth2: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MailConfig {
    pub imap: Vec<Server>,
    pub smtp: Vec<Server>,
    /// Entries dropped by validation, as reason codes (pop3, bad_host, port_not_brokered, ...).
    pub dropped: Vec<&'static str>,
}

impl MailConfig {
    pub fn is_usable(&self) -> bool {
        !self.imap.is_empty() && !self.smtp.is_empty()
    }
    fn drop(&mut self, why: &'static str) {
        if self.dropped.len() < MAX_DROPPED {
            self.dropped.push(why);
        }
    }
}

/// LDH host name: ≥ 2 labels of 1–63 bytes, ≤ 253 total, no trailing dot, last label not numeric.
/// IP literals are refused (a config naming an address is refused; the user can enter it manually).
pub fn valid_host(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 || h.ends_with('.') {
        return false;
    }
    let mut labels = 0usize;
    let mut last = "";
    for l in h.split('.') {
        if l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-') {
            return false;
        }
        if !l
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return false;
        }
        labels += 1;
        last = l;
    }
    labels >= 2 && !last.bytes().all(|b| b.is_ascii_digit())
}

fn server(e: &xml::Element, proto: Proto, domain: &str, c: &mut MailConfig) -> Option<Server> {
    let host = e
        .child("hostname")
        .map(|h| h.text())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .replace("%emaildomain%", domain);
    if !valid_host(&host) {
        c.drop("bad_host");
        return None;
    }
    let Some(port) = e
        .child("port")
        .and_then(|p| p.text().parse::<u16>().ok())
    else {
        c.drop("bad_port");
        return None;
    };
    let allowed: &[u16] = match proto {
        Proto::Imap => &IMAP_PORTS,
        Proto::Smtp => &SMTP_PORTS,
    };
    if !allowed.contains(&port) {
        c.drop("port_not_brokered");
        return None;
    }
    let sock = match e.child("socketType").map(|s| s.text()).as_deref() {
        Some("SSL") => Sock::Ssl,
        Some("STARTTLS") => Sock::StartTls,
        Some("plain") => Sock::Plain,
        _ => {
            c.drop("bad_socket_type");
            return None;
        }
    };
    let username = e
        .child("username")
        .map(|u| u.text())
        .filter(|u| !u.is_empty());
    if username
        .as_deref()
        .is_some_and(|u| u.len() > 256 || u.chars().any(char::is_control))
    {
        c.drop("bad_username");
        return None;
    }
    let oauth2 = e
        .elements()
        .any(|a| a.local() == "authentication" && a.text() == "OAuth2");
    Some(Server {
        proto,
        host,
        port,
        sock,
        username,
        oauth2,
    })
}

/// Maps a parsed `clientConfig` v1.1 document. `domain` is the user's mail domain (for %EMAILDOMAIN%).
pub fn from_autoconfig(root: &xml::Element, domain: &str) -> Result<MailConfig, &'static str> {
    if root.local() != "clientConfig" {
        return Err("root_not_clientConfig");
    }
    let prov = root.child("emailProvider").ok_or("no_emailProvider")?;
    let mut c = MailConfig::default();
    for e in prov.elements() {
        match (e.local(), e.attr("type")) {
            ("incomingServer", Some("imap")) => {
                if c.imap.len() < MAX_SERVERS {
                    if let Some(s) = server(e, Proto::Imap, domain, &mut c) {
                        c.imap.push(s);
                    }
                }
            }
            ("incomingServer", Some("pop3")) => c.drop("incoming_pop3"),
            ("incomingServer", Some(_)) => c.drop("incoming_other"),
            ("incomingServer", None) => c.drop("incoming_untyped"),
            ("outgoingServer", Some("smtp")) => {
                if c.smtp.len() < MAX_SERVERS {
                    if let Some(s) = server(e, Proto::Smtp, domain, &mut c) {
                        c.smtp.push(s);
                    }
                }
            }
            ("outgoingServer", _) => c.drop("outgoing_other"),
            _ => {}
        }
    }
    Ok(c)
}

/// Why a body was refused: an XML limit/syntax error or a schema error, as a stable code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Xml(XmlError),
    Schema(&'static str),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Xml(e) => write!(f, "xml:{}", e.code()),
            ParseError::Schema(s) => write!(f, "schema:{s}"),
        }
    }
}

/// Parse + map: the unit the fetcher runs on an autoconfig body.
pub fn parse(body: &[u8], domain: &str) -> Result<MailConfig, ParseError> {
    let (root, _) = xml::parse(body, Limits::AUTOCONFIG).map_err(ParseError::Xml)?;
    from_autoconfig(&root, domain).map_err(ParseError::Schema)
}

/// The URL policy for the approved URL and every redirect target (R1, R4): https only, no
/// explicit port (443), an LDH host name (no IP literal), no userinfo; the fragment is dropped.
pub fn check_url(u: &mut Url) -> Result<(), &'static str> {
    if u.scheme() != "https" {
        return Err("https only");
    }
    if u.port().is_some() {
        return Err("explicit port not allowed");
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err("userinfo not allowed");
    }
    match u.host() {
        Some(Host::Domain(d)) if valid_host(d) => {}
        Some(Host::Domain(_)) => return Err("host is not an LDH name"),
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => return Err("IP literal not allowed"),
        None => return Err("no host"),
    }
    u.set_fragment(None);
    Ok(())
}

/// R4 for one redirect: `hop` is the number of redirects already followed. The private-address
/// rule is the caller's (its address policy for the next hop).
pub fn next_hop(current: &Url, location: &str, hop: u32) -> Result<Url, &'static str> {
    if hop >= MAX_REDIRECTS {
        return Err("too_many_redirects");
    }
    let mut n = current.join(location).map_err(|_| "bad_location")?;
    if n.scheme() == "http" {
        return Err("redirect_https_to_http");
    }
    check_url(&mut n)?;
    Ok(n)
}

#[cfg(test)]
mod tests;
