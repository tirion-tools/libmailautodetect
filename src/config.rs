//! The Mozilla `clientConfig` v1.1 mapper: from a parsed document to validated connection metadata.
//! Depends only on [`crate::xml`], so `build.rs` compiles the ISPDB table with the same rules.

use crate::xml::{self, Limits};

/// The host placeholder of `clientConfig` documents, lower case (hosts are lower-cased first).
pub const EMAILDOMAIN: &str = "%emaildomain%";
/// The stand-in domain a template host is validated with ([`parse_template`]).
const TEMPLATE_DOMAIN: &str = "example.org";
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
    pub(crate) fn drop(&mut self, why: &'static str) {
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

/// `domain`: substitute it for `%EMAILDOMAIN%`; `None`: keep the placeholder (a template host,
/// validated with [`TEMPLATE_DOMAIN`] in its place).
fn server(
    e: &xml::Element,
    proto: Proto,
    domain: Option<&str>,
    c: &mut MailConfig,
) -> Option<Server> {
    let named = e
        .child("hostname")
        .map(|h| h.text())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let (host, ok) = match domain {
        Some(d) => {
            let h = named.replace(EMAILDOMAIN, d);
            let ok = valid_host(&h);
            (h, ok)
        }
        None => {
            let ok = valid_host(&named.replace(EMAILDOMAIN, TEMPLATE_DOMAIN));
            (named, ok)
        }
    };
    if !ok {
        c.drop("bad_host");
        return None;
    }
    let Some(port) = e.child("port").and_then(|p| p.text().parse::<u16>().ok()) else {
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
    map_provider(email_provider(root)?, Some(domain))
}

fn email_provider(root: &xml::Element) -> Result<&xml::Element, &'static str> {
    if root.local() != "clientConfig" {
        return Err("root_not_clientConfig");
    }
    root.child("emailProvider").ok_or("no_emailProvider")
}

fn map_provider(prov: &xml::Element, domain: Option<&str>) -> Result<MailConfig, &'static str> {
    let mut c = MailConfig::default();
    for e in prov.elements() {
        match (e.local(), e.attr("type")) {
            ("incomingServer", Some("imap")) => {
                if c.imap.len() < MAX_SERVERS
                    && let Some(s) = server(e, Proto::Imap, domain, &mut c)
                {
                    c.imap.push(s);
                }
            }
            ("incomingServer", Some("pop3")) => c.drop("incoming_pop3"),
            ("incomingServer", Some(_)) => c.drop("incoming_other"),
            ("incomingServer", None) => c.drop("incoming_untyped"),
            ("outgoingServer", Some("smtp")) => {
                if c.smtp.len() < MAX_SERVERS
                    && let Some(s) = server(e, Proto::Smtp, domain, &mut c)
                {
                    c.smtp.push(s);
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
    Xml(xml::Error),
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

/// A provider document kept as a template, for compiling a provider table from a vetted snapshot
/// (Thunderbird's ISPDB): hosts keep `%emaildomain%` and were validated with a stand-in domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderTemplate {
    pub config: MailConfig,
    /// The document's `<domain>` names (lower case, possibly not LDH; the caller filters).
    pub domains: Vec<String>,
}

/// Parse + map without a user domain: [`parse`]'s rules, hosts left as templates.
pub fn parse_template(body: &[u8]) -> Result<ProviderTemplate, ParseError> {
    let (root, _) = xml::parse(body, Limits::AUTOCONFIG).map_err(ParseError::Xml)?;
    let prov = email_provider(&root).map_err(ParseError::Schema)?;
    let config = map_provider(prov, None).map_err(ParseError::Schema)?;
    let domains = prov
        .elements()
        .filter(|e| e.local() == "domain")
        .map(|e| e.text().to_ascii_lowercase())
        .collect();
    Ok(ProviderTemplate { config, domains })
}
