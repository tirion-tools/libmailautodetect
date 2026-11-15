//! Built-in provider table (feature `ispdb`): a pinned snapshot of Thunderbird's ISPDB
//! (`thunderbird/autoconfig`, `ispdb/*.xml`, MPL-2.0) compiled by `build.rs` with this crate's own
//! parser and mapper ([`crate::parse_template`]), so the table obeys exactly the rules applied to
//! network autoconfig documents. The snapshot directory comes from `MAIL_AUTODETECT_ISPDB_DIR`.
//!
//! [`lookup`] answers for the user's domain; [`by_mx`] follows Thunderbird's `fetchConfigForMX`.
//! Hosts are re-validated after `%EMAILDOMAIN%` substitution.

use crate::{MailConfig, Proto, Server, Sock, valid_host};

struct Entry {
    host: &'static str,
    port: u16,
    sock: Sock,
    username: &'static str,
    oauth2: bool,
}

struct Provider {
    file: &'static str,
    imap: &'static [Entry],
    smtp: &'static [Entry],
}

// PROVIDERS, DOMAINS (sorted by name, provider index).
include!(concat!(env!("OUT_DIR"), "/ispdb_table.rs"));

/// The answer of the built-in table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltinConfig {
    /// The snapshot file that answered (`<name>.xml`).
    pub file: &'static str,
    /// The table domain that matched (the user's domain, or the MX-derived one).
    pub matched: String,
    pub config: MailConfig,
}

/// Number of providers and of domain names in the table.
pub fn table_size() -> (usize, usize) {
    (PROVIDERS.len(), DOMAINS.len())
}

fn expand(list: &[Entry], proto: Proto, email_domain: &str, c: &mut MailConfig) -> Vec<Server> {
    let mut out = Vec::with_capacity(list.len());
    for e in list {
        let host = e.host.replace(crate::EMAILDOMAIN, email_domain);
        if !valid_host(&host) {
            c.drop("bad_host");
            continue;
        }
        out.push(Server {
            proto,
            host,
            port: e.port,
            sock: e.sock,
            username: (!e.username.is_empty()).then(|| e.username.to_owned()),
            oauth2: e.oauth2,
        });
    }
    out
}

/// Direct lookup of a lower-case LDH mail domain; `%EMAILDOMAIN%` becomes `email_domain`.
pub fn lookup(domain: &str, email_domain: &str) -> Option<BuiltinConfig> {
    let i = DOMAINS.binary_search_by(|(d, _)| (*d).cmp(domain)).ok()?;
    let p = &PROVIDERS[usize::from(DOMAINS[i].1)];
    let mut config = MailConfig::default();
    config.imap = expand(p.imap, Proto::Imap, email_domain, &mut config);
    config.smtp = expand(p.smtp, Proto::Smtp, email_domain, &mut config);
    Some(BuiltinConfig {
        file: p.file,
        matched: domain.to_owned(),
        config,
    })
}

/// Lookup by MX, as Thunderbird's `fetchConfigForMX`: the lowest-preference MX host's registrable
/// domain, then that domain with the MX host's next label (`mx.a.b.example.com` with registrable
/// `example.com` → `example.com`, then `b.example.com`). The caller resolves MX and derives
/// `mx_registrable` with its Public Suffix List.
pub fn by_mx(mx_host: &str, mx_registrable: &str, email_domain: &str) -> Option<BuiltinConfig> {
    if mx_registrable.is_empty() {
        return None;
    }
    let rest = mx_host.strip_suffix(mx_registrable)?;
    if let Some(c) = lookup(mx_registrable, email_domain) {
        return Some(c);
    }
    // The label of mx_host directly left of the registrable domain, if mx_host has one more.
    let head = rest.strip_suffix('.').filter(|h| !h.is_empty())?;
    let dot = head.rfind('.')?;
    lookup(&mx_host[dot + 1..], email_domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_unique_and_valid() {
        assert!(DOMAINS.windows(2).all(|w| w[0].0 < w[1].0));
        for (d, p) in DOMAINS {
            assert!(valid_host(d), "{d}");
            assert!(usize::from(*p) < PROVIDERS.len());
        }
        for p in PROVIDERS {
            assert!(!p.imap.is_empty() && !p.smtp.is_empty(), "{}", p.file);
            assert!(p.imap.len() <= crate::MAX_SERVERS && p.smtp.len() <= crate::MAX_SERVERS);
            assert!(p.imap.iter().all(|e| crate::IMAP_PORTS.contains(&e.port)));
            assert!(p.smtp.iter().all(|e| crate::SMTP_PORTS.contains(&e.port)));
        }
    }

    #[test]
    fn direct_lookup() {
        let c = lookup("gmx.com", "gmx.com").expect("gmx.com in the snapshot");
        assert_eq!(c.file, "gmx.com.xml");
        assert_eq!(c.matched, "gmx.com");
        assert_eq!(c.config.imap[0].host, "imap.gmx.com");
        assert_eq!(c.config.imap[0].port, 993);
        assert!(c.config.is_usable());
        assert!(lookup("gmx.co.uk", "gmx.co.uk").is_some()); // a <domain> alias of the same file
        assert!(lookup("no-such-provider.test", "no-such-provider.test").is_none());
        assert!(lookup("", "").is_none());
    }

    #[test]
    fn email_domain_is_substituted_and_revalidated() {
        let (d, p) = DOMAINS
            .iter()
            .find(|(_, p)| {
                PROVIDERS[usize::from(*p)]
                    .imap
                    .iter()
                    .any(|e| e.host.contains(crate::EMAILDOMAIN))
            })
            .expect("a provider with a %EMAILDOMAIN% host");
        let c = lookup(d, "user.example").unwrap();
        assert!(
            c.config
                .imap
                .iter()
                .any(|s| s.host.ends_with(".user.example") || s.host == "user.example")
        );
        // 250 bytes: a valid domain, but "<label>." in front of it exceeds 253.
        let long = format!(
            "{}.{}.{}.{}.example",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(50)
        );
        assert!(valid_host(&long));
        let c = lookup(d, &long).unwrap();
        assert!(c.config.imap.len() < PROVIDERS[usize::from(*p)].imap.len());
        assert!(c.config.dropped.contains(&"bad_host"));
    }

    #[test]
    fn mx_lookup() {
        // Google Workspace tenants: MX registrable google.com → the googlemail.com file.
        let g = by_mx("aspmx.l.google.com", "google.com", "example.edu").expect("google.com MX");
        assert!(!g.config.imap.is_empty());
        assert!(by_mx("mx.example.test", "example.test", "example.test").is_none());
        assert!(by_mx("mx.other.test", "example.test", "example.test").is_none()); // not a suffix
        assert!(by_mx("google.com", "", "example.edu").is_none());
    }
}
