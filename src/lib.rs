//! Mail account auto-detection.
//! The strict bounded XML parser ([`xml`]), the Mozilla `clientConfig` v1.1 mapper ([`parse`]) and the
//! redirect rule ([`next_hop`]). Only validated connection metadata leaves the parser:
//! hosts, ports, socket types, username templates, the OAuth2 flag. Display names and documentation
//! URLs are dropped. Confirming a cross-domain answer ("Your mail is hosted by X") is the caller's: it sees
//! every hop's host and every server host in the result, and owns the PSL.

#[cfg(feature = "capi")]
pub mod capi;
mod config;
#[cfg(feature = "ispdb")]
pub mod ispdb;
pub mod xml;

use url::{Host, Url};

pub use config::*;
pub use xml::{Error as XmlError, Limits};

/// R4: at most 3 redirects per autoconfig lookup.
pub const MAX_REDIRECTS: u32 = 3;
/// Largest autoconfig body read from the network (= the parser's byte limit).
pub const MAX_BODY: usize = Limits::AUTOCONFIG.max_bytes;
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
