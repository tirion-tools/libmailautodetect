//! C ABI of the built-in provider table (feature `capi`), declared in `include/mailautodetect.h`.
//! Answers are lent to a visitor callback for the duration of the call: nothing crosses the
//! boundary that the caller must free.

use std::ffi::c_void;

use crate::ispdb::{self, BuiltinConfig};
use crate::{Proto, Server, Sock};

/// `mailautodetect_str`: UTF-8 bytes, not NUL-terminated.
#[repr(C)]
pub struct RawStr {
    pub ptr: *const u8,
    pub len: usize,
}

/// `mailautodetect_server`.
#[repr(C)]
pub struct RawServer {
    /// 0 IMAP, 1 SMTP.
    pub protocol: u8,
    /// 0 SSL, 1 STARTTLS, 2 plain.
    pub socket: u8,
    pub port: u16,
    pub oauth2: bool,
    pub host: RawStr,
    /// Empty when the provider names no username.
    pub username: RawStr,
}

/// `mailautodetect_config`.
#[repr(C)]
pub struct RawConfig {
    pub file: RawStr,
    pub matched: RawStr,
    pub imap: *const RawServer,
    pub imap_len: usize,
    pub smtp: *const RawServer,
    pub smtp_len: usize,
}

/// `mailautodetect_visit`: receives the answer; every pointer is valid only during the call.
pub type Visit = unsafe extern "C" fn(ctx: *mut c_void, config: *const RawConfig);

fn lend(s: &str) -> RawStr {
    RawStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

fn raw_server(s: &Server) -> RawServer {
    RawServer {
        protocol: match s.proto {
            Proto::Imap => 0,
            Proto::Smtp => 1,
        },
        socket: match s.sock {
            Sock::Ssl => 0,
            Sock::StartTls => 1,
            Sock::Plain => 2,
        },
        port: s.port,
        oauth2: s.oauth2,
        host: lend(&s.host),
        username: lend(s.username.as_deref().unwrap_or("")),
    }
}

/// # Safety
/// `s.ptr` points to `s.len` readable bytes (or `s.len` is 0).
unsafe fn text<'a>(s: &RawStr) -> Option<&'a str> {
    if s.len == 0 {
        return Some("");
    }
    if s.ptr.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `len` readable bytes at `ptr` for the duration of the call.
    std::str::from_utf8(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).ok()
}

fn deliver(answer: Option<BuiltinConfig>, visit: Visit, ctx: *mut c_void) -> bool {
    let Some(c) = answer else { return false };
    let imap: Vec<RawServer> = c.config.imap.iter().map(raw_server).collect();
    let smtp: Vec<RawServer> = c.config.smtp.iter().map(raw_server).collect();
    let raw = RawConfig {
        file: lend(c.file),
        matched: lend(&c.matched),
        imap: imap.as_ptr(),
        imap_len: imap.len(),
        smtp: smtp.as_ptr(),
        smtp_len: smtp.len(),
    };
    // SAFETY: `raw` and everything it points to outlive the call; the visitor is the caller's.
    unsafe { visit(ctx, &raw) };
    true
}

/// [`ispdb::lookup`]. Returns false (visitor not called) when the domain is not in the table or an
/// argument is not UTF-8.
///
/// # Safety
/// Every `RawStr` points to `len` readable bytes; `visit` is a valid function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mailautodetect_ispdb_lookup(
    domain: RawStr,
    email_domain: RawStr,
    visit: Visit,
    ctx: *mut c_void,
) -> bool {
    // SAFETY: forwarded from this function's contract.
    let (Some(d), Some(e)) = (unsafe { text(&domain) }, unsafe { text(&email_domain) }) else {
        return false;
    };
    deliver(ispdb::lookup(d, e), visit, ctx)
}

/// [`ispdb::by_mx`]. Returns false (visitor not called) when nothing matches or an argument is not
/// UTF-8.
///
/// # Safety
/// Every `RawStr` points to `len` readable bytes; `visit` is a valid function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mailautodetect_ispdb_by_mx(
    mx_host: RawStr,
    mx_registrable: RawStr,
    email_domain: RawStr,
    visit: Visit,
    ctx: *mut c_void,
) -> bool {
    // SAFETY: forwarded from this function's contract.
    let (Some(h), Some(r), Some(e)) = (
        unsafe { text(&mx_host) },
        unsafe { text(&mx_registrable) },
        unsafe { text(&email_domain) },
    ) else {
        return false;
    };
    deliver(ispdb::by_mx(h, r, e), visit, ctx)
}
