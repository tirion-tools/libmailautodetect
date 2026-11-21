# libmailautodetect

Mail account auto-detection in Rust. From a user's mail domain it produces validated IMAP and SMTP server settings, and
it treats every answer as hostile input.

## Builds on

This crate follows existing standards and data. It does not define its own:

- **[Thunderbird's ISPDB](https://github.com/thunderbird/autoconfig)** is the data source for the built-in provider
  table (feature `ispdb`).
  - The XML files are used unmodified, from a snapshot the consumer pins, and are compiled into the binary at build
    time.
  - They are MPL-2.0. Ship the snapshot's `LICENSE` with any binary that contains the table.
  - Fixes to the data go upstream to `thunderbird/autoconfig`, not into this crate.
- **[Mozilla autoconfig](https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat)** (`clientConfig`
  `config-v1.1.xml`) is the format of both the ISPDB files and the documents a provider serves at
  `autoconfig.<domain>`.
- **Lookup by MX** works as Thunderbird's `fetchConfigForMX` does: when the mail domain has no entry of its own, the
  provider is found by the domain of its MX host.
- **RFC 6186** (SRV records for IMAP and submission) and **Microsoft Autodiscover** belong to the discovery order but
  are **not implemented yet**. The caller runs the order.
- The [`url`](https://crates.io/crates/url) crate parses URLs; nothing else is a dependency.

What it adds:
- a **strict, bounded XML parser** for autoconfig documents: no DTD, no entities, no external references, and limits on
  size, depth, elements, names, attributes and text;
- a **`clientConfig` mapper** that lets only validated connection metadata through: lower-case LDH host names (never an
  IP literal), the standard ports (IMAP 993/143, SMTP 465/587), socket type, username template and the OAuth2 flag.
  Display names and documentation URLs are dropped. Every dropped entry is reported with a reason code (`pop3`,
  `bad_host`, `port_not_allowed`, …);
- the **URL and redirect rules** for fetching autoconfig documents: https only, no explicit port, no userinfo, no IP
  literal, at most 3 redirects, and never from https to http;
- the **built-in table**: the ISPDB snapshot compiled by `build.rs` with the same parser and mapper. A snapshot file
  the parser refuses fails the build. It answers a direct lookup and a lookup by MX. A C ABI (feature `capi`,
  `include/mailautodetect.h`) lets C and C++ callers use it.

## API

```rust
// A document fetched from https://autoconfig.<domain>/mail/config-v1.1.xml (at most MAX_BODY bytes):
let cfg = mailautodetect::parse(body, "example.com")?;      // MailConfig { imap, smtp, dropped }

// Fetching: the first URL and each redirect.
let mut url = url::Url::parse("https://autoconfig.example.com/mail/config-v1.1.xml")?;
mailautodetect::check_url(&mut url)?;
let next = mailautodetect::next_hop(&url, location_header, hops_so_far)?;

// Built-in table (feature "ispdb"; MAILAUTODETECT_ISPDB_DIR = the snapshot's ispdb/ directory at build time):
let hit = mailautodetect::ispdb::lookup("gmx.com", "gmx.com");
let by_mx = mailautodetect::ispdb::by_mx("mx00.emig.gmx.net", "gmx.net", "example.org");
```

The caller does the network I/O, the DNS and the Public Suffix List. It passes the MX host's registrable domain to
`by_mx`. The caller also decides whether to accept a cross-domain answer ("Your mail is hosted by X"); it sees every
redirect hop and every server host to do so.

## Security model

- **Hostile input.** Every byte of an autoconfig document comes from the network, possibly from an attacker who
  controls DNS or the domain. The parser bounds memory and time, and the mapper lets out only metadata that cannot name
  an arbitrary host or port:
  - no IP literals and no non-standard ports;
  - templates validated with a stand-in domain;
  - hosts re-validated after `%EMAILDOMAIN%` substitution.
- **The fuzz target** (`fuzz/`) checks four things:
  - no panic, timeout or OOM;
  - every parser bound;
  - that serialising a parsed tree and parsing it again gives the same tree;
  - that the mapper only emits valid hosts and allowed ports.
- **No I/O.** The crate does no network, file or DNS access at run time, so it can run inside a seccomp/Landlock
  sandbox. The C ABI lends answers to a visitor callback, so the caller has nothing to free.

## Known limits

- **Data the ISPDB cannot fix.** In a TLS-only survey of 74 answers found by MX, 2 servers failed: alice.it (TIM) and
  skynet.be (Proximus). Both match the providers' published settings, and an independent check from another network
  (thunderbird/autoconfig#135) saw different failures. Their direct entries fail the same way. No data change helps.
- **Lookup by MX names the hosting company, not the brand.** Domains hosted by Yahoo (AOL, AT&T, Verizon, …) get Yahoo's
  servers. A domain's own ISPDB entry answers first.
- **ISPDB entries with plaintext connections** exist in the data. The mapper reports them as `Sock::Plain`. Refusing
  them is the caller's policy.
- **charter.net** declares implicit TLS on port 587, which conflicts with a "the port decides the TLS mode" rule. It is
  open until the discovery order is built.

## Gates

Every check runs locally, in a pinned toolchain container (`tools/container/Dockerfile`: Rust 1.93.1 by digest, plus
cargo-fuzz 0.13.2 and cargo-deny 0.20.2):

```sh
tools/container.sh tools/gate.sh            # fmt, clippy, test, fuzz, audit
```

| Job | What |
|---|---|
| `fmt` | `cargo fmt --check` of the crate and the fuzz harness |
| `clippy` | `cargo clippy --locked --all-targets -D warnings`: default features, `--features capi`, and the fuzz harness |
| `test` | `cargo test --locked`, then again with `--features capi`, against the pinned ISPDB snapshot (`tools/ispdb.env`, SHA-256 checked) |
| `fuzz` | the `autoconfig` target for `FUZZ_SECONDS` (default 60), with AddressSanitizer and `fuzz/autoconfig.dict` |
| `audit` | `cargo deny check`: advisories, licences, bans, sources |

The library ships no binaries. Consumers pin a commit. `.github/workflows/` mirrors the gate for when the repository is
hosted.

## Contributing

This repository is not accepting contributions at this time: issues and pull requests are not accepted. Report
security vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

## Licence

MIT, see `LICENSE`. The ISPDB snapshot is not part of this repository, but the fuzz seed corpus is. Its files
`fuzz/corpus/autoconfig/s0000`–`s0162` are unmodified ISPDB files under MPL-2.0 (see `fuzz/README.md`,
`THIRD-PARTY-NOTICES.md` and `LICENSES/MPL-2.0.txt`).
