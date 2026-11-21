# Third-party notices

The code in this repository is MIT-licensed (`LICENSE`, Copyright (c) 2026 Tirion) unless this file says otherwise.

## Bundled third-party code and data

### Thunderbird ISPDB files (MPL-2.0)

- **What:** `fuzz/corpus/autoconfig/s0000` to `s0162`, the 163 files of `ispdb/*.xml`, unmodified but renamed. They
  are fuzz seeds only; the library itself contains no ISPDB data.
- **Source:** https://github.com/thunderbird/autoconfig at commit `f50a4feb7dd0e0ed76a7ce440d591ac592dcc313` (also
  pinned in `tools/ispdb.env`).
- **Licence:** Mozilla Public License 2.0. A copy of that repository's `LICENSE` is in `LICENSES/MPL-2.0.txt`. The
  source form of these files is the files themselves; the upstream repository is the place for changes.

Everything else in `fuzz/corpus/autoconfig/` (`s0163` onwards, `pox0` to `pox3`) is synthetic and MIT-licensed.

### The built-in provider table (feature `ispdb`)

Not in this repository. `build.rs` compiles it from an ISPDB snapshot the consumer supplies at build time
(`MAILAUTODETECT_ISPDB_DIR`), so a binary built with the feature contains MPL-2.0 data: ship the snapshot's `LICENSE`
with it.

## Dependencies (not bundled)

Dependencies are not vendored: they are fetched at build time (Rust crates from crates.io, pinned in `Cargo.lock`) under their own licences, and the gate
checks their licences (`cargo deny`, `deny.toml`). Nothing from them is redistributed in this repository.

- [url](https://crates.io/crates/url) (MIT or Apache-2.0) is the only runtime dependency.
