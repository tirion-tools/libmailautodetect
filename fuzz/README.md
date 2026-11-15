# Fuzzing

`fuzz_targets/autoconfig.rs` is a cargo-fuzz target; `tools/gate.sh fuzz` runs it with `autoconfig.dict`.

Seed corpus `corpus/autoconfig/`:
- `s0000`–`s0162`: the 163 files of Thunderbird's ISPDB (`ispdb/*.xml` of github.com/thunderbird/autoconfig
  at commit f50a4feb7dd0e0ed76a7ce440d591ac592dcc313), unmodified, renamed. They are licensed under the
  Mozilla Public License 2.0 (https://mozilla.org/MPL/2.0/); the source is that repository.
- `s0163`–`s0206`: synthetic hostile documents (oversized, deep, entity tricks, bad encodings, redirects to
  `*.test` hosts).
- `pox0`–`pox3`: synthetic Autodiscover POX documents.
