#!/usr/bin/env bash
# The local gate (run it in the pinned toolchain: tools/container.sh tools/gate.sh [JOB...]).
# Jobs, in order: fmt, clippy, test, fuzz, audit. Exit status 1 when any job fails; a summary of
# every job is printed at the end.
#   FUZZ_SECONDS   seconds per fuzz target (default 60)
# The `ispdb`/`capi` features are checked against a pinned ISPDB snapshot (tools/ispdb.env), fetched
# into .cache/ and verified by SHA-256 before use.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
JOBS=("$@")
[[ ${#JOBS[@]} -gt 0 ]] || JOBS=(fmt clippy test fuzz audit)
FUZZ_SECONDS=${FUZZ_SECONDS:-60}

ispdb() {
  # shellcheck source=tools/ispdb.env
  source tools/ispdb.env
  local dir=.cache/ispdb-$ISPDB_COMMIT
  if [[ ! -d $dir ]]; then
    mkdir -p .cache && curl --fail --location --retry 3 --silent --show-error -o "$dir.tgz" "$ISPDB_URL" \
      && echo "$ISPDB_SHA256  $dir.tgz" | sha256sum --check --quiet \
      && mkdir -p "$dir.tmp" && tar -xzf "$dir.tgz" -C "$dir.tmp" --strip-components=1 && mv "$dir.tmp" "$dir" \
      && rm -f "$dir.tgz" || return 1
  fi
  export MAILAUTODETECT_ISPDB_DIR=$PWD/$dir/ispdb
}

fmt() { cargo fmt --check && cargo fmt --check --manifest-path fuzz/Cargo.toml; }
clippy() {
  ispdb || return 1
  cargo clippy --locked --all-targets -- -D warnings \
    && cargo clippy --locked --all-targets --features capi -- -D warnings \
    && RUSTC_BOOTSTRAP=1 cargo clippy --locked --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
}
test() {
  ispdb || return 1
  cargo test --locked && cargo test --locked --features capi
}
# cargo-fuzz builds with AddressSanitizer by default; RUSTC_BOOTSTRAP lets the stable toolchain
# take the sanitizer flags.
fuzz() {
  local t rc=0
  for t in $(cargo fuzz list --fuzz-dir fuzz); do
    mkdir -p "fuzz/corpus/$t" "target/fuzz-corpus/$t" target/fuzz-findings
    RUSTC_BOOTSTRAP=1 cargo fuzz run --fuzz-dir fuzz "$t" "target/fuzz-corpus/$t" "fuzz/corpus/$t" -- \
      -max_total_time="$FUZZ_SECONDS" -rss_limit_mb=2048 -timeout=30 -max_len=65536 -dict=fuzz/autoconfig.dict \
      -artifact_prefix="target/fuzz-findings/$t-" || rc=1
  done
  return $rc
}
audit() { cargo deny --locked check && cargo deny --locked --manifest-path fuzz/Cargo.toml check; }

declare -A RESULT
fail=0
for j in "${JOBS[@]}"; do
  echo "=== $j"
  start=$SECONDS
  if "$j"; then RESULT[$j]="PASS $((SECONDS - start))s"; else RESULT[$j]="FAIL $((SECONDS - start))s"; fail=1; fi
done
echo "=== summary"
for j in "${JOBS[@]}"; do echo "$j: ${RESULT[$j]}"; done
exit $fail
