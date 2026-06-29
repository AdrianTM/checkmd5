# checkmd5 (Rust port)

A Rust port of the checkmd5 integrity checker. It reads `md5sum`-style list
files and verifies that each listed file still matches its recorded MD5 digest,
with aggregate progress reporting, cancellation, and optional parallel hashing.

The command-line interface, exit codes, and list-file format are unchanged from
the C++/Qt version; see `checkmd5.1` for the full manual.

## Building

```bash
cargo build --release      # binary at target/release/checkmd5
```

## Testing

```bash
cargo test                 # unit + end-to-end tests
cargo clippy --all-targets # lints
cargo fmt --check          # formatting
```

The integration tests in `tests/integration.rs` mirror the original CTest
fixtures (success, mismatch, malformed list, missing target, machine output,
parallel, relative paths). The unit tests cross-check the MD5 digests against
known vectors.

## Usage

```bash
checkmd5 [--force] [--verbose] [--machine] [--log=file] [--jobs=count] file.md5 [file2.md5 ...]
```

- `--force`     keep checking after a failure instead of stopping.
- `--verbose`   print per-target results to stderr.
- `--machine`   emit only bare percentages on stdout, for scripts.
- `--log=file`  write a plain-text English log of the run.
- `--jobs=N`    hash up to `N` files in parallel; `0` picks a count automatically.

Progress is written to stdout; all human-facing messages go to stderr, so
`--machine` stdout stays a clean stream of `NN%` lines. Exit codes: `0` pass,
`1` mismatch, `2` aborted, `3` bad/unreadable list, `4` OS error.

## Notes on the port

This is an idiomatic rewrite rather than a line-by-line translation:

- **MD5** uses the audited [`md-5`](https://crates.io/crates/md-5) crate (RustCrypto)
  instead of the hand-rolled, pointer-casting implementation.
- **CLI** uses [`clap`](https://crates.io/crates/clap) derive.
- **Signals** use [`signal-hook`](https://crates.io/crates/signal-hook).
- **Parallel hashing** uses `std::thread::scope` with worker threads pulling
  from a shared atomic index and reporting results over an `mpsc` channel; the
  dispatcher wakes on each completion (or every 20 ms) to refresh progress.

The original C++/Qt sources are retained in the repository for reference and can
be removed once the Rust port is adopted.
