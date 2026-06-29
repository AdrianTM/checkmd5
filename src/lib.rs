//! Core library for `checkmd5`: load MD5 checksum lists and verify the files
//! they reference, with progress reporting, cancellation and optional parallel
//! hashing.

pub mod checker;
pub mod progress;

pub use checker::{Checker, Config, ExitCode};
