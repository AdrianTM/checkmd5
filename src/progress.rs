//! Aggregate progress reporting.
//!
//! Progress is expressed as a whole-number percentage of total bytes hashed.
//! Updates are throttled two ways so we neither spam the terminal nor a
//! `--machine` consumer: the byte counter only triggers a recompute roughly
//! every `1/PROGRESS_STEPS` of the total, and a line is only emitted when the
//! rounded percentage actually changes.

use std::io::{self, Write};

/// Number of byte-count buckets across the whole job; bounds how often the
/// percentage is recomputed during a long-running hash.
const PROGRESS_STEPS: u64 = 1000;

pub struct Progress {
    total: u64,
    machine: bool,
    /// Byte count at which the next recompute is allowed.
    next_update_at: u64,
    /// Highest byte count we've already reported for (parallel refresh guard).
    last_notified: u64,
    /// Last whole percent written; `None` means nothing shown yet.
    last_percent: Option<u32>,
}

impl Progress {
    pub fn new(total: u64, machine: bool) -> Self {
        Self {
            total,
            machine,
            next_update_at: 0,
            last_notified: 0,
            last_percent: None,
        }
    }

    /// Refresh from a possibly-stale byte count (used by the parallel
    /// dispatcher). Skips work when the count hasn't advanced and we're not yet
    /// at completion.
    pub fn refresh(&mut self, processed: u64) {
        if processed <= self.last_notified && processed < self.total {
            return;
        }
        self.update(processed);
    }

    /// Report that `processed` bytes have been hashed so far.
    pub fn update(&mut self, processed: u64) {
        if processed < self.next_update_at && processed < self.total {
            return;
        }

        let percent = if self.total > 0 {
            ((100.0 * processed as f64) / self.total as f64).round() as u32
        } else {
            0
        }
        .min(100);

        if self.last_percent != Some(percent) {
            self.last_percent = Some(percent);
            self.write(percent);
        }

        self.last_notified = processed;
        self.next_update_at = if self.total > 0 {
            let step = (self.total / PROGRESS_STEPS).max(1);
            ((processed / step) + 1) * step
        } else {
            processed + 1
        };
    }

    fn write(&self, percent: u32) {
        let mut out = io::stdout().lock();
        // `--machine` output is parsed by scripts: one bare percentage per
        // line. Interactive output redraws a single line with a carriage
        // return. Either way progress goes to stdout; all human messages go to
        // stderr so `--machine` stdout stays clean.
        let _ = if self.machine {
            writeln!(out, "{percent}%")
        } else {
            write!(out, "Checking: {percent}%\r")
        };
        let _ = out.flush();
    }
}
