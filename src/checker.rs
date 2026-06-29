//! Checksum-list loading and verification.
//!
//! A *list* is an `md5sum`-style file: each line is a 32-character hex MD5
//! digest, some whitespace, then a path (resolved relative to the list file).
//! [`Checker::run`] loads every list, hashes every referenced file and reports
//! whether the computed digests match, serially or across worker threads.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use md5::{Digest, Md5};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};

use crate::progress::Progress;

const MD5_HASH_LENGTH: usize = 32;
const MIN_CHECKSUM_LINE_LENGTH: usize = MD5_HASH_LENGTH + 2;
const HASH_BUFFER_SIZE: usize = 256 * 1024;

/// How often the parallel dispatcher wakes to refresh progress while workers
/// are busy. Completions wake it immediately via the channel; this only bounds
/// how stale the percentage can get during a long single-file hash.
const PROGRESS_REFRESH: Duration = Duration::from_millis(20);

/// Process exit status. Non-zero values may change in future versions; the only
/// guarantee is `Ok` on success and non-zero on failure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExitCode {
    /// Every file matched its expected hash.
    Ok = 0,
    /// At least one file did not match (or could not be read).
    BadCheck = 1,
    /// The user interrupted the check before it finished.
    Aborted = 2,
    /// A list was unreadable, malformed, or referenced a missing file.
    BadList = 3,
    /// An operating-system level error occurred.
    System = 4,
}

impl ExitCode {
    pub fn code(self) -> i32 {
        self as i32
    }
}

/// Runtime options, normally built from the command line.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// Keep checking after a failure instead of stopping at the first one.
    pub force: bool,
    /// Log per-target progress to stderr as well as to the log file.
    pub verbose: bool,
    /// Emit only bare percentages on stdout, for script consumption.
    pub machine: bool,
    /// Files to hash in parallel; `0` selects a thread count automatically.
    pub jobs: usize,
    /// Optional path to a plain-text log file.
    pub log_file: Option<PathBuf>,
}

/// One verified entry: an expected hash and the resolved file it applies to.
struct Target {
    hash: String,
    path: PathBuf,
    size: u64,
}

/// Why a streaming hash stopped early.
enum StopReason {
    /// A termination signal was received.
    Aborted,
    /// Another failure asked outstanding work to wind down.
    Skipped,
}

/// Result of hashing a single file.
enum HashOutcome {
    /// Finished; carries the uppercase hex digest.
    Done(String),
    Aborted,
    Skipped,
    /// An I/O error occurred; carries a human-readable description.
    Error(String),
}

pub struct Checker {
    config: Config,
    log: Option<File>,
    /// Set to the signal number by the signal handler; `0` means none.
    signal: Arc<AtomicUsize>,
}

impl Checker {
    /// Create a checker, opening the log file (if any) and installing handlers
    /// for SIGINT/SIGTERM/SIGHUP so a check can be interrupted cleanly.
    pub fn new(config: Config) -> std::io::Result<Self> {
        let log = match &config.log_file {
            Some(path) => Some(File::create(path)?),
            None => None,
        };

        let signal = Arc::new(AtomicUsize::new(0));
        for sig in [SIGINT, SIGTERM, SIGHUP] {
            signal_hook::flag::register_usize(sig, Arc::clone(&signal), sig as usize)?;
        }

        Ok(Self {
            config,
            log,
            signal,
        })
    }

    /// Load every list, verify the referenced files, and return an exit status.
    pub fn run(&mut self, files: &[PathBuf]) -> ExitCode {
        self.log_start(files);

        let targets = self.load_targets(files);
        if targets.is_empty() {
            self.write_log("Exit: 3\n");
            return ExitCode::BadList;
        }

        let result = match self.resolve_jobs() {
            1 => self.check_serial(&targets),
            jobs => self.check_parallel(&targets, jobs),
        };

        if !self.config.machine {
            eprintln!(
                "{}",
                match result {
                    ExitCode::Ok => "The integrity check has passed.",
                    ExitCode::BadCheck => "The integrity check has failed.",
                    ExitCode::Aborted => "The integrity check was aborted.",
                    _ => "The integrity check could not be completed.",
                }
            );
        }

        self.write_log(&format!("Exit: {}\n", result.code()));
        result
    }

    /// Resolve the effective worker count: `0` means "pick automatically",
    /// anything else is clamped to at least one.
    fn resolve_jobs(&self) -> usize {
        match self.config.jobs {
            0 => thread::available_parallelism().map_or(1, |n| n.get()),
            n => n,
        }
        .max(1)
    }

    fn load_targets(&mut self, files: &[PathBuf]) -> Vec<Target> {
        let mut targets = Vec::new();

        for raw in files {
            let filename = ensure_md5_extension(raw, &mut |name| {
                eprintln!("Note: Appending .md5 extension to {name}");
            });

            // The base directory is the same for every line in this list, so
            // resolve it once.
            let base_dir = match std::path::absolute(&filename) {
                Ok(abs) => abs.parent().map(Path::to_path_buf).unwrap_or_default(),
                Err(e) => {
                    self.log(true, &format!("ERROR: {e}: {}\n", filename.display()));
                    return Vec::new();
                }
            };

            let file = match File::open(&filename) {
                Ok(f) => f,
                Err(e) => {
                    self.log(true, &format!("ERROR: {e}: {}\n", filename.display()));
                    return Vec::new();
                }
            };

            for (index, line) in BufReader::new(file).lines().enumerate() {
                let line_number = index + 1;
                let line = match line {
                    Ok(line) => line,
                    Err(e) => {
                        self.log(
                            true,
                            &format!("ERROR ({} line {line_number}): {e}\n", filename.display()),
                        );
                        return Vec::new();
                    }
                };

                match self.parse_line(line.trim(), &filename, line_number, &base_dir) {
                    Some(target) => targets.push(target),
                    None => return Vec::new(),
                }
            }
        }

        targets
    }

    /// Parse one trimmed list line into a [`Target`], logging and returning
    /// `None` on any malformed entry or missing file.
    fn parse_line(
        &mut self,
        line: &str,
        filename: &Path,
        line_number: usize,
        base_dir: &Path,
    ) -> Option<Target> {
        let list = filename.display();

        if line.len() < MIN_CHECKSUM_LINE_LENGTH {
            self.log(
                true,
                &format!("ERROR ({list} line {line_number}): Line too short.\n"),
            );
            return None;
        }

        let hash: String = line.chars().take(MD5_HASH_LENGTH).collect();
        if hash.len() != MD5_HASH_LENGTH || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            self.log(
                true,
                &format!("ERROR ({list} line {line_number}): Invalid hex or too short for MD5.\n"),
            );
            return None;
        }
        let hash = hash.to_ascii_uppercase();

        // Hash is 32 ASCII bytes, so byte index 32 is a valid char boundary.
        let path = line[MD5_HASH_LENGTH..].trim_start_matches([' ', '\t']);
        if path.is_empty() {
            self.log(
                true,
                &format!("ERROR ({list} line {line_number}): No space or path.\n"),
            );
            return None;
        }

        let resolved = base_dir.join(path);
        let metadata = match std::fs::metadata(&resolved) {
            Ok(m) => m,
            Err(_) => {
                let shown = std::path::absolute(&resolved).unwrap_or(resolved);
                self.log(
                    true,
                    &format!(
                        "ERROR ({list} line {line_number}): Cannot stat: {}\n",
                        shown.display()
                    ),
                );
                return None;
            }
        };

        Some(Target {
            hash,
            path: std::path::absolute(&resolved).unwrap_or(resolved),
            size: metadata.len(),
        })
    }

    fn check_serial(&mut self, targets: &[Target]) -> ExitCode {
        if !self.config.machine {
            eprintln!("Press [Ctrl+C] to abort the integrity check.");
        }

        let verbose = self.config.verbose;
        let machine = self.config.machine;
        let force = self.config.force;
        let total: u64 = targets.iter().map(|t| t.size).sum();
        let signal = Arc::clone(&self.signal);

        let mut progress = Progress::new(total, machine);
        let mut processed = 0u64;
        let mut passed = 0usize;
        let mut passed_size = 0u64;
        let mut result = ExitCode::Ok;

        for target in targets {
            self.log(
                verbose,
                &format!("Target: {} {}\n", target.hash, target.path.display()),
            );

            let file = match File::open(&target.path) {
                Ok(f) => f,
                Err(e) => {
                    self.log(true, &format!("{e}: {}\n", target.path.display()));
                    result = ExitCode::BadCheck;
                    if !force {
                        break;
                    }
                    processed += target.size;
                    continue;
                }
            };

            progress.update(processed);
            let outcome = stream_hash(
                file,
                |n| {
                    processed += n;
                    progress.update(processed);
                },
                || (signal.load(Ordering::Relaxed) != 0).then_some(StopReason::Aborted),
            );

            match outcome {
                HashOutcome::Aborted => {
                    if !machine {
                        eprintln!();
                    }
                    self.log(
                        verbose,
                        &format!("Aborted: (signal {})\n", signal.load(Ordering::Relaxed)),
                    );
                    result = ExitCode::Aborted;
                    break;
                }
                HashOutcome::Skipped => break, // not requested in serial mode
                HashOutcome::Error(e) => {
                    self.log(true, &format!("{e}: {}\n", target.path.display()));
                    result = ExitCode::BadCheck;
                    if !force {
                        break;
                    }
                }
                HashOutcome::Done(computed) => {
                    if verbose && !machine {
                        eprintln!(); // break the progress line
                    }
                    let matches = target.hash == computed;
                    self.log(
                        verbose,
                        &format!(
                            "{}: {computed} {}\n",
                            if matches { "Passed" } else { "Failed" },
                            target.path.display()
                        ),
                    );
                    if matches {
                        passed += 1;
                        passed_size += target.size;
                    } else {
                        if !verbose && !machine {
                            eprintln!();
                        }
                        eprintln!("Checksum mismatch : {}", target.path.display());
                        result = ExitCode::BadCheck;
                        if !force {
                            break;
                        }
                    }
                }
            }
        }

        if !verbose && !machine {
            eprintln!(); // break the progress line
        }
        self.log(
            verbose,
            &format!(
                "Result: {passed}/{} targets ({passed_size}/{total} bytes) passed\n",
                targets.len()
            ),
        );

        result
    }

    fn check_parallel(&mut self, targets: &[Target], jobs: usize) -> ExitCode {
        if !self.config.machine {
            eprintln!("Press [Ctrl+C] to abort the integrity check.");
        }

        let verbose = self.config.verbose;
        let machine = self.config.machine;
        let force = self.config.force;
        let total: u64 = targets.iter().map(|t| t.size).sum();

        let processed = AtomicU64::new(0);
        let stop = AtomicBool::new(false);
        let next_index = AtomicUsize::new(0);
        let signal = Arc::clone(&self.signal);

        // Each result identifies its target by index so the dispatcher can look
        // up the hash/path without the worker copying them.
        let (tx, rx) = mpsc::channel::<(usize, HashOutcome)>();

        thread::scope(|scope| {
            for _ in 0..jobs {
                let tx = tx.clone();
                let (processed, stop, next_index, signal) =
                    (&processed, &stop, &next_index, &signal);
                scope.spawn(move || loop {
                    if signal.load(Ordering::Relaxed) != 0
                        || (!force && stop.load(Ordering::Acquire))
                    {
                        break;
                    }
                    let index = next_index.fetch_add(1, Ordering::Relaxed);
                    let Some(target) = targets.get(index) else {
                        break;
                    };

                    let outcome = match File::open(&target.path) {
                        Ok(file) => stream_hash(
                            file,
                            |n| {
                                processed.fetch_add(n, Ordering::Relaxed);
                            },
                            || {
                                if signal.load(Ordering::Relaxed) != 0 {
                                    Some(StopReason::Aborted)
                                } else if stop.load(Ordering::Acquire) {
                                    Some(StopReason::Skipped)
                                } else {
                                    None
                                }
                            },
                        ),
                        Err(e) => HashOutcome::Error(e.to_string()),
                    };

                    if tx.send((index, outcome)).is_err() {
                        break;
                    }
                });
            }
            // Drop the template sender so the channel disconnects once every
            // worker has finished, ending the dispatch loop below.
            drop(tx);

            let mut progress = Progress::new(total, machine);
            let mut passed = 0usize;
            let mut passed_size = 0u64;
            let mut result = ExitCode::Ok;

            loop {
                let (index, outcome) = match rx.recv_timeout(PROGRESS_REFRESH) {
                    Ok(received) => received,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        progress.refresh(processed.load(Ordering::Relaxed));
                        continue;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };
                progress.refresh(processed.load(Ordering::Relaxed));

                let target = &targets[index];
                match outcome {
                    HashOutcome::Aborted => {
                        if result != ExitCode::Aborted {
                            if !machine {
                                eprintln!();
                            }
                            self.log(
                                verbose,
                                &format!("Aborted: (signal {})\n", signal.load(Ordering::Relaxed)),
                            );
                            result = ExitCode::Aborted;
                            stop.store(true, Ordering::Release);
                        }
                    }
                    HashOutcome::Skipped => {}
                    HashOutcome::Error(e) => {
                        self.log(true, &format!("{e}: {}\n", target.path.display()));
                        result = ExitCode::BadCheck;
                        if !force {
                            stop.store(true, Ordering::Release);
                        }
                    }
                    HashOutcome::Done(computed) => {
                        self.log(
                            verbose,
                            &format!("Target: {} {}\n", target.hash, target.path.display()),
                        );
                        let matches = target.hash == computed;
                        self.log(
                            verbose,
                            &format!(
                                "{}: {computed} {}\n",
                                if matches { "Passed" } else { "Failed" },
                                target.path.display()
                            ),
                        );
                        if matches {
                            passed += 1;
                            passed_size += target.size;
                        } else {
                            if !verbose && !machine {
                                eprintln!();
                            }
                            eprintln!("Checksum mismatch : {}", target.path.display());
                            result = ExitCode::BadCheck;
                            if !force {
                                stop.store(true, Ordering::Release);
                            }
                        }
                    }
                }
            }

            if !verbose && !machine {
                eprintln!();
            }
            progress.refresh(total);
            self.log(
                verbose,
                &format!(
                    "Result: {passed}/{} targets ({passed_size}/{total} bytes) passed\n",
                    targets.len()
                ),
            );

            result
        })
    }

    fn log_start(&mut self, files: &[PathBuf]) {
        let mut message = format!("Start: {}\nLists:", format_timestamp());
        for file in files {
            let _ = write!(message, " {}", file.display());
        }
        message.push('\n');
        self.write_log(&message);
    }

    /// Write to the log file only.
    fn write_log(&mut self, message: &str) {
        if let Some(file) = &mut self.log {
            let _ = file.write_all(message.as_bytes());
            let _ = file.flush();
        }
    }

    /// Write to the log file, and to stderr when `console` is set.
    fn log(&mut self, console: bool, message: &str) {
        self.write_log(message);
        if console {
            eprint!("{message}");
        }
    }
}

/// Stream `file` through MD5, reporting cumulative bytes via `on_bytes` and
/// polling `should_stop` between reads so a signal or cancellation takes effect
/// promptly. Returns the uppercase hex digest on success.
fn stream_hash<P, S>(mut file: File, mut on_bytes: P, mut should_stop: S) -> HashOutcome
where
    P: FnMut(u64),
    S: FnMut() -> Option<StopReason>,
{
    let mut hasher = Md5::new();
    let mut buffer = vec![0u8; HASH_BUFFER_SIZE];

    loop {
        match should_stop() {
            Some(StopReason::Aborted) => return HashOutcome::Aborted,
            Some(StopReason::Skipped) => return HashOutcome::Skipped,
            None => {}
        }

        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return HashOutcome::Error(e.to_string()),
        };
        hasher.update(&buffer[..read]);
        on_bytes(read as u64);
    }

    HashOutcome::Done(to_hex_upper(&hasher.finalize()))
}

/// Append `.md5` to `path` unless its name already ends in `.md5` (any case),
/// invoking `note` with the original name when an extension is added.
fn ensure_md5_extension(path: &Path, note: &mut dyn FnMut(&str)) -> PathBuf {
    let name = path.as_os_str().to_string_lossy();
    if name.to_ascii_lowercase().ends_with(".md5") {
        return path.to_path_buf();
    }
    note(&name);
    let mut name = path.to_path_buf().into_os_string();
    name.push(".md5");
    PathBuf::from(name)
}

fn to_hex_upper(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02X}");
    }
    hex
}

/// Format the current time as `YYYY-MM-DD HH:MM:SS UTC` for the log header,
/// without pulling in a date/time dependency.
fn format_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs()) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

/// Convert a count of days since the Unix epoch into a `(year, month, day)`
/// civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_md5_digests() {
        assert_eq!(
            to_hex_upper(&Md5::digest(b"")),
            "D41D8CD98F00B204E9800998ECF8427E"
        );
        assert_eq!(
            to_hex_upper(&Md5::digest(b"hello")),
            "5D41402ABC4B2A76B9719D911017C592"
        );
        assert_eq!(
            to_hex_upper(&Md5::digest(b"abc")),
            "900150983CD24FB0D6963F7D28E17F72"
        );
    }

    #[test]
    fn md5_handles_multi_block_input() {
        // Larger than one 64-byte block to exercise streaming behaviour.
        let data = vec![b'a'; 1000];
        assert_eq!(
            to_hex_upper(&Md5::digest(&data)),
            "CABE45DCC9AE5B66BA86600CCA6B8BA8"
        );
    }

    #[test]
    fn appends_md5_extension_when_missing() {
        let mut noted = None;
        let out = ensure_md5_extension(Path::new("sums.txt"), &mut |n| noted = Some(n.to_string()));
        assert_eq!(out, PathBuf::from("sums.txt.md5"));
        assert_eq!(noted.as_deref(), Some("sums.txt"));
    }

    #[test]
    fn keeps_existing_md5_extension_any_case() {
        let mut called = false;
        let out = ensure_md5_extension(Path::new("sums.MD5"), &mut |_| called = true);
        assert_eq!(out, PathBuf::from("sums.MD5"));
        assert!(!called);
    }

    #[test]
    fn civil_date_matches_known_epochs() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(18_993), (2022, 1, 1));
    }
}
