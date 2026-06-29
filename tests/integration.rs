//! End-to-end tests mirroring the original CTest fixtures: each builds a small
//! checksum list in a scratch directory, runs the compiled binary against it,
//! and asserts on the exit status (and, for `--machine`, on stream routing).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_checkmd5");
const HELLO_MD5: &str = "5d41402abc4b2a76b9719d911017c592";

/// Create a fresh, uniquely named fixture directory under the test tmp dir.
fn fixture_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run the binary in `workdir` with `args` and return its captured output.
fn run(workdir: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .current_dir(workdir)
        .output()
        .expect("failed to spawn checkmd5")
}

fn exit_code(output: &Output) -> i32 {
    output.status.code().expect("process terminated by signal")
}

#[test]
fn success() {
    let dir = fixture_dir("success");
    fs::write(dir.join("test_data.txt"), "hello").unwrap();
    fs::write(
        dir.join("good.md5"),
        format!("{HELLO_MD5}  test_data.txt\n"),
    )
    .unwrap();

    assert_eq!(exit_code(&run(&dir, &["good.md5"])), 0);
}

#[test]
fn relative_path_resolved_against_list() {
    let dir = fixture_dir("relative");
    fs::create_dir_all(dir.join("data")).unwrap();
    fs::write(dir.join("data/test_data.txt"), "hello").unwrap();
    fs::write(
        dir.join("relative.md5"),
        format!("{HELLO_MD5}  data/test_data.txt\n"),
    )
    .unwrap();

    // Run from a different cwd to prove the path is resolved relative to the
    // list file, not the working directory.
    assert_eq!(
        exit_code(&run(
            Path::new(env!("CARGO_TARGET_TMPDIR")),
            &[dir.join("relative.md5").to_str().unwrap()]
        )),
        0
    );
}

#[test]
fn appends_md5_extension() {
    let dir = fixture_dir("append_ext");
    fs::write(dir.join("test_data.txt"), "hello").unwrap();
    fs::write(
        dir.join("good.md5"),
        format!("{HELLO_MD5}  test_data.txt\n"),
    )
    .unwrap();

    // Passing "good" should auto-append ".md5".
    assert_eq!(exit_code(&run(&dir, &["good"])), 0);
}

#[test]
fn machine_output_goes_to_stdout_only() {
    let dir = fixture_dir("machine");
    fs::write(dir.join("test_data.txt"), "hello").unwrap();
    fs::write(
        dir.join("good.md5"),
        format!("{HELLO_MD5}  test_data.txt\n"),
    )
    .unwrap();

    let output = run(&dir, &["--machine", "good.md5"]);
    assert_eq!(exit_code(&output), 0);
    assert!(!output.stdout.is_empty(), "--machine produced no stdout");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.lines().any(|line| line.trim_end().ends_with('%')
            && line
                .trim_end_matches('%')
                .chars()
                .all(|c| c.is_ascii_digit())),
        "progress percentage leaked to stderr: {stderr:?}"
    );
}

#[test]
fn machine_mismatch_reports_failure() {
    let dir = fixture_dir("machine_mismatch");
    fs::write(dir.join("test_data.txt"), "hello").unwrap();
    fs::write(
        dir.join("mismatch.md5"),
        "00000000000000000000000000000000  test_data.txt\n",
    )
    .unwrap();

    assert_eq!(exit_code(&run(&dir, &["--machine", "mismatch.md5"])), 1);
}

#[test]
fn parallel_success() {
    let dir = fixture_dir("parallel");
    fs::write(dir.join("a.txt"), "hello").unwrap();
    fs::write(dir.join("b.txt"), "hello").unwrap();
    fs::write(
        dir.join("good.md5"),
        format!("{HELLO_MD5}  a.txt\n{HELLO_MD5}  b.txt\n"),
    )
    .unwrap();

    assert_eq!(exit_code(&run(&dir, &["--jobs=2", "good.md5"])), 0);
}

#[test]
fn mismatch_reports_failure() {
    let dir = fixture_dir("mismatch");
    fs::write(dir.join("test_data.txt"), "hello").unwrap();
    fs::write(
        dir.join("mismatch.md5"),
        "00000000000000000000000000000000  test_data.txt\n",
    )
    .unwrap();

    assert_eq!(exit_code(&run(&dir, &["mismatch.md5"])), 1);
}

#[test]
fn missing_target_reports_bad_list() {
    let dir = fixture_dir("missing");
    fs::write(
        dir.join("missing.md5"),
        "d41d8cd98f00b204e9800998ecf8427e  missing-file.txt\n",
    )
    .unwrap();

    assert_eq!(exit_code(&run(&dir, &["missing.md5"])), 3);
}

#[test]
fn malformed_list_reports_bad_list() {
    let dir = fixture_dir("malformed");
    fs::write(dir.join("malformed.md5"), "not-an-md5 line\n").unwrap();

    assert_eq!(exit_code(&run(&dir, &["malformed.md5"])), 3);
}

#[test]
fn force_continues_past_mismatch() {
    let dir = fixture_dir("force");
    fs::write(dir.join("test_data.txt"), "hello").unwrap();
    fs::write(
        dir.join("mixed.md5"),
        format!("00000000000000000000000000000000  test_data.txt\n{HELLO_MD5}  test_data.txt\n"),
    )
    .unwrap();

    // Overall result is still failure, but --force checks every entry.
    assert_eq!(exit_code(&run(&dir, &["--force", "mixed.md5"])), 1);
}
