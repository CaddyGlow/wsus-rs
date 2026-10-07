//! Process execution behind a trait.
//!
//! [`ProcessRunner`] starts the program directly (`std::process::Command`, no
//! shell, arguments passed as separate strings), with stdin closed, a hard
//! timeout and bounded captured output. The CLI uses it only on Windows; it is
//! plain `std` and is exercised on the host with harmless programs. Tests of
//! the executor use [`FakeRunner`].
//!
//! `msiexec.exe` is the exception to "separate arguments": it parses its own command line, and a
//! property whose value holds spaces must read `NAME="a b"`. With the whole token quoted
//! (`"NAME=a b"`, what `Command` produces) it does not understand the property, shows its usage
//! dialog and, with no desktop to dismiss it, never exits (OBSERVED on Windows 11 as SYSTEM, see
//! docs/wsus-install.md). On Windows its command line is therefore built by
//! [`msiexec_command_line`] and handed over verbatim.
//!
//! Limits: on timeout only the started process is killed, not a process tree (unless the request
//! says `kill_on_timeout: false`, in which case nothing is killed).
use std::{
    io::Read,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

/// What to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRequest {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub timeout: Duration,
    /// Maximum bytes captured per stream.
    pub output_limit: usize,
    /// Kill the process when the timeout expires. A servicing client must not kill DISM or
    /// the servicing stack mid-transaction (docs/wsus-cbs-integration.md, Q-E): with `false` the
    /// runner stops waiting, reports `timed_out`, and leaves the process running.
    pub kill_on_timeout: bool,
}

/// What happened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunResult {
    /// `None` when the process was killed on timeout.
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub output_truncated: bool,
    pub duration: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("cannot start the process: {0}")]
    Spawn(String),
    #[error("cannot wait for the process: {0}")]
    Wait(String),
}

pub trait Runner {
    fn run(&self, request: &RunRequest) -> Result<RunResult, RunnerError>;
}

/// Quote one argument the way `CommandLineToArgvW` expects (what `Command` does).
fn quote_arg(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '"']) {
        return a.to_owned();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for c in a.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            c => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// `NAME=value` where `NAME` is an installer property name.
fn msi_property(a: &str) -> Option<(&str, &str)> {
    let (n, v) = a.split_once('=')?;
    (!n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')).then_some((n, v))
}

/// Command line text for `msiexec.exe` (without the program name): properties as `NAME=value`
/// or, when the value has whitespace or quotes, `NAME="value"` with embedded quotes doubled (the
/// msiexec rule); every other argument is quoted as usual.
pub fn msiexec_command_line(args: &[String]) -> String {
    args.iter()
        .map(|a| match msi_property(a) {
            Some((n, v)) if v.contains([' ', '\t', '"']) => {
                format!("{n}=\"{}\"", v.replace('"', "\"\""))
            }
            Some(_) => a.clone(),
            None => quote_arg(a),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_msiexec(program: &std::path::Path) -> bool {
    // Both separators, so the check also holds for Windows paths on a non-Windows host (tests).
    let text = program.to_string_lossy();
    text.rsplit(['/', '\\'])
        .next()
        .is_some_and(|n| n.eq_ignore_ascii_case("msiexec.exe"))
}

/// `std::process` runner.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessRunner;

struct Capture {
    data: Mutex<(Vec<u8>, bool)>,
}

fn drain(mut stream: impl Read + Send + 'static, limit: usize) -> Arc<Capture> {
    let cap = Arc::new(Capture {
        data: Mutex::new((Vec::new(), false)),
    });
    let c = Arc::clone(&cap);
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while let Ok(n) = stream.read(&mut buf) {
            if n == 0 {
                break;
            }
            if let Ok(mut d) = c.data.lock() {
                let room = limit.saturating_sub(d.0.len());
                d.0.extend_from_slice(&buf[..n.min(room)]);
                if n > room {
                    d.1 = true;
                }
            }
        }
    });
    cap
}

impl Runner for ProcessRunner {
    fn run(&self, request: &RunRequest) -> Result<RunResult, RunnerError> {
        let mut command = Command::new(&request.program);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            if is_msiexec(&request.program) {
                command.raw_arg(msiexec_command_line(&request.args));
            } else {
                command.args(&request.args);
            }
        }
        #[cfg(not(windows))]
        {
            let _ = is_msiexec;
            command.args(&request.args);
        }
        let mut child = command
            .current_dir(&request.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| RunnerError::Spawn(e.to_string()))?;
        let out = child.stdout.take().map(|s| drain(s, request.output_limit));
        let err = child.stderr.take().map(|s| drain(s, request.output_limit));
        let start = Instant::now();
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break Some(s),
                Ok(None) => {}
                Err(e) => return Err(RunnerError::Wait(e.to_string())),
            }
            if start.elapsed() >= request.timeout {
                timed_out = true;
                if request.kill_on_timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                break None;
            }
            thread::sleep(Duration::from_millis(25));
        };
        // Give the reader threads a moment to drain what the process wrote.
        thread::sleep(Duration::from_millis(50));
        let take = |c: Option<Arc<Capture>>| {
            c.and_then(|c| c.data.lock().ok().map(|d| (d.0.clone(), d.1)))
                .unwrap_or_default()
        };
        let (stdout, t1) = take(out);
        let (stderr, t2) = take(err);
        Ok(RunResult {
            exit_code: status.and_then(|s| s.code()),
            timed_out,
            stdout,
            stderr,
            output_truncated: t1 || t2,
            duration: start.elapsed(),
        })
    }
}

type Reply = dyn Fn(&RunRequest) -> Result<RunResult, RunnerError> + Send + Sync;

/// Test double: records requests and answers through a closure.
pub struct FakeRunner {
    reply: Box<Reply>,
    calls: Mutex<Vec<RunRequest>>,
}

impl FakeRunner {
    pub fn new(
        reply: impl Fn(&RunRequest) -> Result<RunResult, RunnerError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            reply: Box::new(reply),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Always exits with `code`.
    pub fn exiting(code: i32) -> Self {
        Self::new(move |_| {
            Ok(RunResult {
                exit_code: Some(code),
                ..RunResult::default()
            })
        })
    }

    /// Requests seen so far.
    pub fn calls(&self) -> Vec<RunRequest> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

impl Runner for FakeRunner {
    fn run(&self, request: &RunRequest) -> Result<RunResult, RunnerError> {
        if let Ok(mut c) = self.calls.lock() {
            c.push(request.clone());
        }
        (self.reply)(request)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn req(program: &str, args: &[&str], timeout_ms: u64) -> RunRequest {
        RunRequest {
            program: program.into(),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            cwd: std::env::temp_dir(),
            timeout: Duration::from_millis(timeout_ms),
            output_limit: 16,
            kill_on_timeout: true,
        }
    }

    #[test]
    fn captures_exit_code_and_bounded_output() {
        let r = ProcessRunner
            .run(&req(
                "/bin/sh",
                &["-c", "printf 0123456789abcdefXYZ; exit 3"],
                5000,
            ))
            .unwrap();
        assert_eq!(r.exit_code, Some(3));
        assert_eq!(r.stdout, b"0123456789abcdef");
        assert!(r.output_truncated);
    }

    #[test]
    fn kills_on_timeout() {
        let r = ProcessRunner
            .run(&req("/bin/sh", &["-c", "sleep 30"], 200))
            .unwrap();
        assert!(r.timed_out);
        assert_eq!(r.exit_code, None);
    }

    #[test]
    fn leaves_the_process_running_when_asked_not_to_kill() {
        let mut r = req("/bin/sh", &["-c", "sleep 2; exit 7"], 150);
        r.kill_on_timeout = false;
        let started = Instant::now();
        let res = ProcessRunner.run(&r).unwrap();
        assert!(res.timed_out);
        assert_eq!(res.exit_code, None);
        // The runner returned at the timeout, long before the child's own exit.
        assert!(started.elapsed() < Duration::from_millis(1500));
    }

    #[test]
    fn missing_program_is_a_spawn_error() {
        assert!(matches!(
            ProcessRunner.run(&req("/nonexistent/prog", &[], 1000)),
            Err(RunnerError::Spawn(_))
        ));
    }

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn msiexec_properties_with_spaces_use_the_name_equals_quoted_value_form() {
        assert_eq!(
            msiexec_command_line(&v(&[
                "/i",
                r"C:\a b\p.msi",
                "LABVALUE=hello world",
                r"INSTALLDIR=C:\ProgramData\WSUS MSI Props Test Custom",
                "/qn",
                "/norestart"
            ])),
            r#"/i "C:\a b\p.msi" LABVALUE="hello world" INSTALLDIR="C:\ProgramData\WSUS MSI Props Test Custom" /qn /norestart"#
        );
    }

    #[test]
    fn msiexec_plain_values_stay_bare_and_embedded_quotes_are_doubled() {
        assert_eq!(
            msiexec_command_line(&v(&["A=1", "B=say \"hi\" now", "C="])),
            r#"A=1 B="say ""hi"" now" C="#
        );
    }

    #[test]
    fn msiexec_non_property_arguments_use_standard_quoting() {
        assert_eq!(
            msiexec_command_line(&v(&["/update", r"C:\x y\", "ODD ARG=1"])),
            r#"/update "C:\x y\\" "ODD ARG=1""#
        );
        assert_eq!(quote_arg(""), "\"\"");
    }

    #[test]
    fn only_msiexec_is_special() {
        assert!(is_msiexec(std::path::Path::new(
            r"C:\Windows\System32\MsiExec.EXE"
        )));
        assert!(!is_msiexec(std::path::Path::new("setup.exe")));
    }
}
