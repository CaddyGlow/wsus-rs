//! Structured logging.
//!
//! Every operation emits one summary event with `operation`,
//! `correlation_id`, `duration_ms`, `outcome`, `fault_code`, `counts` and,
//! where known, `server_generation`. Output goes through a sanitizing writer
//! (see [`crate::redact`]). Full debug tracing to a file is opt-in
//! (`--trace-file`); the file is sanitized line by line before it reaches disk.

use crate::redact::sanitize;
use anyhow::{Context, Result};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
    sync::{Arc, Mutex},
    time::Instant,
};
use tracing_subscriber::{
    EnvFilter, Layer, fmt::MakeWriter, layer::SubscriberExt, util::SubscriberInitExt,
};
use uuid::Uuid;
use wsus_client::{session::WuspError, sync::SyncError};

/// Writer that sanitizes every complete line before forwarding it.
pub struct SanitizingWriter<W: Write> {
    inner: W,
    pending: Vec<u8>,
}

impl<W: Write> SanitizingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            pending: Vec::new(),
        }
    }

    fn drain(&mut self, all: bool) -> io::Result<()> {
        while let Some(pos) = self.pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=pos).collect();
            let text = String::from_utf8_lossy(&line);
            self.inner.write_all(sanitize(&text).as_bytes())?;
        }
        if all && !self.pending.is_empty() {
            let rest = std::mem::take(&mut self.pending);
            self.inner
                .write_all(sanitize(&String::from_utf8_lossy(&rest)).as_bytes())?;
        }
        Ok(())
    }
}

impl<W: Write> Write for SanitizingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buf);
        self.drain(false)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain(true)?;
        self.inner.flush()
    }
}

impl<W: Write> Drop for SanitizingWriter<W> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[derive(Clone)]
struct StderrMaker;

impl<'a> MakeWriter<'a> for StderrMaker {
    type Writer = SanitizingWriter<io::Stderr>;
    fn make_writer(&'a self) -> Self::Writer {
        SanitizingWriter::new(io::stderr())
    }
}

#[derive(Clone)]
struct FileMaker(Arc<Mutex<File>>);

struct SharedFile(Arc<Mutex<File>>);

impl Write for SharedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).flush()
    }
}

impl<'a> MakeWriter<'a> for FileMaker {
    type Writer = SanitizingWriter<SharedFile>;
    fn make_writer(&'a self) -> Self::Writer {
        SanitizingWriter::new(SharedFile(self.0.clone()))
    }
}

/// Logging options resolved from the command line and configuration.
#[derive(Debug, Clone)]
pub struct LogOptions {
    pub level: String,
    pub json: bool,
    /// Extra `-v` flags: 1 = debug, 2 = trace.
    pub verbose: u8,
    pub trace_file: Option<std::path::PathBuf>,
}

/// Installs the global subscriber. Safe to call once per process; a second
/// call (tests) is ignored.
pub fn init(options: &LogOptions) -> Result<()> {
    let level = match options.verbose {
        0 => options.level.clone(),
        1 => "debug".into(),
        _ => "trace".into(),
    };
    let filter = EnvFilter::try_new(&level).context("invalid logging.level")?;
    let console = if options.json {
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(StderrMaker)
            .with_filter(filter)
            .boxed()
    } else {
        tracing_subscriber::fmt::layer()
            .with_writer(StderrMaker)
            .with_target(false)
            .with_filter(filter)
            .boxed()
    };
    let trace = match &options.trace_file {
        Some(path) => Some(open_trace_file(path)?),
        None => None,
    };
    let trace_layer = trace.map(|file| {
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(FileMaker(file))
            .with_filter(EnvFilter::new("debug"))
    });
    let _ = tracing_subscriber::registry()
        .with(console)
        .with(trace_layer)
        .try_init();
    Ok(())
}

fn open_trace_file(path: &Path) -> Result<Arc<Mutex<File>>> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts
        .open(path)
        .with_context(|| format!("cannot open trace file {}", path.display()))?;
    Ok(Arc::new(Mutex::new(file)))
}

/// Fault code carried anywhere in an error chain, if the failure was a SOAP
/// fault answered by the server.
pub fn fault_code_of(error: &anyhow::Error) -> Option<String> {
    for cause in error.chain() {
        if let Some(e) = cause.downcast_ref::<WuspError>()
            && let Some(code) = e.fault_code()
        {
            return Some(code.as_str().to_owned());
        }
        if let Some(SyncError::Session(e)) = cause.downcast_ref::<SyncError>()
            && let Some(code) = e.fault_code()
        {
            return Some(code.as_str().to_owned());
        }
    }
    None
}

/// Extra fields of the summary event.
#[derive(Debug, Default, Clone)]
pub struct OpFields {
    pub counts: Vec<(&'static str, u64)>,
    pub server_generation: Option<String>,
}

/// Timer and correlation id of one operation.
pub struct Op {
    name: &'static str,
    correlation_id: Uuid,
    started: Instant,
}

impl Op {
    pub fn start(name: &'static str) -> Self {
        let op = Self {
            name,
            correlation_id: Uuid::new_v4(),
            started: Instant::now(),
        };
        tracing::debug!(operation = name, correlation_id = %op.correlation_id, "operation started");
        op
    }

    pub fn correlation_id(&self) -> Uuid {
        self.correlation_id
    }

    /// Emits the summary event.
    pub fn finish<T>(&self, result: &Result<T>, fields: &OpFields) {
        let counts = fields
            .counts
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(",");
        let duration_ms = self.started.elapsed().as_millis() as u64;
        let generation = fields.server_generation.as_deref().unwrap_or("");
        match result {
            Ok(_) => tracing::info!(
                operation = self.name,
                correlation_id = %self.correlation_id,
                duration_ms,
                outcome = "ok",
                fault_code = "",
                server_generation = generation,
                counts = %counts,
                "operation finished"
            ),
            Err(e) => tracing::warn!(
                operation = self.name,
                correlation_id = %self.correlation_id,
                duration_ms,
                outcome = "error",
                fault_code = fault_code_of(e).as_deref().unwrap_or(""),
                server_generation = generation,
                counts = %counts,
                error = %sanitize(&format!("{e:#}")),
                "operation failed"
            ),
        }
    }
}
