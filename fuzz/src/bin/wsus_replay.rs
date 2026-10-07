//! Replay files through a wsus-protocol harness without instrumentation.
use std::{env, error::Error, fs};

#[allow(dead_code)]
#[path = "../wsus.rs"]
mod wsus;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let usage = "usage: wsus_replay TARGET FILE...";
    let target = args.next().ok_or(usage)?;
    let files: Vec<_> = args.collect();
    if files.is_empty() {
        return Err(usage.into());
    }
    for file in files {
        eprintln!("replaying {target}: {file}");
        wsus::run(&target, &fs::read(file)?)?;
    }
    Ok(())
}
