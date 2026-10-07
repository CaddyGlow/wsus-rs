//! Drives one `ServicingBackend` directly on a Windows guest (docs/wsus-install.md, DISM API run).
//!
//! `servicing_probe <dism|dism_api> list|info <cab>|add <cab> <log_dir> <timeout_secs>`; needs the
//! `cbs-handler` feature. Prints the results; the package listing is taken before and after an add
//! and the difference is printed. `PROBE_EXIT_AFTER_ADD=1` ends the process right after the add result. Local files only: no WSUS or network access.

#[cfg(all(windows, feature = "cbs-handler"))]
fn main() {
    use std::{path::Path, sync::Arc, time::Duration};
    use wsus_client::install::{
        runner::ProcessRunner,
        servicing::{ServicingBackend, dism::DismBackend, dism_api::DismApiBackend},
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let sys = wsus_client::install::win_util::system_directory().expect("system directory");
    let backend: Box<dyn ServicingBackend> = match args.first().map(String::as_str) {
        Some("dism") => Box::new(DismBackend::new(Arc::new(ProcessRunner), sys)),
        Some("dism_api") => Box::new(DismApiBackend::load(&sys).expect("load DismApi.dll")),
        _ => return eprintln!("usage: servicing_probe <dism|dism_api> list|info|add ..."),
    };
    println!("backend {}", backend.name());
    match args.get(1).map(String::as_str) {
        Some("list") => {
            let s = backend.list_packages().expect("list");
            for p in &s.packages {
                println!("{} | {}", p.identity, p.state);
            }
            println!("count {} digest {}", s.packages.len(), s.digest());
        }
        Some("info") => {
            let cab = Path::new(&args[2]);
            println!("applicability {:?}", backend.payload_applicability(cab));
        }
        Some("add") => {
            let cab = Path::new(&args[2]);
            let log = Path::new(&args[3]);
            let timeout = Duration::from_secs(args[4].parse().expect("timeout secs"));
            let before = backend.list_packages().expect("list before");
            println!(
                "before: {} packages {}",
                before.packages.len(),
                before.digest()
            );
            println!("applicability {:?}", backend.payload_applicability(cab));
            let t = std::time::Instant::now();
            let r = backend.add_package(cab, log, timeout);
            println!("add took {:?}", t.elapsed());
            println!("{r:#?}");
            if std::env::var_os("PROBE_EXIT_AFTER_ADD").is_some() {
                // simulates a client that ends right after a timed-out add
                std::process::exit(0);
            }
            println!("pending {:?}", backend.pending_indicators());
            let after = backend.list_packages().expect("list after");
            println!(
                "after: {} packages {}",
                after.packages.len(),
                after.digest()
            );
            for d in after.diff_from(&before) {
                println!("diff {d}");
            }
        }
        _ => eprintln!("usage: servicing_probe <dism|dism_api> list|info|add ..."),
    }
}

#[cfg(not(all(windows, feature = "cbs-handler")))]
fn main() {
    eprintln!("servicing_probe needs Windows and the cbs-handler feature");
}
