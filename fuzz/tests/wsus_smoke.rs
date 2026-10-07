//! Runs every wsus harness over the crate fixtures under every flags byte.
//! A panic here, including a failed round-trip assertion, is a finding.
#[allow(dead_code)]
#[path = "../src/wsus.rs"]
mod wsus;

use std::{fs, path::Path};

const TARGETS: [&str; 9] = [
    "wsus_envelope",
    "wsus_fault",
    "wsus_xml",
    "wsus_wusp",
    "wsus_wsusss",
    "wsus_metadata",
    "wsus_applicability",
    "wsus_roundtrip",
    "wsus_xpress",
];

#[test]
fn wsus_fixtures_pass_every_harness_under_every_flags_byte() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/wsus-protocol/tests/fixtures");
    let mut seen = 0;
    for entry in fs::read_dir(dir).expect("fixture directory") {
        let path = entry.expect("fixture entry").path();
        if !matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("xml" | "txt")
        ) {
            continue;
        }
        let body = fs::read(&path).expect("fixture bytes");
        for flags in 0..=u8::MAX {
            let mut input = vec![flags];
            input.extend_from_slice(&body);
            for target in TARGETS {
                eprintln!("{target} {} flags={flags:#04x}", path.display());
                wsus::run(target, &input).expect("known target");
            }
        }
        seen += 1;
    }
    assert!(seen >= 10, "expected the wsus fixtures, found {seen}");
}

#[test]
fn wsus_harnesses_accept_empty_and_truncated_input() {
    for target in TARGETS {
        wsus::run(target, &[]).expect("known target");
        wsus::run(target, &[0xff]).expect("known target");
        wsus::run(target, b"\x00<a").expect("known target");
    }
}

/// Deterministic mutation pass standing in for a short fuzz campaign when no
/// fuzzing engine is installed. Set WSUS_MUTATIONS to raise the count.
#[test]
fn wsus_harnesses_survive_deterministic_mutations_of_fixtures() {
    let iterations: u64 = std::env::var("WSUS_MUTATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/wsus-protocol/tests/fixtures");
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut files: Vec<_> = fs::read_dir(dir)
        .expect("fixture directory")
        .map(|e| e.expect("entry").path())
        .collect();
    files.sort();
    for path in files {
        if !matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("xml" | "txt")
        ) {
            continue;
        }
        let seed = fs::read(&path).expect("fixture bytes");
        for _ in 0..iterations {
            let mut input = vec![next() as u8];
            input.extend_from_slice(&seed);
            for _ in 0..=(next() % 4) {
                let at = 1 + (next() as usize) % (input.len() - 1);
                match next() % 4 {
                    0 => input[at] = next() as u8,
                    1 => input[at] ^= 1 << (next() % 8),
                    2 => {
                        input.remove(at);
                    }
                    _ => input.insert(at, next() as u8),
                }
                if input.len() < 2 {
                    break;
                }
            }
            for target in TARGETS {
                let outcome = std::panic::catch_unwind(|| wsus::run(target, &input));
                if let Err(panic) = outcome {
                    eprintln!("FAILING INPUT for {target}: {:?}", input);
                    std::panic::resume_unwind(panic);
                }
            }
        }
    }
}

/// The applicability harness also loads the bytes as a facts snapshot (flags
/// bit 2); run it over the snapshot sample and over its truncations.
#[test]
fn wsus_applicability_survives_the_snapshot_fixture_and_its_truncations() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../crates/wsus-protocol/tests/fixtures/applicability_facts_sample.json");
    let body = fs::read(&path).expect("snapshot fixture");
    for flags in [0u8, 2, 4, 6] {
        for cut in (0..body.len()).step_by(7).chain([body.len()]) {
            let mut input = vec![flags];
            input.extend_from_slice(&body[..cut]);
            wsus::run("wsus_applicability", &input).expect("known target");
        }
    }
}
