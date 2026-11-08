//! `cybercircuit-verify BUNDLE --keys KEYS [--log-key PEM] [--receipts FILE]`
//!
//! Exit status: 0 only for VALID; 1 for anything not valid (including an
//! unsupported format, a resource limit or an unreadable file); 2 only for a
//! usage error.

use std::path::PathBuf;
use std::process::ExitCode;

use cybercircuit_verify::{Options, verify};

const USAGE: &str = "usage: cybercircuit-verify BUNDLE_DIR --keys GATEWAY_KEYS [--log-key REKOR_PEM] [--receipts FILE]

Verifies a CircuitBreaker evidence bundle (format v1 or v2) against keys and
receipts you obtained separately from the bundle. Prints VALID, or INVALID
with the first failing check, its section in the spec, and its stage and reason.";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (mut bundle, mut keys, mut log_key, mut receipts) = (None, None, None, None);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--keys" => keys = args.next().map(PathBuf::from),
            "--log-key" => log_key = args.next().map(PathBuf::from),
            "--receipts" => receipts = args.next().map(PathBuf::from),
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            _ if bundle.is_none() && !a.starts_with('-') => bundle = Some(PathBuf::from(a)),
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(bundle), Some(keys)) = (bundle, keys) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let options = Options {
        bundle: &bundle,
        trusted_keys: &keys,
        trusted_log_key: log_key.as_deref(),
        receipts: receipts.as_deref(),
    };
    println!("bundle: {}", bundle.display());
    match verify(&options) {
        Ok(s) => {
            println!("format: v{}", s.format);
            println!("gateway key: {} (trusted)", s.key_id);
            println!("log key: {}", s.log_key);
            println!(
                "decision records {}, control records {}, checkpoints {}, anchors {}, receipts checked {}, trips {}, sealed {}",
                s.decision_records,
                s.control_records,
                s.checkpoints,
                s.anchors,
                s.receipts_checked,
                s.trips,
                if s.sealed { "yes" } else { "no" }
            );
            if let Some(r) = &s.v2 {
                println!(
                    "hardening: increment {}, model mode {}, artifact set {}",
                    r.increment,
                    r.model_mode,
                    r.artifacts
                        .map_or("none".to_owned(), |n| format!("{n} artifacts"))
                );
                println!(
                    "model requests observed (lower bound) {}, refused (lower bound) {}",
                    r.model_requests_observed_lower_bound, r.model_refusals_observed_lower_bound
                );
                for (k, v) in &r.boundary_violations_observed_lower_bound {
                    println!("boundary violations {k}: {v} (lower bound)");
                }
                for (k, v) in &r.tripwire_presentations_observed_lower_bound {
                    println!("tripwire presentations {k}: {v} (lower bound)");
                }
                let kills: Vec<String> = r.kills.iter().map(|(k, v)| format!("{k} {v}")).collect();
                println!(
                    "kills: {}; resets applied {}, refused {}",
                    if kills.is_empty() {
                        "none".to_owned()
                    } else {
                        kills.join(", ")
                    },
                    r.resets_applied,
                    r.resets_refused
                );
                println!(
                    "admissions {} (host-wide registry checked: {}); releases {:?}",
                    r.admissions, r.admissions_registry_checked, r.releases
                );
                println!(
                    "security counts complete: {}",
                    if r.security_counts_complete {
                        "yes"
                    } else {
                        "no"
                    }
                );
                for why in &r.incomplete {
                    println!("incomplete: {why}");
                }
            }
            println!("RESULT: VALID");
            ExitCode::SUCCESS
        }
        Err(f) => {
            println!("RESULT: INVALID, {f}");
            println!("STAGE: {}; REASON: {}", f.stage, f.code);
            ExitCode::from(1)
        }
    }
}
