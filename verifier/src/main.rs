//! `cybercircuit-verify BUNDLE --keys KEYS [--log-key PEM] [--receipts FILE]`
//!
//! Exit status: 0 valid, 1 invalid, 2 usage or I/O error.

use std::path::PathBuf;
use std::process::ExitCode;

use cybercircuit_verify::{Options, verify};

const USAGE: &str = "usage: cybercircuit-verify BUNDLE_DIR --keys GATEWAY_KEYS [--log-key REKOR_PEM] [--receipts FILE]

Verifies a CircuitBreaker evidence bundle (format v1) against keys and
receipts you obtained separately from the bundle. Prints VALID, or INVALID
with the first failing check and its section in the spec.";

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
            println!("RESULT: VALID");
            ExitCode::SUCCESS
        }
        Err(f) => {
            println!("RESULT: INVALID, {f}");
            ExitCode::from(1)
        }
    }
}
