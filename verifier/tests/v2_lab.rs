//! Format v2: bundles exported by the CircuitBreaker gateway in lab runs.
//! The verifier was written without the gateway's code; these check that it
//! reaches the producer's verdicts on real output.

use std::path::{Path, PathBuf};

use cybercircuit_verify::{Options, Summary, verify};

fn data() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/v2-lab-2026-10-28")
}

fn check(name: &str, receipts: bool) -> Result<Summary, String> {
    let d = data();
    let keys = d.join(format!("keys/{name}.pub.json"));
    let rec = d.join(format!("receipts/{name}.jsonl"));
    verify(&Options {
        bundle: &d.join(format!("bundles/{name}")),
        trusted_keys: &keys,
        trusted_log_key: None,
        receipts: receipts.then_some(rec.as_path()),
    })
    .map_err(|f| f.to_string())
}

#[test]
fn complete_runs_are_valid_sealed_and_complete_with_their_receipts() {
    for name in [
        "connect-trip",
        "proxy-trip",
        "endpoint-optin-trip",
        "endpoint-misses-50",
        "evidence-failure-null-link",
        "f1-artifacts",
        "explicit-hardening-demo",
    ] {
        let s = check(name, true).unwrap_or_else(|e| panic!("{name}: {e}"));
        let r = s.v2.unwrap();
        assert!(s.sealed, "{name}");
        assert!(r.security_counts_complete, "{name}: {:?}", r.incomplete);
    }
}

#[test]
fn fifty_endpoint_misses_count_as_the_producer_reports() {
    let r = check("endpoint-misses-50", true).unwrap().v2.unwrap();
    assert_eq!(r.model_requests_observed_lower_bound, 52);
    assert_eq!(r.model_refusals_observed_lower_bound, 50);
    assert_eq!(
        r.boundary_violations_observed_lower_bound["model_endpoint_not_allowlisted:deny"],
        50
    );
}

#[test]
fn trips_are_bound_to_their_violation_events() {
    for name in ["connect-trip", "proxy-trip", "endpoint-optin-trip"] {
        let s = check(name, true).unwrap();
        assert_eq!(s.trips, 1, "{name}");
        assert_eq!(s.v2.unwrap().kills["confirmed"], 1, "{name}");
    }
}

#[test]
fn pre_go_artifact_failure_is_valid_but_incomplete() {
    let r = check("pre-go-artifact-append-failure", true)
        .unwrap()
        .v2
        .unwrap();
    assert!(!r.security_counts_complete);
    assert!(
        r.incomplete
            .iter()
            .any(|w| w.starts_with("artifact admission missing")),
        "{:?}",
        r.incomplete
    );
}

#[test]
fn terminal_missing_trip_prefix_is_incomplete_alone_and_invalid_with_receipts() {
    let r = check("terminal-missing-trip", false).unwrap().v2.unwrap();
    assert!(
        r.incomplete
            .iter()
            .any(|w| w.starts_with("trip record missing")),
        "{:?}",
        r.incomplete
    );
    let e = check("terminal-missing-trip", true).unwrap_err();
    assert!(e.contains("missing from the bundle"), "{e}");
}
