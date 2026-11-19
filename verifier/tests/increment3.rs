//! Format v2, increment 3 (host-wide storage registry). Bundles exported by the
//! CircuitBreaker gateway's Phase 3B-3 work on 2026-11-19, re-exported after
//! review. Three are captures of real synthetic scopes; the rest are isolated,
//! re-signed chains that each break one rule. This verifier was written from
//! the published spec without the gateway's code; the expected verdicts below
//! are this verifier's, checked against the producer's own.

use std::path::{Path, PathBuf};

use cybercircuit_verify::{Failure, Options, Summary, verify};

fn data() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/3b3-d11-2026-11-19")
}

fn run(case: &str, key: &str) -> Result<Summary, Failure> {
    let d = data();
    let bundle = d.join(case);
    let receipts = bundle.join("receipts.jsonl");
    verify(&Options {
        bundle: &bundle,
        trusted_keys: &d.join("trusted-keys").join(format!("{key}.pub.json")),
        trusted_log_key: None,
        receipts: receipts.exists().then_some(receipts.as_path()),
    })
}

/// A registry-checked increment-3 capture: one admission and one release.
fn capture(case: &str) -> cybercircuit_verify::v2::Report {
    let s = run(case, case).unwrap_or_else(|f| panic!("{case}: {f}"));
    assert_eq!(s.format, 2, "{case}");
    assert!(s.sealed, "{case}");
    assert!(s.receipts_checked > 0, "{case}");
    let r = s.v2.unwrap();
    assert_eq!(r.increment, 3, "{case}");
    assert_eq!(
        (r.admissions, r.admissions_registry_checked),
        (1, 1),
        "{case}"
    );
    assert!(r.security_counts_complete, "{case}: {:?}", r.incomplete);
    r
}

fn invalid(case: &str, section: &str, detail: &str) {
    let f = run(case, "valid-admission-release").expect_err(case);
    assert_eq!(f.code, "invalid", "{case}: {f}");
    assert_eq!(f.section, section, "{case}: {f}");
    assert!(f.detail.contains(detail), "{case}: {f}");
}

#[test]
fn confirmed_end_with_registry_release_is_valid() {
    let r = capture("valid-admission-release");
    assert_eq!(r.releases.get("confirmed"), Some(&1));
    assert_eq!(r.registry_releases, 1);
}

#[test]
fn confirmed_end_with_retained_ownership_is_valid_and_not_a_registry_release() {
    let r = capture("confirmed-end-ownership-retained");
    assert_eq!(r.releases.get("confirmed"), Some(&1));
    assert_eq!(r.registry_releases, 0);
}

#[test]
fn uncertain_death_is_recorded_as_unknown_with_ownership_retained() {
    let r = capture("death-uncertain-ownership-retained");
    assert_eq!(r.releases.get("confirmed"), None);
    assert_eq!(r.releases.get("unknown"), Some(&1));
    assert_eq!(r.registry_releases, 0);
}

#[test]
fn registry_release_after_an_unchecked_admission_is_invalid() {
    invalid(
        "released-without-checked-increment1",
        "v2 6.5",
        "a registry release needs a registry-checked admission and a confirmed end",
    );
}

#[test]
fn increment3_admission_without_a_registry_check_is_invalid() {
    invalid(
        "released-without-checked-increment3",
        "v2 6.1",
        "increment 3 needs a registry check",
    );
}

#[test]
fn security_event_after_a_confirmed_release_is_invalid() {
    invalid(
        "security-after-release",
        "v2 6.5",
        "after the execution's confirmed end",
    );
}

#[test]
fn release_without_an_admission_is_invalid() {
    invalid(
        "missing-admission",
        "v2 6.5",
        "no earlier admission for this execution",
    );
}

#[test]
fn header_only_preflight_is_valid_unsealed_and_invents_no_admission() {
    let s = run("header-only-preflight", "valid-admission-release").unwrap();
    assert!(!s.sealed);
    assert_eq!((s.checkpoints, s.receipts_checked), (0, 0));
    let r = s.v2.unwrap();
    assert_eq!(r.increment, 3);
    assert_eq!(r.admissions, 0);
    assert!(r.releases.is_empty());
    assert!(!r.security_counts_complete);
}

#[test]
fn a_bundle_missing_a_required_file_is_refused() {
    // v2 §3: checkpoints.jsonl and gateway-keys.pub.json are always required.
    // The first export of the header-only case omitted both.
    let d = data().join("header-only-preflight");
    let tmp = std::env::temp_dir().join(format!("cc-inc3-missing-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    for f in ["bundle.json", "decision.jsonl", "control.jsonl"] {
        std::fs::copy(d.join(f), tmp.join(f)).unwrap();
    }
    let keys = data().join("trusted-keys/valid-admission-release.pub.json");
    let result = verify(&Options {
        bundle: &tmp,
        trusted_keys: &keys,
        trusted_log_key: None,
        receipts: None,
    });
    let _ = std::fs::remove_dir_all(&tmp);
    let f = result.expect_err("verified without required files");
    assert_eq!(f.code, "invalid", "{f}");
    assert!(f.detail.contains("gateway-keys.pub.json"), "{f}");
}
