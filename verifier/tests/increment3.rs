//! Format v2, increment 3 (host-wide storage registry). Bundles exported by the
//! CircuitBreaker gateway's Phase 3B-3 work on 2026-11-19. Two are captures of
//! real synthetic scopes in a disposable VM; the rest are isolated, re-signed
//! chains that each break one rule. This verifier was written from the
//! published spec without the gateway's code; the expected verdicts below are
//! this verifier's, checked against the producer's own.

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
        receipts: Some(receipts.as_path()),
    })
}

fn invalid(case: &str, section: &str, detail: &str) {
    let f = run(case, "valid-admission-release")
        .err()
        .unwrap_or_else(|| panic!("{case} verified"));
    assert_eq!(f.code, "invalid", "{case}: {f}");
    assert_eq!(f.section, section, "{case}: {f}");
    assert!(f.detail.contains(detail), "{case}: {f}");
}

#[test]
fn checked_admission_and_confirmed_registry_release_is_valid() {
    let s = run("valid-admission-release", "valid-admission-release").unwrap();
    assert_eq!(s.format, 2);
    assert!(s.sealed);
    assert_eq!(s.receipts_checked, 2);
    let r = s.v2.unwrap();
    assert_eq!(r.increment, 3);
    assert_eq!((r.admissions, r.admissions_registry_checked), (1, 1));
    assert_eq!(r.releases.get("confirmed"), Some(&1));
    assert!(r.security_counts_complete, "{:?}", r.incomplete);
}

#[test]
fn retained_ownership_is_valid_but_records_no_release() {
    let s = run("unknown-ownership-retained", "unknown-ownership-retained").unwrap();
    assert!(s.sealed);
    assert_eq!(s.receipts_checked, 3);
    let r = s.v2.unwrap();
    assert_eq!(r.increment, 3);
    assert_eq!((r.admissions, r.admissions_registry_checked), (1, 1));
    assert_eq!(r.releases.get("confirmed"), None);
    assert_eq!(r.releases.get("unknown"), Some(&1));
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
fn header_only_export_missing_required_files_is_refused() {
    // v2 §3 requires checkpoints.jsonl and gateway-keys.pub.json in every
    // bundle. The producer's header-only preflight export omits both; the
    // private checker called it VALID. Under the published spec it is not.
    let f = run(
        "header-only-missing-required-files",
        "valid-admission-release",
    )
    .expect_err("verified without required files");
    assert_eq!(f.code, "invalid", "{f}");
    assert!(f.detail.contains("gateway-keys.pub.json"), "{f}");
}
