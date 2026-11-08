//! Format v2: bundles from real coding agents run under CircuitBreaker on
//! 2026-11-05 (Claude Code 2.1.311, Codex CLI 0.142.5, Gemini CLI 0.65.0).
//! Each run did a normal task, was tripped on purpose by exhausting its
//! issue-write quota, was refused while quarantined, was reset by the operator
//! and ran again. The expected figures are the gateway's own report; this
//! verifier was written without the gateway's code.

use std::path::{Path, PathBuf};

use cybercircuit_verify::{Options, Summary, verify};

fn data(agent: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/t-ih14-2026-11-05")
        .join(agent)
}

fn check(agent: &str) -> Summary {
    let d = data(agent);
    let receipts = d.join("alarms.jsonl");
    verify(&Options {
        bundle: &d.join("bundle"),
        trusted_keys: &d.join("gateway-keys.pub.json"),
        trusted_log_key: None,
        receipts: Some(receipts.as_path()),
    })
    .unwrap_or_else(|f| panic!("{agent}: {f}"))
}

#[test]
fn each_real_agent_run_matches_the_gateways_report() {
    // agent, receipts (= checkpoints), model requests, model refusals, model mode
    for (agent, receipts, requests, refusals, mode) in [
        ("claude", 13, 14, 2, "anthropic"),
        ("codex", 13, 20, 7, "openai"),
        ("gemini", 14, 11, 2, "gemini"),
    ] {
        let s = check(agent);
        assert_eq!(s.format, 2, "{agent}");
        assert!(s.sealed, "{agent}");
        assert_eq!(s.receipts_checked, receipts, "{agent}");
        assert_eq!(s.checkpoints, receipts, "{agent}");
        assert_eq!(s.trips, 1, "{agent}");
        let r = s.v2.unwrap();
        assert_eq!(r.increment, 1, "{agent}");
        assert_eq!(r.model_mode, mode, "{agent}");
        assert_eq!(r.artifacts, None, "{agent}");
        assert_eq!(r.model_requests_observed_lower_bound, requests, "{agent}");
        assert_eq!(r.model_refusals_observed_lower_bound, refusals, "{agent}");
        assert!(
            r.boundary_violations_observed_lower_bound.is_empty(),
            "{agent}"
        );
        assert!(
            r.tripwire_presentations_observed_lower_bound.is_empty(),
            "{agent}"
        );
        assert_eq!(r.kills.get("confirmed"), Some(&1), "{agent}");
        assert_eq!((r.resets_applied, r.resets_refused), (1, 0), "{agent}");
        assert_eq!(r.admissions, 5, "{agent}");
        assert_eq!(r.admissions_registry_checked, 0, "{agent}");
        assert_eq!(r.releases.get("confirmed"), Some(&5), "{agent}");
        assert!(r.security_counts_complete, "{agent}: {:?}", r.incomplete);
        assert!(r.incomplete.is_empty(), "{agent}: {:?}", r.incomplete);
    }
}

#[test]
fn codex_retries_while_quarantined_are_counted_through_the_suppression_record() {
    // 16 individual model-use records (13 completed, 3 refused) plus one
    // already-closed-gateway suppression record with count 4.
    let r = check("codex").v2.unwrap();
    assert_eq!(r.model_use_suppressed, 4);
    assert_eq!(r.model_use_recorded.get("completed"), Some(&13));
    assert_eq!(r.model_use_recorded.get("refused"), Some(&3));
}

#[test]
fn a_real_bundle_with_one_changed_byte_is_invalid() {
    let src = data("claude");
    let tmp = std::env::temp_dir().join(format!("cc-real-tamper-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    for f in std::fs::read_dir(src.join("bundle")).unwrap() {
        let f = f.unwrap().path();
        std::fs::copy(&f, tmp.join(f.file_name().unwrap())).unwrap();
    }
    let control = tmp.join("control.jsonl");
    let text = std::fs::read_to_string(&control).unwrap();
    let edited = text.replacen("\"status\":200", "\"status\":201", 1);
    assert_ne!(text, edited);
    std::fs::write(&control, edited).unwrap();
    let keys = src.join("gateway-keys.pub.json");
    let result = verify(&Options {
        bundle: &tmp,
        trusted_keys: &keys,
        trusted_log_key: None,
        receipts: None,
    });
    let _ = std::fs::remove_dir_all(&tmp);
    assert!(result.is_err(), "edited real bundle verified");
}
