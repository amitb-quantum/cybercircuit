//! Format v2 conformance (contract v0.3 §11), against synthetic signed bundles.

mod common;

use std::fs;
use std::process::Command;

use common::*;
use cybercircuit_verify::{Failure, Options, Summary, verify};

fn run(b: &Bundle) -> Result<Summary, Failure> {
    let keys = trusted_keys();
    verify(&Options {
        bundle: b.path(),
        trusted_keys: &keys,
        trusted_log_key: None,
        receipts: None,
    })
}

/// With CC_V2_FIXTURES set, record the verdict next to the bundle.
fn expect(b: &Bundle, text: String) {
    if export_dir().is_some() {
        fs::write(b.file("EXPECTED"), text + "\n").unwrap();
    }
}

fn ok(b: &Bundle) -> Summary {
    match run(b) {
        Ok(s) => {
            let r = s.v2.as_ref().expect("v2 report");
            expect(
                b,
                format!(
                    "VALID sealed={} security_counts_complete={} incomplete={:?}",
                    s.sealed, r.security_counts_complete, r.incomplete
                ),
            );
            s
        }
        Err(f) => panic!("expected VALID, got {f} (stage {}, {})", f.stage, f.code),
    }
}

fn fails(b: &Bundle, needle: &str) -> Failure {
    match run(b) {
        Ok(_) => panic!("expected INVALID containing {needle:?}, got VALID"),
        Err(f) => {
            assert!(
                f.to_string().contains(needle),
                "expected {needle:?}, got {f} (stage {}, {})",
                f.stage,
                f.code
            );
            expect(
                b,
                format!("INVALID stage={} reason={} ({f})", f.stage, f.code),
            );
            f
        }
    }
}

const EP: &str = "model_endpoint_not_allowlisted";
const CONNECT: &str = "model_connect_forbidden";
const PROXY: &str = "model_proxy_target_forbidden";

/// Fifty default endpoint misses in one window, between normal requests.
fn endpoint_misses() -> Builder {
    Builder::new(Profile::default())
        .cp("start") // 1
        .c(&admission(EXEC, 0)) // 2
        .c(&ok_use()) // 3
        .c(&bv_companion("GET")) // 4
        .c(&bv(EXEC, 0, EP, "deny", 4, None, 100)) // 5
        .c(&closure(5, 49, 4_100, true)) // 6
        .c(&ok_use()) // 7
        .c(&release(EXEC, "confirmed", false)) // 8
        .cp("shutdown") // 9
}

/// A CONNECT attempt: durable quarantine, matching trip, confirmed kill.
fn connect_trip() -> Builder {
    Builder::new(Profile::default())
        .cp("start") // 1
        .c(&admission(EXEC, 0)) // 2
        .c(&bv_companion("CONNECT")) // 3
        .d(&quarantine_decision(1)) // decision 1
        .c(&bv(EXEC, 0, CONNECT, "quarantine", 3, Some(1), 50)) // 4
        .c(&trip(&format!("boundary_violation:{CONNECT}"), true, 4, 0)) // 5
        .c(&kill("confirmed")) // 6
        .cp("tripped") // 7
        .c(&closure(4, 0, 50, true)) // 8
        .c(&release(EXEC, "confirmed", false)) // 9
        .cp("shutdown") // 10
}

// ------------------------------------------------------------ valid profiles

#[test]
fn fifty_default_endpoint_misses_count_fifty_and_never_trip() {
    let s = ok(&endpoint_misses().build("misses"));
    assert_eq!(s.format, 2);
    assert!(s.sealed);
    assert_eq!(s.trips, 0);
    let r = s.v2.unwrap();
    assert_eq!(
        r.boundary_violations_observed_lower_bound[&format!("{EP}:deny")],
        50
    );
    // 2 completed + 1 companion + 49 suppressed
    assert_eq!(r.model_requests_observed_lower_bound, 52);
    assert_eq!(r.model_refusals_observed_lower_bound, 50);
    assert!(r.security_counts_complete, "{:?}", r.incomplete);
}

#[test]
fn connect_quarantine_with_matching_trip_is_valid_and_complete() {
    let s = ok(&connect_trip().build("connect"));
    let r = s.v2.unwrap();
    assert_eq!(s.trips, 1);
    assert_eq!(r.kills["confirmed"], 1);
    assert_eq!(
        r.boundary_violations_observed_lower_bound[&format!("{CONNECT}:quarantine")],
        1
    );
    assert!(r.security_counts_complete, "{:?}", r.incomplete);
}

#[test]
fn model_free_demo_profile_without_security_events_is_valid() {
    let s = ok(&Builder::new(Profile {
        model_mode: "none",
        ..Profile::default()
    })
    .cp("start")
    .c(&admission(EXEC, 0))
    .d(&allow_decision(0))
    .c(&release(EXEC, "confirmed", false))
    .cp("shutdown")
    .build("demo"));
    let r = s.v2.unwrap();
    assert_eq!(r.admissions, 1);
    assert_eq!(r.admissions_registry_checked, 0);
    assert!(r.security_counts_complete);
}

#[test]
fn opt_in_endpoint_quarantine_is_valid() {
    let b = Builder::new(Profile {
        trip_on_endpoint: true,
        ..Profile::default()
    })
    .cp("start") // 1
    .c(&admission(EXEC, 0)) // 2
    .c(&bv_companion("POST")) // 3
    .d(&quarantine_decision(1))
    .c(&bv(EXEC, 0, EP, "quarantine", 3, Some(1), 0)) // 4
    .c(&trip(&format!("boundary_violation:{EP}"), true, 4, 0)) // 5
    .c(&kill("confirmed")) // 6
    .c(&closure(4, 0, 0, true)) // 7
    .cp("shutdown");
    ok(&b.build("optin"));
}

#[test]
fn proxy_target_quarantine_is_valid() {
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&admission(EXEC, 0)) // 2
        .c(&bv_companion("GET")) // 3
        .d(&quarantine_decision(1))
        .c(&bv(EXEC, 0, PROXY, "quarantine", 3, Some(1), 7)) // 4
        .c(&trip(&format!("boundary_violation:{PROXY}"), true, 4, 0)) // 5
        .c(&closure(4, 0, 7, true)) // 6
        .cp("shutdown");
    ok(&b.build("proxy"));
}

#[test]
fn increment_two_tripwire_presentation_is_valid() {
    let b = Builder::new(Profile {
        increment: 2,
        tripwire_ids: vec!["tw-01", "tw-02"],
        ..Profile::default()
    })
    .cp("start")
    .c(&admission(EXEC, 0)) // 2
    .c(&tw_companion()) // 3
    .d(&quarantine_decision(1))
    .c(&tw(EXEC, 0, "tw-02", 3, Some(1), 9)) // 4
    .c(&trip("tripwire_presented", true, 4, 0)) // 5
    .c(&kill("confirmed")) // 6
    .c(&closure(4, 0, 9, true)) // 7
    .cp("shutdown");
    let r = ok(&b.build("tw")).v2.unwrap();
    assert_eq!(r.tripwire_presentations_observed_lower_bound["tw-02"], 1);
}

#[test]
fn increment_three_registry_admission_and_release_is_valid() {
    let b = Builder::new(Profile {
        increment: 3,
        model_mode: "none",
        ..Profile::default()
    })
    .cp("start")
    .c(&admission_registry(EXEC, 0))
    .c(&release(EXEC, "unknown", false))
    .c(&release(EXEC, "confirmed", true))
    .cp("shutdown");
    let r = ok(&b.build("inc3")).v2.unwrap();
    assert_eq!(r.admissions_registry_checked, 1);
    assert_eq!(r.releases["confirmed"], 1);
}

#[test]
fn every_model_mode_is_accepted() {
    for mode in ["anthropic", "openai", "gemini"] {
        let p = Profile {
            model_mode: mode,
            ..Profile::default()
        };
        ok(&Builder::new(p)
            .cp("start")
            .c(&admission(EXEC, 0))
            .c(&ok_use())
            .cp("shutdown")
            .build(&format!("mode-{mode}")));
    }
}

// --------------------------------------------- exact bytes (Appendix A)

#[test]
fn appendix_a_known_answer_vector_verifies() {
    // The contract's literal bytes and hashes, not the builder's.
    let manifest = "{\"schema_version\":\"circuitbreaker.bundle.v2\",\"run_id\":\"demo\",\"subject_id\":\"demo\",\"session_id\":\"session-1\",\"operator_uid\":1000,\"decision_journal_id\":\"00000000-0000-4000-8000-000000000001\",\"control_journal_id\":\"00000000-0000-4000-8000-000000000002\",\"hardening\":{\"increment\":1,\"model_mode\":\"none\",\"gateway_observed\":false,\"trip_on_model_endpoint_not_allowlisted\":false,\"package_mode\":\"pre_staged_ro\",\"artifact_manifest_sha256\":null,\"tripwires\":false,\"tripwire_ids\":[],\"tripwire_catalogue_sha256\":null,\"registry\":false}}\n";
    let header = "{\"format\":\"circuitbreaker-control.2\",\"journal_id\":\"00000000-0000-4000-8000-000000000002\",\"bundle_manifest_sha256\":\"4124d1ca3bfcf8681a9c0db24ae52ce192055360025b21a9b039d5a73d3c1186\"}";
    let record = "{\"body\":{\"format\":\"circuitbreaker-control.2\",\"sequence\":1,\"previous_sha256\":\"e7e24f0b4b25f8ed9fa05729d1fef7bdca8397b5937dd8bd8239eed33f2e2282\",\"entry\":{\"kind\":\"launch_admission\",\"execution_id\":\"00000000-0000-4000-8000-000000000004\",\"epoch\":1,\"boot_id\":\"00000000-0000-4000-8000-000000000003\",\"cgroup_dev\":1,\"cgroup_ino\":2,\"registry_checked\":false,\"registry_id\":null,\"inventory_sha256\":null}},\"sha256\":\"afd396221c2f9453cc4dfa98a1680e725be962b2e186aca5a82ac2bf015d2896\"}";
    let dir = scratch("appendix-a");
    let dj = "00000000-0000-4000-8000-000000000001";
    let dh = format!("{{\"format\":\"circuitbreaker-m2.1\",\"journal_id\":\"{dj}\"}}");
    let dhead = sha(&[b"circuitbreaker.m2.genesis\0", dh.as_bytes()]);
    let statement = format!(
        "{{\"schema_version\":\"circuitbreaker.checkpoint.v1\",\"gateway_key_id\":\"{}\",\"sequence\":1,\"reason\":\"start\",\"decision\":{{\"journal_id\":\"{dj}\",\"sequence\":0,\"head_sha256\":\"{dhead}\",\"epoch\":0,\"state\":\"Active\"}},\"control\":{{\"journal_id\":\"00000000-0000-4000-8000-000000000002\",\"sequence\":1,\"head_sha256\":\"afd396221c2f9453cc4dfa98a1680e725be962b2e186aca5a82ac2bf015d2896\"}},\"previous_checkpoint_sha256\":\"{}\",\"wall_time_unix_ms\":1}}",
        keys().key_id,
        "0".repeat(64)
    );
    fs::write(dir.join("bundle.json"), manifest).unwrap();
    fs::write(dir.join("decision.jsonl"), format!("{dh}\n")).unwrap();
    fs::write(dir.join("control.jsonl"), format!("{header}\n{record}\n")).unwrap();
    fs::write(
        dir.join("checkpoints.jsonl"),
        format!("{}\n", sign(&statement)),
    )
    .unwrap();
    fs::write(dir.join("gateway-keys.pub.json"), &keys().file).unwrap();
    let s = ok(&Bundle { dir });
    assert!(s.sealed);
}

// ------------------------------------------------------- version selection

#[test]
fn v2_header_without_manifest_is_format_mismatch() {
    let b = endpoint_misses().build("nomanifest");
    fs::remove_file(b.file("bundle.json")).unwrap();
    assert_eq!(fails(&b, "bundle.json is missing").code, "format_mismatch");
}

#[test]
fn manifest_with_v1_header_is_format_mismatch() {
    let b = endpoint_misses().build("v1header");
    let c = b.read("control.jsonl");
    b.write(
        "control.jsonl",
        &c.replacen("circuitbreaker-control.2", "circuitbreaker-control.1", 1),
    );
    assert_eq!(fails(&b, "header is v1").code, "format_mismatch");
}

#[test]
fn unknown_manifest_version_is_unsupported() {
    let b = endpoint_misses().build("v3manifest");
    let m = b.read("bundle.json");
    b.write("bundle.json", &m.replace("bundle.v2", "bundle.v3"));
    let f = fails(&b, "not supported");
    assert_eq!((f.stage, f.code), (2, "unsupported_format"));
}

#[test]
fn unknown_control_version_without_manifest_is_unsupported() {
    let b = endpoint_misses().build("v3control");
    fs::remove_file(b.file("bundle.json")).unwrap();
    let c = b.read("control.jsonl");
    b.write(
        "control.jsonl",
        &c.replacen("circuitbreaker-control.2", "circuitbreaker-control.3", 1),
    );
    assert_eq!(fails(&b, "not supported").code, "unsupported_format");
}

#[test]
fn a_changed_manifest_breaks_the_header_binding() {
    let b = endpoint_misses().build("manifestedit");
    let m = b.read("bundle.json");
    b.write("bundle.json", &m.replace("\"run-1\"", "\"run-2\""));
    fails(&b, "does not bind this bundle.json");
}

// ------------------------------------------------- canonical bytes and grammar

#[test]
fn manifest_duplicate_key_is_refused() {
    let b = endpoint_misses().build("dupkey");
    let m = b.read("bundle.json");
    b.write(
        "bundle.json",
        &m.replacen(
            "\"run_id\":\"run-1\",",
            "\"run_id\":\"run-0\",\"run_id\":\"run-1\",",
            1,
        ),
    );
    fails(&b, "canonical form");
}

#[test]
fn manifest_reordered_or_spaced_is_refused() {
    let b = endpoint_misses().build("spaced");
    let m = b.read("bundle.json");
    b.write("bundle.json", &m.replacen("\"run_id\":", "\"run_id\": ", 1));
    fails(&b, "canonical form");
    let b = endpoint_misses().build("reordered");
    let m = b.read("bundle.json");
    let v: serde_json::Value = serde_json::from_str(&m).unwrap();
    b.write("bundle.json", &(serde_json::to_string(&v).unwrap() + "\n")); // sorted keys
    fails(&b, "canonical form");
}

#[test]
fn manifest_without_final_lf_or_with_float_is_refused() {
    let b = endpoint_misses().build("nolf");
    let m = b.read("bundle.json");
    b.write("bundle.json", m.trim_end());
    fails(&b, "single LF");
    let b = endpoint_misses().build("float");
    let m = b.read("bundle.json");
    b.write(
        "bundle.json",
        &m.replace("\"operator_uid\":1000", "\"operator_uid\":1000.0"),
    );
    fails(&b, "operator_uid");
}

#[test]
fn oversized_manifest_is_a_resource_limit() {
    let b = endpoint_misses().build("bigmanifest");
    b.write("bundle.json", &format!("{}\n", " ".repeat(17_000)));
    assert_eq!(fails(&b, "over 16384").code, "resource_limit");
}

#[test]
fn profile_contradictions_are_refused() {
    let p = Profile::default();
    let cases = [
        (
            "\"tripwires\":false",
            "\"tripwires\":true",
            "tripwires must be",
        ),
        (
            "\"registry\":false",
            "\"registry\":true",
            "registry must be",
        ),
        (
            "\"gateway_observed\":true",
            "\"gateway_observed\":false",
            "gateway_observed must be",
        ),
    ];
    for (i, (from, to, msg)) in cases.iter().enumerate() {
        let mut bld = Builder::new(p.clone()).cp("start");
        bld.manifest_override = Some(manifest(&p).replace(from, to));
        fails(&bld.build(&format!("profile-{i}")), msg);
    }
}

#[test]
fn unknown_kind_unknown_field_and_bad_integer_are_refused() {
    let base = || Builder::new(Profile::default()).cp("start");
    fails(
        &base().c("{\"kind\":\"teleport\"}").build("unknownkind"),
        "unknown entry kind",
    );
    fails(
        &base()
            .c("{\"kind\":\"kill\",\"outcome\":\"confirmed\",\"extra\":1}")
            .build("extrafield"),
        "fields must be exactly",
    );
    fails(
        &base()
            .c("{\"kind\":\"scope_lost\",\"cgroup_dev\":1e3,\"cgroup_ino\":2}")
            .build("exponent"),
        "wrong type",
    );
    fails(
        &base()
            .c("{\"kind\":\"scope_lost\",\"cgroup_dev\":-1,\"cgroup_ino\":2}")
            .build("negative"),
        "wrong type",
    );
}

#[test]
fn needless_escapes_and_key_order_in_entries_are_refused() {
    let base = || Builder::new(Profile::default()).cp("start");
    fails(
        &base()
            .c("{\"kind\":\"peer_rejected\",\"reason\":\"a\\/b\"}")
            .build("escslash"),
        "canonical form",
    );
    fails(
        &base()
            .c("{\"kind\":\"peer_rejected\",\"reason\":\"\\u0041\"}")
            .build("escprintable"),
        "canonical form",
    );
    fails(
        &base()
            .c("{\"outcome\":\"confirmed\",\"kind\":\"kill\"}")
            .build("entryorder"),
        "canonical form",
    );
}

#[test]
fn unknown_security_trigger_family_is_refused() {
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&legacy_trip("boundary_violation:model_teleport"))
        .build("badtrigger");
    fails(&b, "unknown security trigger");
}

#[test]
fn legacy_triggers_keep_their_original_shape() {
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&admission(EXEC, 0))
        .d(&quarantine_decision(1))
        .c(&legacy_trip("quota_exhausted:read_file"))
        .c(&kill("confirmed"))
        .cp("tripped");
    let s = ok(&b.build("legacytrip"));
    assert_eq!(s.trips, 1);
}

#[test]
fn oversized_control_line_is_a_resource_limit() {
    let reason = "x".repeat(16_400);
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&format!(
            "{{\"kind\":\"peer_rejected\",\"reason\":\"{reason}\"}}"
        ))
        .build("bigline");
    assert_eq!(fails(&b, "over 16384").code, "resource_limit");
}

#[test]
fn kinds_outside_the_profile_are_refused() {
    // tripwire event at increment 1
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&admission(EXEC, 0))
        .c(&tw_companion())
        .c(&tw(EXEC, 0, "tw-01", 3, None, 0))
        .build("twinc1");
    fails(&b, "not allowed by this bundle's hardening profile");
    // boundary event without a model ingress
    let b = Builder::new(Profile {
        model_mode: "none",
        ..Profile::default()
    })
    .cp("start")
    .c(&admission(EXEC, 0))
    .c(&bv_companion("GET"))
    .c(&bv(EXEC, 0, EP, "deny", 3, None, 0))
    .build("bvnone");
    fails(&b, "not allowed by this bundle's hardening profile");
}

// ------------------------------------------------- actions and opt-in (§6.3)

#[test]
fn opposite_actions_are_invalid() {
    // default endpoint miss labelled quarantine
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&admission(EXEC, 0))
        .c(&bv_companion("GET"))
        .c(&bv(EXEC, 0, EP, "quarantine", 3, None, 0))
        .build("epquar");
    fails(&b, "action must be deny");
    // opted-in endpoint miss labelled deny
    let b = Builder::new(Profile {
        trip_on_endpoint: true,
        ..Profile::default()
    })
    .cp("start")
    .c(&admission(EXEC, 0))
    .c(&bv_companion("GET"))
    .c(&bv(EXEC, 0, EP, "deny", 3, None, 0))
    .build("optindeny");
    fails(&b, "action must be quarantine");
    // CONNECT labelled deny
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&admission(EXEC, 0))
        .c(&bv_companion("CONNECT"))
        .c(&bv(EXEC, 0, CONNECT, "deny", 3, None, 0))
        .build("connectdeny");
    fails(&b, "action must be quarantine");
}

#[test]
fn a_deny_event_cannot_link_a_restriction() {
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&admission(EXEC, 0))
        .c(&bv_companion("GET"))
        .d(&quarantine_decision(1))
        .c(&bv(EXEC, 0, EP, "deny", 3, Some(1), 0))
        .build("denylink");
    fails(&b, "must not link a restriction");
}

#[test]
fn restriction_link_must_be_a_quarantine_at_epoch_plus_one() {
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&admission(EXEC, 0))
        .c(&bv_companion("CONNECT"))
        .d(&quarantine_decision(2))
        .c(&bv(EXEC, 0, CONNECT, "quarantine", 3, Some(1), 0))
        .build("wrongepoch");
    fails(&b, "not a RiskApplied quarantine at epoch + 1");
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&admission(EXEC, 0))
        .c(&bv_companion("CONNECT"))
        .c(&bv(EXEC, 0, CONNECT, "quarantine", 3, Some(5), 0))
        .build("nolink");
    fails(&b, "is not in the decision journal");
}

// ----------------------------------------------- event/trip binding (§6.7)

#[test]
fn terminal_missing_trip_is_valid_but_incomplete() {
    let b = Builder::new(Profile::default())
        .cp("start") // 1
        .c(&admission(EXEC, 0)) // 2
        .c(&bv_companion("CONNECT")) // 3
        .d(&quarantine_decision(1))
        .c(&bv(EXEC, 0, CONNECT, "quarantine", 3, Some(1), 0)) // 4
        .cp("tripped"); // 5 (bookkeeping only)
    let s = ok(&b.build("terminal"));
    let r = s.v2.unwrap();
    assert!(
        r.incomplete
            .iter()
            .any(|w| w.starts_with("trip record missing")),
        "{:?}",
        r.incomplete
    );
    assert!(!r.security_counts_complete);
}

#[test]
fn missing_trip_with_later_substantive_record_is_invalid() {
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&admission(EXEC, 0))
        .c(&bv_companion("CONNECT"))
        .d(&quarantine_decision(1))
        .c(&bv(EXEC, 0, CONNECT, "quarantine", 3, Some(1), 0)) // 4
        .c(&kill("confirmed")) // 5
        .cp("tripped");
    fails(
        &b.build("latekill"),
        "no trip record, and later substantive",
    );
}

#[test]
fn trip_binding_errors_are_invalid() {
    let trig = format!("boundary_violation:{CONNECT}");
    let start = || {
        Builder::new(Profile::default())
            .cp("start")
            .c(&admission(EXEC, 0)) // 2
            .c(&bv_companion("CONNECT")) // 3
            .d(&quarantine_decision(1))
    };
    // trip before its event
    fails(
        &start()
            .c(&trip(&trig, true, 5, 0)) // 4
            .c(&bv(EXEC, 0, CONNECT, "quarantine", 3, Some(1), 0)) // 5
            .build("tripfirst"),
        "is not an earlier security event",
    );
    let event = || start().c(&bv(EXEC, 0, CONNECT, "quarantine", 3, Some(1), 0)); // 4
    fails(
        &event()
            .c(&trip(&format!("boundary_violation:{PROXY}"), true, 4, 0))
            .build("wrongtrigger"),
        "trigger does not match",
    );
    fails(
        &event().c(&trip(&trig, true, 4, 1)).build("wrongepoch2"),
        "epoch transition",
    );
    fails(
        &event().c(&trip(&trig, false, 4, 0)).build("persisted"),
        "restriction_persisted must match",
    );
    fails(
        &event()
            .c(&trip(&trig, true, 4, 0))
            .c(&trip(&trig, true, 4, 0))
            .build("duptrip"),
        "already has a trip",
    );
    fails(
        &event()
            .c(&reset(true, 1))
            .c(&trip(&trig, true, 4, 0))
            .build("resetbetween"),
        "applied reset intervenes",
    );
    // orphan new-trigger trip pointing at a non-event
    fails(
        &start().c(&trip(&trig, true, 2, 0)).build("orphan"),
        "is not an earlier security event",
    );
}

#[test]
fn a_restriction_linked_twice_is_invalid() {
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&admission(EXEC, 0)) // 2
        .c(&bv_companion("CONNECT")) // 3
        .c(&bv_companion("CONNECT")) // 4
        .d(&quarantine_decision(1))
        .c(&bv(EXEC, 0, CONNECT, "quarantine", 3, Some(1), 0)) // 5
        .c(&bv(EXEC, 0, CONNECT, "quarantine", 4, Some(1), 6_000)) // 6
        .build("duplink");
    fails(&b, "linked twice");
}

#[test]
fn null_link_restriction_failure_pairs_with_an_unpersisted_trip() {
    let trig = format!("boundary_violation:{CONNECT}");
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&admission(EXEC, 0)) // 2
        .c(&bv_companion("CONNECT")) // 3
        .c(&bv(EXEC, 0, CONNECT, "quarantine", 3, None, 0)) // 4
        .c(&trip(&trig, false, 4, 0)) // 5
        .c(&kill("confirmed"))
        .c(&closure(4, 0, 0, true))
        .cp("shutdown");
    ok(&b.build("nulllink"));
    // ...and without a trip it is an incomplete restriction attempt, not a completed trip
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&admission(EXEC, 0))
        .c(&bv_companion("CONNECT"))
        .c(&bv(EXEC, 0, CONNECT, "quarantine", 3, None, 0))
        .c(&kill("unknown"))
        .cp("shutdown");
    let r = ok(&b.build("nulllink2")).v2.unwrap();
    assert!(
        r.incomplete
            .iter()
            .any(|w| w.starts_with("restriction not durable"))
    );
    assert_eq!(r.kills["unknown"], 1);
}

// ------------------------------------------------- companions and admissions (§7)

#[test]
fn companion_errors_are_invalid() {
    let start = || {
        Builder::new(Profile::default())
            .cp("start")
            .c(&admission(EXEC, 0))
    }; // 2
    fails(
        &start()
            .c(&ok_use()) // 3: an ordinary request, not a companion
            .c(&bv(EXEC, 0, EP, "deny", 3, None, 0))
            .build("fakecompanion"),
        "safe fixed values",
    );
    fails(
        &start()
            .c(&bv_companion("GET")) // 3
            .c(&bv(EXEC, 0, EP, "deny", 3, None, 0)) // 4
            .c(&closure(4, 0, 0, true))
            .c(&bv(EXEC, 0, EP, "deny", 3, None, 6_000))
            .build("reusedcompanion"),
        "already used",
    );
    fails(
        &start()
            .c(&bv_companion("GET"))
            .c(&bv(EXEC, 0, CONNECT, "quarantine", 3, None, 0))
            .build("connectmethod"),
        "safe fixed values",
    );
    fails(
        &start()
            .c(&bv(EXEC, 0, EP, "deny", 9, None, 0))
            .build("futurecompanion"),
        "not an earlier model_use",
    );
}

#[test]
fn unmatched_companion_is_reported_incomplete() {
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&admission(EXEC, 0))
        .c(&bv_companion("GET"))
        .cp("shutdown");
    let r = ok(&b.build("unmatched")).v2.unwrap();
    assert!(
        r.incomplete
            .iter()
            .any(|w| w.starts_with("security companion with no event"))
    );
    assert!(!r.security_counts_complete);
}

#[test]
fn admission_errors_are_invalid() {
    fails(
        &Builder::new(Profile::default())
            .cp("start")
            .c(&bv_companion("GET"))
            .c(&bv(EXEC, 0, EP, "deny", 2, None, 0))
            .build("noadmission"),
        "no earlier admission",
    );
    fails(
        &Builder::new(Profile::default())
            .cp("start")
            .c(&admission(EXEC, 0))
            .c(&admission(EXEC, 0))
            .build("repeatexec"),
        "execution_id is not new",
    );
    fails(
        &Builder::new(Profile::default())
            .cp("start")
            .c(&admission(EXEC, 0))
            .c(&release(EXEC, "confirmed", false))
            .c(&bv_companion("GET"))
            .c(&bv(EXEC, 0, EP, "deny", 4, None, 0))
            .build("afterrelease"),
        "after the execution's confirmed end",
    );
    fails(
        &Builder::new(Profile::default())
            .cp("start")
            .c(&admission(EXEC, 0))
            .c(&release(EXEC, "confirmed", false))
            .c(&release(EXEC, "confirmed", false))
            .build("doublerelease"),
        "after the execution's confirmed end",
    );
    fails(
        &Builder::new(Profile::default())
            .cp("start")
            .c(&admission_registry(EXEC, 0))
            .build("registryinc1"),
        "registry fields must be false",
    );
    fails(
        &Builder::new(Profile::default())
            .cp("start")
            .c(&admission(EXEC, 0))
            .c(&release(EXEC, "confirmed", true))
            .build("registryrelease"),
        "registry release needs",
    );
    fails(
        &Builder::new(Profile {
            increment: 2,
            tripwire_ids: vec!["tw-01"],
            ..Profile::default()
        })
        .cp("start")
        .c(&admission(EXEC, 0))
        .c(&tw_companion())
        .c(&tw(EXEC, 0, "tw-07", 3, None, 0))
        .build("foreignmarker"),
        "not in the manifest",
    );
}

#[test]
fn decision_subject_must_match_the_manifest() {
    let b = Builder::new(Profile::default())
        .cp("start")
        .d(&use_decision(0, "intruder"))
        .build("subject");
    fails(&b, "subject differs");
}

// ------------------------------------------------------------- artifacts (§3.2)

fn with_set(set: &str) -> Builder {
    Builder::new(Profile {
        artifacts: Some(set.to_owned()),
        ..Profile::default()
    })
}

#[test]
fn artifact_set_is_bound_and_counted() {
    let set = artifact_set(&[("a1", "pip.whl", 10), ("b2", "dep.whl", 5)]);
    let b = with_set(&set)
        .cp("start")
        .c(&admission(EXEC, 0))
        .c(&artifact_admitted(EXEC, &set, 2, 15))
        .c(&bv_companion("GET")) // 4
        .c(&bv(EXEC, 0, EP, "deny", 4, None, 0))
        .c(&closure(5, 0, 0, true))
        .cp("shutdown");
    let r = ok(&b.build("artifacts")).v2.unwrap();
    assert_eq!(r.artifacts, Some(2));
}

#[test]
fn artifact_file_errors_are_invalid() {
    let set = artifact_set(&[("a1", "pip.whl", 10), ("b2", "dep.whl", 5)]);
    let b = with_set(&set).cp("start").build("artedit");
    b.write(
        "artifacts.json",
        &set.replace("\"bytes\":10", "\"bytes\":11"),
    );
    fails(&b, "does not match artifact_manifest_sha256");
    fails(
        &with_set(&artifact_set(&[
            ("b2", "dep.whl", 5),
            ("a1", "pip.whl", 10),
        ]))
        .cp("start")
        .build("artorder"),
        "unique and sorted",
    );
    fails(
        &with_set(&artifact_set(&[
            ("a1", "same.whl", 1),
            ("b2", "same.whl", 1),
        ]))
        .cp("start")
        .build("artdupname"),
        "duplicate filename",
    );
    fails(
        &with_set(&artifact_set(&[("a1", "big.whl", 67_108_865)]))
            .cp("start")
            .build("artbig"),
        "over 64 MiB",
    );
    fails(
        &with_set(&artifact_set(&[("a1", "../x", 1)]))
            .cp("start")
            .build("artpath"),
        "wrong type",
    );
    let b = with_set(&set).cp("start").build("artmissing");
    fs::remove_file(b.file("artifacts.json")).unwrap();
    fails(&b, "artifacts.json is missing");
    let b = Builder::new(Profile::default())
        .cp("start")
        .build("artorphan");
    b.write("artifacts.json", &set);
    fails(&b, "declares no artifact set");
}

#[test]
fn artifact_admission_errors_are_invalid() {
    let set = artifact_set(&[("a1", "pip.whl", 10)]);
    fails(
        &with_set(&set)
            .cp("start")
            .c(&admission(EXEC, 0))
            .c(&artifact_admitted(EXEC, &set, 2, 10))
            .build("artcount"),
        "differs from artifacts.json",
    );
    fails(
        &with_set(&set)
            .cp("start")
            .c(&admission(EXEC, 0))
            .c(&bv_companion("GET"))
            .c(&bv(EXEC, 0, EP, "deny", 3, None, 0))
            .build("artlate"),
        "before the execution's artifact admission",
    );
    fails(
        &Builder::new(Profile::default())
            .cp("start")
            .c(&admission(EXEC, 0))
            .c(&artifact_admitted(EXEC, &set, 1, 10))
            .build("artundeclared"),
        "not allowed by this bundle's hardening profile",
    );
}

#[test]
fn admission_without_artifact_and_no_activity_is_incomplete() {
    // The pre-GO artifact append failure: the admission is all that was written.
    let set = artifact_set(&[("a1", "pip.whl", 10)]);
    let r = ok(&with_set(&set)
        .cp("start")
        .c(&admission(EXEC, 0))
        .build("prego"))
    .v2
    .unwrap();
    assert!(
        r.incomplete
            .iter()
            .any(|w| w.starts_with("artifact admission missing"))
    );
}

// ------------------------------------------------------------- windows (§6.6)

#[test]
fn window_rules() {
    let start = || {
        Builder::new(Profile::default())
            .cp("start")
            .c(&admission(EXEC, 0)) // 2
            .c(&bv_companion("GET")) // 3
            .c(&bv_companion("GET")) // 4
            .c(&bv(EXEC, 0, EP, "deny", 3, None, 1_000)) // 5
    };
    // exactly at +5 s: a separate window
    let r = ok(&start()
        .c(&closure(5, 3, 5_999, true)) // 6
        .c(&bv(EXEC, 0, EP, "deny", 4, None, 6_000)) // 7
        .c(&closure(7, 0, 6_000, true))
        .cp("shutdown")
        .build("winedge"))
    .v2
    .unwrap();
    assert_eq!(
        r.boundary_violations_observed_lower_bound[&format!("{EP}:deny")],
        5
    );
    // overlapping same-key window
    fails(
        &start()
            .c(&closure(5, 0, 1_000, true))
            .c(&bv(EXEC, 0, EP, "deny", 4, None, 5_999))
            .build("winoverlap"),
        "overlaps the open window",
    );
    // new window before the old one closes
    fails(
        &start()
            .c(&bv(EXEC, 0, EP, "deny", 4, None, 7_000))
            .build("winunclosed"),
        "overlaps the open window",
    );
    fails(
        &start()
            .c(&closure(5, 0, 1_000, true))
            .c(&closure(5, 0, 1_000, true))
            .build("windup"),
        "a second closure",
    );
    fails(
        &start().c(&closure(5, 0, 6_001, true)).build("winlate"),
        "outside [start, start + 5000]",
    );
    fails(
        &start()
            .c(&closure(5, u64::MAX, 6_000, true))
            .build("winsat"),
        "saturated count cannot be complete",
    );
    let r = ok(&start()
        .c(&closure(5, u64::MAX, 6_000, false))
        .cp("shutdown")
        .build("winsatok"))
    .v2
    .unwrap();
    assert!(!r.security_counts_complete);
    assert!(
        r.incomplete
            .iter()
            .any(|w| w.starts_with("repeat count incomplete"))
    );
    let r = ok(&start().cp("shutdown").build("winopen")).v2.unwrap();
    assert!(
        r.incomplete
            .iter()
            .any(|w| w.starts_with("repeat window not closed"))
    );
}

// ------------------------------------------------ checkpoints and sealing (§8)

#[test]
fn single_signature_is_not_enough() {
    let b = endpoint_misses().build("onesig");
    let c = b.read("checkpoints.jsonl");
    let mut lines: Vec<String> = c.lines().map(str::to_owned).collect();
    let at = lines[1].find("\"slh_dsa_sha2_128f\":\"").unwrap() + 22;
    let flip = if &lines[1][at..at + 1] == "0" {
        "1"
    } else {
        "0"
    };
    lines[1].replace_range(at..at + 1, flip);
    b.write("checkpoints.jsonl", &(lines.join("\n") + "\n"));
    let f = fails(&b, "SLH-DSA");
    assert_eq!(f.stage, 5);
}

#[test]
fn a_record_after_the_last_checkpoint_is_unsealed_not_invalid() {
    let s = ok(&endpoint_misses().c(&ok_use()).build("unsealed"));
    assert!(!s.sealed);
    let r = s.v2.unwrap();
    assert!(!r.security_counts_complete);
    assert!(r.incomplete.iter().any(|w| w.contains("unsealed")));
}

#[test]
fn a_closure_after_the_last_checkpoint_is_unsealed() {
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&admission(EXEC, 0))
        .c(&bv_companion("GET"))
        .c(&bv(EXEC, 0, EP, "deny", 3, None, 0))
        .cp("shutdown")
        .c(&closure(4, 0, 0, true));
    assert!(!ok(&b.build("lateclosure")).sealed);
}

#[test]
fn a_checkpoint_entry_must_name_a_checkpoint_in_the_file() {
    let b = Builder::new(Profile::default())
        .cp("start")
        .c(&format!(
            "{{\"kind\":\"checkpoint\",\"sequence\":2,\"reason\":\"periodic\",\"statement_sha256\":\"{}\"}}",
            "ab".repeat(32)
        ))
        .build("phantomcp");
    fails(&b, "not in the checkpoint file");
}

#[test]
fn a_receipt_covered_truncation_is_invalid() {
    let b = connect_trip().build("receipt");
    let receipts = b.file("../cc-v2-receipts.jsonl");
    let cps = b.read("checkpoints.jsonl");
    fs::write(&receipts, &cps).unwrap();
    // Cut the bundle back to its first checkpoint, consistently: journals end
    // where checkpoint 1 (and its bookkeeping record) end.
    let first = cps.lines().next().unwrap();
    b.write("checkpoints.jsonl", &format!("{first}\n"));
    let control: Vec<String> = b
        .read("control.jsonl")
        .lines()
        .take(2)
        .map(str::to_owned)
        .collect();
    b.write("control.jsonl", &(control.join("\n") + "\n"));
    let decision = b.read("decision.jsonl").lines().next().unwrap().to_owned();
    b.write("decision.jsonl", &format!("{decision}\n"));
    // Without the receipt the cut is undetectable (and sealed at checkpoint 1).
    assert!(ok(&b).sealed);
    let keys = trusted_keys();
    let r = verify(&Options {
        bundle: b.path(),
        trusted_keys: &keys,
        trusted_log_key: None,
        receipts: Some(&receipts),
    });
    let f = r.expect_err("truncation must be refused");
    assert!(f.to_string().contains("missing from the bundle"), "{f}");
}

// ------------------------------------------------------------ exit codes (§10)

fn cli(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_cybercircuit-verify"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn exit_codes_are_0_valid_1_anything_else_2_usage() {
    let keys = trusted_keys();
    let keys = keys.to_str().unwrap();
    let good = connect_trip().build("cli-good");
    let (code, out) = cli(&[good.path().to_str().unwrap(), "--keys", keys]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("format: v2") && out.ends_with("RESULT: VALID\n"),
        "{out}"
    );

    let bad = connect_trip().build("cli-unsupported");
    let m = bad.read("bundle.json");
    bad.write("bundle.json", &m.replace("bundle.v2", "bundle.v9"));
    let (code, out) = cli(&[bad.path().to_str().unwrap(), "--keys", keys]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("STAGE: 2; REASON: unsupported_format"),
        "{out}"
    );

    let (code, out) = cli(&["/nonexistent", "--keys", keys]);
    assert_eq!(code, 1, "{out}");

    let (code, _) = cli(&[good.path().to_str().unwrap()]);
    assert_eq!(code, 2);
}
