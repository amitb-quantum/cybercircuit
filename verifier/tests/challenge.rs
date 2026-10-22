//! The open verifier against evidence challenge 1 and targeted tampering.

use std::fs;
use std::path::{Path, PathBuf};

use cybercircuit_verify::{Options, verify};

fn data() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/challenge-1")
}

fn run(bundle: &Path, keys: &Path, receipts: bool) -> Result<String, String> {
    let d = data();
    let receipts_path = d.join("receipts.jsonl");
    verify(&Options {
        bundle,
        trusted_keys: keys,
        trusted_log_key: Some(&d.join("rekor-log.pub.pem")),
        receipts: receipts.then_some(receipts_path.as_path()),
    })
    .map(|s| {
        format!(
            "VALID {} {} {} {}",
            s.checkpoints, s.anchors, s.receipts_checked, s.sealed
        )
    })
    .map_err(|f| f.to_string())
}

fn check(label: &str, receipts: bool) -> Result<String, String> {
    let d = data();
    run(
        &d.join(format!("bundle-{label}")),
        &d.join("gateway-keys.pub.json"),
        receipts,
    )
}

/// The published answer key: A rewrite, B cut, C honest, D post-quantum signature.
#[test]
fn challenge_1_verdicts_match_the_answer_key() {
    assert_eq!(check("C", true).unwrap(), "VALID 3 3 3 true");
    assert_eq!(check("C", false).unwrap(), "VALID 3 3 0 true");
    let a = check("A", true).unwrap_err();
    assert!(a.starts_with("§4.6: checkpoint 2: control head"), "{a}");
    assert_eq!(check("B", false).unwrap(), "VALID 1 1 0 true");
    let b = check("B", true).unwrap_err();
    assert!(b.contains("received checkpoint 2 is missing"), "{b}");
    let d = check("D", false).unwrap_err();
    assert!(d.starts_with("§4.4: checkpoint 2: check 4, SLH-DSA"), "{d}");
}

/// Copy bundle C to a scratch directory and apply EDIT to one file.
fn tampered(name: &str, file: &str, edit: impl FnOnce(String) -> String) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cc-verify-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    for entry in fs::read_dir(data().join("bundle-C")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), dir.join(entry.file_name())).unwrap();
    }
    let path = dir.join(file);
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, edit(text)).unwrap();
    dir
}

fn keys() -> PathBuf {
    data().join("gateway-keys.pub.json")
}

#[test]
fn a_different_trusted_key_is_refused_first() {
    let other = data().parent().unwrap().join("other-gateway-keys.pub.json");
    let e = run(&data().join("bundle-C"), &other, false).unwrap_err();
    assert!(e.starts_with("§1:"), "{e}");
}

#[test]
fn an_edited_decision_record_breaks_its_hash() {
    let dir = tampered("decision", "decision.jsonl", |t| {
        t.replacen("\"RISK_RESTRICTED\"", "\"RISK_RESTRICTEX\"", 1)
    });
    let e = run(&dir, &keys(), false).unwrap_err();
    assert!(e.starts_with("§2: record 1: sha256"), "{e}");
}

#[test]
fn a_truncated_control_journal_is_framing_failure() {
    let dir = tampered("truncated", "control.jsonl", |t| {
        t[..t.len() - 1].to_owned()
    });
    let e = run(&dir, &keys(), false).unwrap_err();
    assert!(e.starts_with("§3:") && e.contains("newline"), "{e}");
}

#[test]
fn a_missing_anchors_file_is_refused_when_the_journal_records_anchors() {
    let dir = tampered("noanchors", "rekor-anchors.jsonl", |t| t);
    fs::remove_file(dir.join("rekor-anchors.jsonl")).unwrap();
    let e = run(&dir, &keys(), false).unwrap_err();
    assert!(e.contains("check 8"), "{e}");
}

#[test]
fn an_anchor_with_a_changed_log_time_fails_its_signed_entry_timestamp() {
    let dir = tampered("set", "rekor-anchors.jsonl", |t| {
        let mut lines: Vec<String> = t.lines().map(str::to_owned).collect();
        let at = lines[0].find("\"integratedTime\":").unwrap() + "\"integratedTime\":".len();
        let digit = lines[0].as_bytes()[at];
        let replacement = if digit == b'9' {
            '8'
        } else {
            (digit + 1) as char
        };
        lines[0].replace_range(at..at + 1, &replacement.to_string());
        lines.join("\n") + "\n"
    });
    let e = run(&dir, &keys(), false).unwrap_err();
    assert!(e.contains("check 2, signed entry timestamp"), "{e}");
}

#[test]
fn a_reordered_checkpoint_line_is_not_canonical() {
    let dir = tampered("order", "checkpoints.jsonl", |t| {
        let mut lines: Vec<String> = t.lines().map(str::to_owned).collect();
        let v: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        lines[0] = serde_json::to_string(&v).unwrap(); // keys sorted, not spec order
        lines.join("\n") + "\n"
    });
    let e = run(&dir, &keys(), false).unwrap_err();
    assert!(
        e.starts_with("§4.2: checkpoint 1: line is not in canonical form"),
        "{e}"
    );
}
