//! Format version 2 (evidence bundle format v2, contract v0.3).
//!
//! Written from the contract and the v1 spec it inherits, not from the
//! gateway's code. v2 keeps the v1 decision journal, keys, checkpoints,
//! anchors and receipts unchanged. It adds an authenticated `bundle.json`
//! manifest, a new control-journal chain (`circuitbreaker-control.2`) whose
//! header binds the manifest, new security event kinds, and cross-record
//! bindings between them.
//!
//! Stages follow contract §10: 1 keys, 2 version and manifest, 3 journal
//! grammar, 4 artifacts and bindings, 5 checkpoints, 6 anchors and receipts,
//! 7 totals and flags. The first failure is reported.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::{
    Checkpoint, Failure, GatewayKeys, Journal, Options, Summary, anchors_and_receipts, checkpoints,
    decision_journal, hex, is_bookkeeping, is_hex64, is_uuid, jstr, sealed, sha,
};

const CONTROL_FORMAT: &str = "circuitbreaker-control.2";
const CONTROL_V1_FORMAT: &str = "circuitbreaker-control.1";
const MANIFEST_SCHEMA: &str = "circuitbreaker.bundle.v2";
const ARTIFACT_SCHEMA: &str = "circuitbreaker.artifact-set.v1";
const GENESIS: &[u8] = b"circuitbreaker-control-v2/genesis\0";
const ENTRY: &[u8] = b"circuitbreaker-control-v2/entry\0";

/// §2: control header/record line, excluding LF.
const MAX_RECORD: usize = 16_384;
/// §2: `bundle.json`, including LF.
const MAX_MANIFEST: usize = 16_384;
/// §2 and §3.2: `artifacts.json`, including LF.
const MAX_ARTIFACTS: usize = 262_144;
const MAX_TEXT: usize = 4_096;
const MAX_ARTIFACT_BYTES: u64 = 67_108_864;
const MAX_ARTIFACT_TOTAL: u64 = 536_870_912;
/// §6.6: repeat window length.
const WINDOW_MS: u64 = 5_000;

const REASONS: &[&str] = &[
    "model_connect_forbidden",
    "model_proxy_target_forbidden",
    "model_endpoint_not_allowlisted",
];
const BV_PATH: &str = "[boundary_violation]";
const TW_PATH: &str = "[tripwire_presented]";

// ------------------------------------------------------------ failures

fn err(stage: u8, section: &'static str, code: &'static str, detail: String) -> Failure {
    Failure {
        section,
        detail,
        stage,
        code,
    }
}

fn bad<T>(stage: u8, section: &'static str, detail: impl Into<String>) -> Result<T, Failure> {
    Err(err(stage, section, "invalid", detail.into()))
}

fn ensure(
    cond: bool,
    stage: u8,
    section: &'static str,
    detail: impl Into<String>,
) -> Result<(), Failure> {
    if cond {
        Ok(())
    } else {
        bad(stage, section, detail)
    }
}

fn limit<T>(stage: u8, section: &'static str, detail: impl Into<String>) -> Result<T, Failure> {
    Err(err(stage, section, "resource_limit", detail.into()))
}

// ------------------------------------------------------------ types (§2)

#[derive(Clone, Copy)]
enum T {
    U,
    P,
    Uid,
    H,
    Uuid,
    Id,
    Aid,
    Twid,
    Text,
    DecisionId,
    Bool,
    Status,
    Increment,
    Enum(&'static [&'static str]),
    Const(&'static str),
    Null(&'static T),
}

fn is_id(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len())
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_twid(s: &str) -> bool {
    s.strip_prefix("tw-")
        .filter(|n| n.len() == 2 && n.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|n| n.parse::<u8>().ok())
        .is_some_and(|n| (1..=16).contains(&n))
}

/// `<decision journal UUID>:` plus 16 lowercase hex digits of a positive sequence.
fn decision_id(s: &str) -> Option<(&str, u64)> {
    let (j, n) = s.split_once(':')?;
    let ok =
        is_uuid(j) && n.len() == 16 && n.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let n = u64::from_str_radix(n, 16).ok().filter(|n| ok && *n >= 1)?;
    Some((j, n))
}

/// An HTTP method token (RFC 9110 tchar), at most 32 bytes (§7).
fn is_method(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn type_ok(v: &Value, t: T) -> bool {
    match t {
        T::U => v.is_u64(),
        T::P => v.as_u64().is_some_and(|n| v.is_u64() && n >= 1),
        T::Uid => v
            .as_u64()
            .is_some_and(|n| v.is_u64() && n <= u64::from(u32::MAX)),
        T::H => v.as_str().is_some_and(is_hex64),
        T::Uuid => v.as_str().is_some_and(is_uuid),
        T::Id => v.as_str().is_some_and(|s| is_id(s, 128)),
        T::Aid => v.as_str().is_some_and(|s| is_id(s, 64)),
        T::Twid => v.as_str().is_some_and(is_twid),
        T::Text => v
            .as_str()
            .is_some_and(|s| s.is_ascii() && s.len() <= MAX_TEXT),
        T::DecisionId => v.as_str().is_some_and(|s| decision_id(s).is_some()),
        T::Bool => v.is_boolean(),
        T::Status => v
            .as_u64()
            .is_some_and(|n| v.is_u64() && (100..=599).contains(&n)),
        T::Increment => v
            .as_u64()
            .is_some_and(|n| v.is_u64() && (1..=3).contains(&n)),
        T::Enum(set) => v.as_str().is_some_and(|s| set.contains(&s)),
        T::Const(c) => v.as_str() == Some(c),
        T::Null(inner) => v.is_null() || type_ok(v, *inner),
    }
}

type Schema = &'static [(&'static str, T)];

/// Checks an object has exactly `fields`, each of its type, and returns its
/// canonical bytes (§2): compact, keys in schema order, standard escaping.
fn canon_obj(
    v: &Value,
    fields: Schema,
    stage: u8,
    section: &'static str,
    what: &str,
) -> Result<String, Failure> {
    let Some(obj) = v.as_object() else {
        return bad(stage, section, format!("{what}: not an object"));
    };
    let names: Vec<&str> = fields.iter().map(|(k, _)| *k).collect();
    ensure(
        obj.len() == fields.len() && names.iter().all(|k| obj.contains_key(*k)),
        stage,
        section,
        format!("{what}: fields must be exactly {names:?}"),
    )?;
    let mut out = String::from("{");
    for (i, (k, t)) in fields.iter().enumerate() {
        let val = &obj[*k];
        ensure(
            type_ok(val, *t),
            stage,
            section,
            format!("{what}: `{k}` has the wrong type or value"),
        )?;
        if i > 0 {
            out.push(',');
        }
        out.push_str(&jstr(&Value::from(*k)));
        out.push(':');
        out.push_str(&jstr(val));
    }
    out.push('}');
    Ok(out)
}

/// Reads a known bundle file as a regular file, never through a symlink (§3).
fn read_regular(path: &Path, stage: u8, section: &'static str) -> Result<Vec<u8>, Failure> {
    let name = path.display().to_string();
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => {}
        Ok(_) => return bad(stage, section, format!("{name} is not a regular file")),
        Err(e) => return bad(stage, section, format!("cannot read {name}: {e}")),
    }
    fs::read(path).or_else(|e| bad(stage, section, format!("cannot read {name}: {e}")))
}

/// A one-line canonical JSON file: ASCII, exactly one final LF, no other LF.
fn one_line(
    bytes: &[u8],
    max: usize,
    stage: u8,
    section: &'static str,
    what: &str,
) -> Result<String, Failure> {
    if bytes.len() > max {
        return limit(stage, section, format!("{what} is over {max} bytes"));
    }
    ensure(
        bytes.is_ascii(),
        stage,
        section,
        format!("{what} is not ASCII"),
    )?;
    ensure(
        bytes.ends_with(b"\n") && bytes.iter().filter(|b| **b == b'\n').count() == 1,
        stage,
        section,
        format!("{what} must be one line ending in a single LF"),
    )?;
    Ok(String::from_utf8_lossy(&bytes[..bytes.len() - 1]).into_owned())
}

fn parse(text: &str, stage: u8, section: &'static str, what: &str) -> Result<Value, Failure> {
    serde_json::from_str(text).or_else(|_| bad(stage, section, format!("{what}: not JSON")))
}

// ------------------------------------------------------- version (§1, §10.2)

/// True for a v2 bundle, false for v1. Unknown or mixed versions fail with
/// `unsupported_format` or `format_mismatch`; there is no fallback to v1
/// once a v2 marker is present.
pub(crate) fn select(bundle: &Path) -> Result<bool, Failure> {
    let manifest = bundle.join("bundle.json");
    let has_manifest = fs::symlink_metadata(&manifest).is_ok();
    let header_format = fs::read(bundle.join("control.jsonl"))
        .ok()
        .and_then(|d| {
            let line = d.split(|b| *b == b'\n').next()?.to_vec();
            serde_json::from_slice::<Value>(&line).ok()
        })
        .and_then(|h| h.get("format").and_then(Value::as_str).map(str::to_owned));
    if has_manifest {
        let bytes = read_regular(&manifest, 2, "v2 3.1")?;
        if bytes.len() > MAX_MANIFEST {
            return limit(
                2,
                "v2 3.1",
                format!("bundle.json is over {MAX_MANIFEST} bytes"),
            );
        }
        let schema = serde_json::from_slice::<Value>(&bytes).ok().and_then(|v| {
            v.get("schema_version")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
        let Some(schema) = schema else {
            return bad(
                2,
                "v2 3.1",
                "bundle.json is not a manifest with a schema_version",
            );
        };
        if schema != MANIFEST_SCHEMA {
            return Err(err(
                2,
                "v2 1",
                "unsupported_format",
                format!("bundle.json schema_version {schema:?} is not supported"),
            ));
        }
        return match header_format.as_deref() {
            Some(CONTROL_FORMAT) => Ok(true),
            Some(CONTROL_V1_FORMAT) => Err(err(
                2,
                "v2 1",
                "format_mismatch",
                "bundle.json is v2 but the control journal header is v1".into(),
            )),
            Some(other) => Err(err(
                2,
                "v2 1",
                "unsupported_format",
                format!("control journal format {other:?} is not supported"),
            )),
            None => Err(err(
                2,
                "v2 1",
                "format_mismatch",
                "bundle.json is v2 but the control journal has no readable header".into(),
            )),
        };
    }
    match header_format.as_deref() {
        Some(CONTROL_FORMAT) => Err(err(
            2,
            "v2 1",
            "format_mismatch",
            "control journal header is v2 but bundle.json is missing".into(),
        )),
        Some(f) if f != CONTROL_V1_FORMAT && f.starts_with("circuitbreaker-control.") => Err(err(
            2,
            "v2 1",
            "unsupported_format",
            format!("control journal format {f:?} is not supported"),
        )),
        // v1, or a header too broken to name a version: v1 §3 reports it.
        _ => Ok(false),
    }
}

// ------------------------------------------------------- manifest (§3.1)

struct Manifest {
    subject_id: String,
    session_id: String,
    decision_journal_id: String,
    control_journal_id: String,
    increment: u64,
    model_mode: String,
    gateway_observed: bool,
    trip_on_endpoint: bool,
    artifact_digest: Option<String>,
    tripwires: bool,
    tripwire_ids: Vec<String>,
    registry: bool,
    /// hex(M): SHA-256 of the exact file bytes including LF.
    sha: String,
}

const MANIFEST_TOP: Schema = &[
    ("schema_version", T::Const(MANIFEST_SCHEMA)),
    ("run_id", T::Id),
    ("subject_id", T::Id),
    ("session_id", T::Id),
    ("operator_uid", T::Uid),
    ("decision_journal_id", T::Uuid),
    ("control_journal_id", T::Uuid),
];

const HARDENING_SCALARS: Schema = &[
    ("increment", T::Increment),
    (
        "model_mode",
        T::Enum(&["none", "anthropic", "openai", "gemini"]),
    ),
    ("gateway_observed", T::Bool),
    ("trip_on_model_endpoint_not_allowlisted", T::Bool),
    ("package_mode", T::Const("pre_staged_ro")),
    ("artifact_manifest_sha256", T::Null(&T::H)),
    ("tripwires", T::Bool),
];

fn manifest(bundle: &Path) -> Result<Manifest, Failure> {
    let (st, sec) = (2, "v2 3.1");
    let bytes = read_regular(&bundle.join("bundle.json"), st, sec)?;
    let text = one_line(&bytes, MAX_MANIFEST, st, sec, "bundle.json")?;
    let v = parse(&text, st, sec, "bundle.json")?;
    let obj = v
        .as_object()
        .map_or_else(|| bad(st, sec, "bundle.json: not an object"), Ok)?;
    let mut names: Vec<&str> = MANIFEST_TOP.iter().map(|(k, _)| *k).collect();
    names.push("hardening");
    ensure(
        obj.len() == names.len() && names.iter().all(|k| obj.contains_key(*k)),
        st,
        sec,
        format!("bundle.json: fields must be exactly {names:?}"),
    )?;
    // Canonical bytes, built field by field.
    let mut canon = String::from("{");
    for (i, (k, t)) in MANIFEST_TOP.iter().enumerate() {
        ensure(
            type_ok(&obj[*k], *t),
            st,
            sec,
            format!("bundle.json: `{k}` has the wrong type or value"),
        )?;
        if i > 0 {
            canon.push(',');
        }
        canon.push_str(&format!("{}:{}", jstr(&Value::from(*k)), jstr(&obj[*k])));
    }
    let h = obj["hardening"].as_object().map_or_else(
        || bad(st, sec, "bundle.json: hardening is not an object"),
        Ok,
    )?;
    let mut hnames: Vec<&str> = HARDENING_SCALARS.iter().map(|(k, _)| *k).collect();
    hnames.extend(["tripwire_ids", "tripwire_catalogue_sha256", "registry"]);
    ensure(
        h.len() == hnames.len() && hnames.iter().all(|k| h.contains_key(*k)),
        st,
        sec,
        format!("bundle.json: hardening fields must be exactly {hnames:?}"),
    )?;
    canon.push_str(",\"hardening\":{");
    for (i, (k, t)) in HARDENING_SCALARS.iter().enumerate() {
        ensure(
            type_ok(&h[*k], *t),
            st,
            sec,
            format!("bundle.json: hardening `{k}` has the wrong type or value"),
        )?;
        if i > 0 {
            canon.push(',');
        }
        canon.push_str(&format!("{}:{}", jstr(&Value::from(*k)), jstr(&h[*k])));
    }
    let ids = h["tripwire_ids"].as_array().map_or_else(
        || bad(st, sec, "bundle.json: tripwire_ids is not an array"),
        Ok,
    )?;
    ensure(
        ids.iter().all(|i| type_ok(i, T::Twid)),
        st,
        sec,
        "bundle.json: a tripwire ID is not tw-01..tw-16",
    )?;
    ensure(
        type_ok(&h["tripwire_catalogue_sha256"], T::Null(&T::H)) && h["registry"].is_boolean(),
        st,
        sec,
        "bundle.json: tripwire_catalogue_sha256 or registry has the wrong type",
    )?;
    canon.push_str(&format!(
        ",\"tripwire_ids\":{},\"tripwire_catalogue_sha256\":{},\"registry\":{}}}}}",
        jstr(&h["tripwire_ids"]),
        jstr(&h["tripwire_catalogue_sha256"]),
        jstr(&h["registry"])
    ));
    ensure(
        canon == text,
        st,
        sec,
        "bundle.json is not in canonical form (key order, spacing, escaping or duplicate keys)",
    )?;

    let s = |k: &str| obj[k].as_str().unwrap_or_default().to_owned();
    let m = Manifest {
        subject_id: s("subject_id"),
        session_id: s("session_id"),
        decision_journal_id: s("decision_journal_id"),
        control_journal_id: s("control_journal_id"),
        increment: h["increment"].as_u64().unwrap_or(0),
        model_mode: h["model_mode"].as_str().unwrap_or_default().to_owned(),
        gateway_observed: h["gateway_observed"] == true,
        trip_on_endpoint: h["trip_on_model_endpoint_not_allowlisted"] == true,
        artifact_digest: h["artifact_manifest_sha256"].as_str().map(str::to_owned),
        tripwires: h["tripwires"] == true,
        tripwire_ids: ids
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        registry: h["registry"] == true,
        sha: hex(&sha(&[&bytes])),
    };
    // Profile constraints.
    let model = m.model_mode != "none";
    ensure(
        m.gateway_observed == model,
        st,
        sec,
        "bundle.json: gateway_observed must be true exactly when model_mode is not none",
    )?;
    ensure(
        m.gateway_observed || !m.trip_on_endpoint,
        st,
        sec,
        "bundle.json: endpoint-trip opt-in without a model ingress",
    )?;
    ensure(
        m.tripwires == (m.increment >= 2 && model),
        st,
        sec,
        "bundle.json: tripwires must be true exactly when increment >= 2 and a model ingress exists",
    )?;
    if m.tripwires {
        let sorted = m.tripwire_ids.windows(2).all(|w| w[0] < w[1]);
        ensure(
            (1..=16).contains(&m.tripwire_ids.len())
                && sorted
                && h["tripwire_catalogue_sha256"].is_string(),
            st,
            sec,
            "bundle.json: tripwires need 1..16 sorted unique IDs and a catalogue digest",
        )?;
    } else {
        ensure(
            m.tripwire_ids.is_empty() && h["tripwire_catalogue_sha256"].is_null(),
            st,
            sec,
            "bundle.json: tripwires off needs no IDs and a null catalogue digest",
        )?;
    }
    ensure(
        m.registry == (m.increment == 3),
        st,
        sec,
        "bundle.json: registry must be true exactly when increment is 3",
    )?;
    Ok(m)
}

/// Required-file inventory (§3, §10 step 2).
fn inventory(bundle: &Path) -> Result<(), Failure> {
    for f in [
        "decision.jsonl",
        "control.jsonl",
        "checkpoints.jsonl",
        "gateway-keys.pub.json",
    ] {
        read_regular(&bundle.join(f), 2, "v2 3")?;
    }
    Ok(())
}

// ------------------------------------------------------- artifacts (§3.2)

struct Artifacts {
    count: u64,
    total: u64,
}

fn artifacts(bundle: &Path, m: &Manifest) -> Result<Option<Artifacts>, Failure> {
    let (st, sec) = (4, "v2 3.2");
    let path = bundle.join("artifacts.json");
    let present = fs::symlink_metadata(&path).is_ok();
    let Some(digest) = &m.artifact_digest else {
        ensure(
            !present,
            st,
            sec,
            "artifacts.json is present but the manifest declares no artifact set",
        )?;
        return Ok(None);
    };
    ensure(
        present,
        st,
        sec,
        "the manifest declares an artifact set but artifacts.json is missing",
    )?;
    let bytes = read_regular(&path, st, sec)?;
    let text = one_line(&bytes, MAX_ARTIFACTS, st, sec, "artifacts.json")?;
    ensure(
        hex(&sha(&[&bytes])) == *digest,
        st,
        sec,
        "artifacts.json does not match artifact_manifest_sha256",
    )?;
    let v = parse(&text, st, sec, "artifacts.json")?;
    let obj = v
        .as_object()
        .map_or_else(|| bad(st, sec, "artifacts.json: not an object"), Ok)?;
    ensure(
        obj.len() == 2
            && obj.get("schema_version").and_then(Value::as_str) == Some(ARTIFACT_SCHEMA),
        st,
        sec,
        "artifacts.json: fields must be exactly schema_version and artifacts",
    )?;
    let list = obj.get("artifacts").and_then(Value::as_array).map_or_else(
        || bad(st, sec, "artifacts.json: artifacts is not an array"),
        Ok,
    )?;
    ensure(
        (1..=256).contains(&list.len()),
        st,
        sec,
        "artifacts.json: needs 1..256 artifacts",
    )?;
    const ITEM: Schema = &[
        ("id", T::Aid),
        ("filename", T::Id),
        ("bytes", T::U),
        ("sha256", T::H),
    ];
    let mut items = Vec::new();
    let mut total: u64 = 0;
    let mut names = HashSet::new();
    let mut last_id: Option<String> = None;
    for (i, a) in list.iter().enumerate() {
        let what = format!("artifacts.json: entry {}", i + 1);
        items.push(canon_obj(a, ITEM, st, sec, &what)?);
        let id = a["id"].as_str().unwrap_or_default().to_owned();
        ensure(
            last_id
                .as_ref()
                .is_none_or(|l| l.as_bytes() < id.as_bytes()),
            st,
            sec,
            format!("{what}: IDs must be unique and sorted"),
        )?;
        last_id = Some(id);
        ensure(
            names.insert(a["filename"].as_str().unwrap_or_default().to_owned()),
            st,
            sec,
            format!("{what}: duplicate filename"),
        )?;
        let n = a["bytes"].as_u64().unwrap_or(u64::MAX);
        ensure(
            n <= MAX_ARTIFACT_BYTES,
            st,
            sec,
            format!("{what}: over 64 MiB"),
        )?;
        total = total
            .checked_add(n)
            .filter(|t| *t <= MAX_ARTIFACT_TOTAL)
            .map_or_else(|| bad(st, sec, "artifacts.json: total over 512 MiB"), Ok)?;
    }
    let canon = format!(
        "{{\"schema_version\":\"{ARTIFACT_SCHEMA}\",\"artifacts\":[{}]}}",
        items.join(",")
    );
    ensure(
        canon == text,
        st,
        sec,
        "artifacts.json is not in canonical form",
    )?;
    Ok(Some(Artifacts {
        count: list.len() as u64,
        total,
    }))
}

// ------------------------------------------------- control journal (§4–§6)

const KILL: &[&str] = &["not_applicable", "confirmed", "failed", "unknown"];
const NEW_TRIGGERS: &[&str] = &[
    "boundary_violation:model_connect_forbidden",
    "boundary_violation:model_proxy_target_forbidden",
    "boundary_violation:model_endpoint_not_allowlisted",
    "tripwire_presented",
];

fn entry_schema(kind: &str, e: &Value) -> Option<Schema> {
    Some(match kind {
        "tripped" => {
            let trigger = e.get("trigger").and_then(Value::as_str).unwrap_or_default();
            if NEW_TRIGGERS.contains(&trigger) {
                &[
                    ("kind", T::Const("tripped")),
                    ("trigger", T::Text),
                    ("restriction_persisted", T::Bool),
                    ("security_event_sequence", T::P),
                    ("epoch_before", T::U),
                    ("epoch_after", T::P),
                ]
            } else {
                &[
                    ("kind", T::Const("tripped")),
                    ("trigger", T::Text),
                    ("restriction_persisted", T::Bool),
                ]
            }
        }
        "kill" => &[("kind", T::Const("kill")), ("outcome", T::Enum(KILL))],
        "scope_lost" => &[
            ("kind", T::Const("scope_lost")),
            ("cgroup_dev", T::U),
            ("cgroup_ino", T::U),
        ],
        "daemon_lost" => &[
            ("kind", T::Const("daemon_lost")),
            ("kill", T::Enum(KILL)),
            ("elapsed_ms", T::U),
        ],
        "alarm" => &[
            ("kind", T::Const("alarm")),
            ("event", T::Text),
            (
                "outcome",
                T::Enum(&["delivered", "failed", "timed_out", "dropped"]),
            ),
        ],
        "peer_rejected" => &[("kind", T::Const("peer_rejected")), ("reason", T::Text)],
        "peers_suppressed" => &[("kind", T::Const("peers_suppressed")), ("count", T::P)],
        "model_use" => &[
            ("kind", T::Const("model_use")),
            ("method", T::Text),
            ("path", T::Text),
            ("request_bytes", T::U),
            ("status", T::Status),
            ("response_bytes", T::U),
            (
                "outcome",
                T::Enum(&[
                    "completed",
                    "refused",
                    "aborted",
                    "upstream_error",
                    "client_closed",
                ]),
            ),
            ("refusal", T::Null(&T::Text)),
        ],
        "model_uses_suppressed" => &[("kind", T::Const("model_uses_suppressed")), ("count", T::P)],
        "checkpoint" => &[
            ("kind", T::Const("checkpoint")),
            ("sequence", T::P),
            (
                "reason",
                T::Enum(&["start", "tripped", "reset", "periodic", "shutdown"]),
            ),
            ("statement_sha256", T::H),
        ],
        "anchor" => &[
            ("kind", T::Const("anchor")),
            ("checkpoint_sequence", T::P),
            (
                "outcome",
                T::Enum(&["anchored", "unverified", "failed", "timed_out", "dropped"]),
            ),
            ("log_index", T::Null(&T::U)),
            ("detail", T::Null(&T::Text)),
        ],
        "reset" => &[
            ("kind", T::Const("reset")),
            ("operator_uid", T::Uid),
            ("reason", T::Null(&T::Text)),
            ("applied", T::Bool),
            ("refusal", T::Null(&T::Text)),
            ("epoch_before", T::U),
            ("epoch_after", T::U),
        ],
        "launch_admission" => &[
            ("kind", T::Const("launch_admission")),
            ("execution_id", T::Uuid),
            ("epoch", T::U),
            ("boot_id", T::Uuid),
            ("cgroup_dev", T::U),
            ("cgroup_ino", T::U),
            ("registry_checked", T::Bool),
            ("registry_id", T::Null(&T::Uuid)),
            ("inventory_sha256", T::Null(&T::H)),
        ],
        "artifact_set_admitted" => &[
            ("kind", T::Const("artifact_set_admitted")),
            ("execution_id", T::Uuid),
            ("manifest_sha256", T::H),
            ("artifact_count", T::P),
            ("total_bytes", T::U),
        ],
        "boundary_violation" => &[
            ("kind", T::Const("boundary_violation")),
            ("execution_id", T::Uuid),
            ("epoch", T::U),
            ("reason", T::Enum(REASONS)),
            ("action", T::Enum(&["deny", "quarantine"])),
            ("model_use_sequence", T::P),
            ("restriction_decision_id", T::Null(&T::DecisionId)),
            ("window_start_ms", T::U),
        ],
        "tripwire_presented" => &[
            ("kind", T::Const("tripwire_presented")),
            ("execution_id", T::Uuid),
            ("epoch", T::U),
            ("marker_id", T::Twid),
            ("action", T::Const("quarantine")),
            ("model_use_sequence", T::P),
            ("restriction_decision_id", T::Null(&T::DecisionId)),
            ("window_start_ms", T::U),
        ],
        "admission_released" => &[
            ("kind", T::Const("admission_released")),
            ("execution_id", T::Uuid),
            ("scope_end", T::Enum(&["confirmed", "failed", "unknown"])),
            ("registry_released", T::Bool),
        ],
        "security_events_suppressed" => &[
            ("kind", T::Const("security_events_suppressed")),
            ("first_sequence", T::P),
            ("count", T::U),
            ("window_end_ms", T::U),
            ("complete", T::Bool),
        ],
        _ => return None,
    })
}

/// Reads the control journal, checks framing, canonical bytes, the v2 hash
/// chain and every entry's grammar (stage 3).
fn control_journal(path: &Path, m: &Manifest) -> Result<Journal, Failure> {
    let (st, sec) = (3, "v2 4");
    let data = read_regular(path, st, sec)?;
    ensure(!data.is_empty(), st, sec, "control.jsonl is empty")?;
    ensure(data.is_ascii(), st, sec, "control.jsonl is not ASCII")?;
    ensure(
        data.ends_with(b"\n"),
        st,
        sec,
        "control.jsonl: last line has no LF",
    )?;
    let text = String::from_utf8_lossy(&data[..data.len() - 1]).into_owned();
    let lines: Vec<&str> = text.split('\n').collect();
    for (i, l) in lines.iter().enumerate() {
        ensure(
            !l.is_empty(),
            st,
            sec,
            format!("control.jsonl line {}: blank line", i + 1),
        )?;
        if l.len() > MAX_RECORD {
            return limit(
                st,
                sec,
                format!("control.jsonl line {}: over {MAX_RECORD} bytes", i + 1),
            );
        }
    }
    // Header.
    let header = parse(lines[0], st, sec, "control header")?;
    let canon = canon_obj(
        &header,
        &[
            ("format", T::Const(CONTROL_FORMAT)),
            ("journal_id", T::Uuid),
            ("bundle_manifest_sha256", T::H),
        ],
        st,
        sec,
        "control header",
    )?;
    ensure(
        canon == lines[0],
        st,
        sec,
        "control header is not in canonical form",
    )?;
    let jid = header["journal_id"].as_str().unwrap_or_default().to_owned();
    ensure(
        jid == m.control_journal_id,
        st,
        "v2 3.1",
        "control journal_id differs from bundle.json",
    )?;
    ensure(
        header["bundle_manifest_sha256"] == m.sha.as_str(),
        st,
        "v2 3.1",
        "control header does not bind this bundle.json",
    )?;
    let mut heads = vec![hex(&sha(&[GENESIS, lines[0].as_bytes()]))];
    let mut bodies = Vec::new();
    for (i, line) in lines.iter().enumerate().skip(1) {
        let n = i as u64;
        let what = format!("control record {n}");
        let Some(rest) = line.strip_prefix("{\"body\":") else {
            return bad(st, sec, format!("{what}: line must start with {{\"body\":"));
        };
        let Some(cut) = rest.rfind(",\"sha256\":\"") else {
            return bad(st, sec, format!("{what}: no sha256"));
        };
        let (body_text, tail) = rest.split_at(cut);
        let digest = tail
            .strip_prefix(",\"sha256\":\"")
            .and_then(|t| t.strip_suffix("\"}"))
            .unwrap_or("");
        ensure(
            is_hex64(digest),
            st,
            sec,
            format!("{what}: line must end with ,\"sha256\":\"<64 hex>\"}}"),
        )?;
        let body = parse(body_text, st, sec, &what)?;
        let bobj = body.as_object().map_or_else(
            || bad(st, sec, format!("{what}: body is not an object")),
            Ok,
        )?;
        ensure(
            bobj.len() == 4
                && ["format", "sequence", "previous_sha256", "entry"]
                    .iter()
                    .all(|k| bobj.contains_key(*k)),
            st,
            sec,
            format!("{what}: body fields must be exactly format, sequence, previous_sha256, entry"),
        )?;
        ensure(
            body["format"] == CONTROL_FORMAT,
            st,
            sec,
            format!("{what}: wrong format"),
        )?;
        ensure(
            body["sequence"].is_u64() && body["sequence"].as_u64() == Some(n),
            st,
            sec,
            format!("{what}: sequence is not {n}"),
        )?;
        ensure(
            body["previous_sha256"] == heads[i - 1].as_str(),
            st,
            sec,
            format!("{what}: previous_sha256 does not link"),
        )?;
        let entry = &body["entry"];
        let kind = entry
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if kind == "tripped" {
            let trigger = entry
                .get("trigger")
                .and_then(Value::as_str)
                .unwrap_or_default();
            ensure(
                NEW_TRIGGERS.contains(&trigger)
                    || !(trigger.starts_with("boundary_violation:")
                        || trigger.starts_with("tripwire_presented")),
                st,
                "v2 6.7",
                format!("{what}: unknown security trigger {trigger:?}"),
            )?;
        }
        let Some(schema) = entry_schema(kind, entry) else {
            return bad(st, sec, format!("{what}: unknown entry kind {kind:?}"));
        };
        let entry_canon = canon_obj(entry, schema, st, "v2 5", &what)?;
        let canon = format!(
            "{{\"format\":\"{CONTROL_FORMAT}\",\"sequence\":{n},\"previous_sha256\":\"{}\",\"entry\":{entry_canon}}}",
            heads[i - 1]
        );
        ensure(
            canon == body_text,
            st,
            sec,
            format!("{what}: body is not in canonical form"),
        )?;
        ensure(
            hex(&sha(&[ENTRY, body_text.as_bytes()])) == digest,
            st,
            sec,
            format!("{what}: sha256 does not match the body"),
        )?;
        // Increment/profile permissions for new kinds.
        let allowed = match kind {
            "boundary_violation" => m.gateway_observed,
            "tripwire_presented" => m.tripwires,
            "artifact_set_admitted" => m.artifact_digest.is_some(),
            _ => true,
        };
        ensure(
            allowed,
            st,
            sec,
            format!("{what}: {kind} is not allowed by this bundle's hardening profile"),
        )?;
        heads.push(digest.to_owned());
        bodies.push(body);
    }
    Ok(Journal {
        journal_id: jid,
        heads,
        bodies,
    })
}

/// Decision subjects must match the manifest's attribution (§3.1).
fn decision_subjects(dj: &Journal, m: &Manifest) -> Result<(), Failure> {
    ensure(
        dj.journal_id == m.decision_journal_id,
        3,
        "v2 3.1",
        "decision journal_id differs from bundle.json",
    )?;
    for (i, body) in dj.bodies.iter().enumerate() {
        let subject = &body["payload"]["subject"];
        if subject.is_null() {
            continue;
        }
        ensure(
            subject["id"] == m.subject_id.as_str() && subject["session"] == m.session_id.as_str(),
            3,
            "v2 3.1",
            format!(
                "decision record {}: subject differs from bundle.json's subject_id/session_id",
                i + 1
            ),
        )?;
    }
    Ok(())
}

// --------------------------------------------- bindings (§6, §7; stage 4)

struct Admission {
    epoch: u64,
    registry_checked: bool,
    artifact: bool,
    observed: bool,
    confirmed_end: bool,
}

struct Event {
    seq: u64,
    kind: &'static str,
    exec: String,
    epoch: u64,
    /// Reason (boundary_violation) or marker ID (tripwire_presented).
    label: String,
    action: String,
    link: Option<String>,
    start: u64,
    trip: Option<u64>,
    closure: Option<(u64, u64, bool)>,
}

impl Event {
    fn trigger(&self) -> String {
        if self.kind == "tripwire_presented" {
            "tripwire_presented".into()
        } else {
            format!("boundary_violation:{}", self.label)
        }
    }
    fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.exec, self.epoch, self.kind, self.label, self.action
        )
    }
    fn group(&self) -> String {
        format!("{}:{}:{}", self.kind, self.label, self.action)
    }
}

struct Bound {
    events: Vec<Event>,
    incomplete: Vec<String>,
}

fn decision_payload<'a>(dj: &'a Journal, id: &str) -> Option<&'a Value> {
    let (jid, n) = decision_id(id)?;
    if jid != dj.journal_id {
        return None;
    }
    dj.bodies
        .get(usize::try_from(n).ok()?.checked_sub(1)?)
        .map(|b| &b["payload"])
}

fn companion_ok(mu: &Value, kind: &str, reason: &str) -> bool {
    let method = mu["method"].as_str().unwrap_or_default();
    let method_ok = if reason == "model_connect_forbidden" {
        method == "CONNECT"
    } else {
        is_method(method) && method != "CONNECT"
    };
    let (path, refusal) = if kind == "tripwire_presented" {
        (TW_PATH, "gateway tripped")
    } else {
        (BV_PATH, "request not allowed")
    };
    method_ok
        && mu["path"] == path
        && mu["status"] == 403
        && mu["outcome"] == "refused"
        && mu["request_bytes"] == 0
        && mu["response_bytes"] == 0
        && mu["refusal"] == refusal
}

fn bindings(
    cj: &Journal,
    dj: &Journal,
    m: &Manifest,
    arts: Option<&Artifacts>,
) -> Result<Bound, Failure> {
    let st = 4;
    let mut adm: HashMap<String, Admission> = HashMap::new();
    let mut adm_order: Vec<String> = Vec::new();
    let mut events: Vec<Event> = Vec::new();
    let mut by_seq: HashMap<u64, usize> = HashMap::new();
    let mut last_by_key: HashMap<String, usize> = HashMap::new();
    let mut used_companions: HashSet<u64> = HashSet::new();
    let mut used_links: HashSet<String> = HashSet::new();
    let mut model_uses: HashMap<u64, &Value> = HashMap::new();
    let mut applied_resets: Vec<u64> = Vec::new();
    let mut incomplete = Vec::new();

    for (i, body) in cj.bodies.iter().enumerate() {
        let seq = i as u64 + 1;
        let e = &body["entry"];
        let kind = e["kind"].as_str().unwrap_or_default();
        let what = format!("control record {seq} ({kind})");
        let s = |k: &str| e[k].as_str().unwrap_or_default().to_owned();
        let u = |k: &str| e[k].as_u64().unwrap_or(0);
        match kind {
            "model_use" => {
                ensure(
                    (e["outcome"] == "refused") == !e["refusal"].is_null(),
                    st,
                    "v2 5",
                    format!("{what}: refusal must be set exactly when outcome is refused"),
                )?;
                model_uses.insert(seq, e);
            }
            "reset" => {
                let (before, after) = (u("epoch_before"), u("epoch_after"));
                if e["applied"] == true {
                    let reason = e["reason"].as_str().unwrap_or_default();
                    ensure(
                        (1..=256).contains(&reason.len())
                            && reason.bytes().all(|b| (0x20..0x7f).contains(&b))
                            && !reason.trim().is_empty()
                            && e["refusal"].is_null()
                            && before.checked_add(1) == Some(after),
                        st,
                        "v2 5",
                        format!(
                            "{what}: an applied reset needs a 1..256-byte printable reason, no refusal, and epoch +1"
                        ),
                    )?;
                    applied_resets.push(seq);
                } else {
                    ensure(
                        before == after,
                        st,
                        "v2 5",
                        format!("{what}: a refused reset must not change the epoch"),
                    )?;
                }
            }
            "anchor" => {
                ensure(
                    e["outcome"] != "anchored" || !e["log_index"].is_null(),
                    st,
                    "v2 5",
                    format!("{what}: an anchored outcome needs a log_index"),
                )?;
            }
            "launch_admission" => {
                let exec = s("execution_id");
                ensure(
                    !adm.contains_key(&exec),
                    st,
                    "v2 6.1",
                    format!("{what}: execution_id is not new"),
                )?;
                let checked = e["registry_checked"] == true;
                if m.registry {
                    ensure(
                        checked && !e["registry_id"].is_null() && !e["inventory_sha256"].is_null(),
                        st,
                        "v2 6.1",
                        format!(
                            "{what}: increment 3 needs a registry check, registry_id and inventory digest"
                        ),
                    )?;
                } else {
                    ensure(
                        !checked && e["registry_id"].is_null() && e["inventory_sha256"].is_null(),
                        st,
                        "v2 6.1",
                        format!(
                            "{what}: before increment 3 the registry fields must be false/null"
                        ),
                    )?;
                }
                adm.insert(
                    exec.clone(),
                    Admission {
                        epoch: u("epoch"),
                        registry_checked: checked,
                        artifact: false,
                        observed: false,
                        confirmed_end: false,
                    },
                );
                adm_order.push(exec);
            }
            "artifact_set_admitted" => {
                let exec = s("execution_id");
                let a = adm.get_mut(&exec).map_or_else(
                    || {
                        bad(
                            st,
                            "v2 6.2",
                            format!("{what}: no earlier admission for this execution"),
                        )
                    },
                    Ok,
                )?;
                ensure(
                    !a.artifact,
                    st,
                    "v2 6.2",
                    format!("{what}: a second artifact admission for this execution"),
                )?;
                ensure(
                    !a.observed && !a.confirmed_end,
                    st,
                    "v2 6.2",
                    format!("{what}: must precede the execution's observations and release"),
                )?;
                let arts = arts.map_or_else(
                    || bad(st, "v2 6.2", format!("{what}: no artifact set declared")),
                    Ok,
                )?;
                ensure(
                    Some(s("manifest_sha256")) == m.artifact_digest
                        && u("artifact_count") == arts.count
                        && u("total_bytes") == arts.total,
                    st,
                    "v2 6.2",
                    format!("{what}: digest, count or total differs from artifacts.json"),
                )?;
                a.artifact = true;
            }
            "boundary_violation" | "tripwire_presented" => {
                let kind: &'static str = if kind == "boundary_violation" {
                    "boundary_violation"
                } else {
                    "tripwire_presented"
                };
                let sec = if kind == "boundary_violation" {
                    "v2 6.3"
                } else {
                    "v2 6.4"
                };
                let exec = s("execution_id");
                let epoch = u("epoch");
                let a = adm.get_mut(&exec).map_or_else(
                    || {
                        bad(
                            st,
                            sec,
                            format!("{what}: no earlier admission for this execution"),
                        )
                    },
                    Ok,
                )?;
                ensure(
                    !a.confirmed_end,
                    st,
                    "v2 6.5",
                    format!("{what}: after the execution's confirmed end"),
                )?;
                ensure(
                    m.artifact_digest.is_none() || a.artifact,
                    st,
                    "v2 6.2",
                    format!("{what}: before the execution's artifact admission"),
                )?;
                ensure(
                    epoch >= a.epoch,
                    st,
                    sec,
                    format!("{what}: epoch precedes the execution's admission epoch"),
                )?;
                a.observed = true;
                let start = u("window_start_ms");
                ensure(
                    start <= u64::MAX - WINDOW_MS,
                    st,
                    sec,
                    format!("{what}: window_start_ms too large"),
                )?;
                let action = s("action");
                let label = if kind == "boundary_violation" {
                    let reason = s("reason");
                    let want = if reason == "model_endpoint_not_allowlisted" && !m.trip_on_endpoint
                    {
                        "deny"
                    } else {
                        "quarantine"
                    };
                    ensure(
                        action == want,
                        st,
                        sec,
                        format!("{what}: action must be {want} for {reason} under this profile"),
                    )?;
                    reason
                } else {
                    let marker = s("marker_id");
                    ensure(
                        m.tripwire_ids.contains(&marker),
                        st,
                        sec,
                        format!("{what}: marker {marker} is not in the manifest"),
                    )?;
                    marker
                };
                // Companion model_use (§7).
                let mus = u("model_use_sequence");
                let mu = (mus < seq).then(|| model_uses.get(&mus)).flatten();
                let mu = mu.map_or_else(
                    || {
                        bad(
                            st,
                            "v2 7",
                            format!("{what}: model_use_sequence {mus} is not an earlier model_use"),
                        )
                    },
                    Ok,
                )?;
                ensure(
                    used_companions.insert(mus),
                    st,
                    "v2 7",
                    format!("{what}: companion model_use {mus} is already used"),
                )?;
                ensure(
                    companion_ok(mu, kind, &label),
                    st,
                    "v2 7",
                    format!(
                        "{what}: companion model_use {mus} does not have the safe fixed values"
                    ),
                )?;
                // Restriction link.
                let link = e["restriction_decision_id"].as_str().map(str::to_owned);
                if action == "deny" {
                    ensure(
                        link.is_none(),
                        st,
                        sec,
                        format!("{what}: a deny event must not link a restriction"),
                    )?;
                }
                if let Some(id) = &link {
                    let p = decision_payload(dj, id).map_or_else(
                        || {
                            bad(
                                st,
                                sec,
                                format!("{what}: restriction {id} is not in the decision journal"),
                            )
                        },
                        Ok,
                    )?;
                    ensure(
                        p["event"] == "RiskApplied"
                            && p["outcome"] == "RESTRICTED"
                            && p["state"] == "Quarantined"
                            && epoch.checked_add(1).is_some_and(|x| p["epoch"] == x),
                        st,
                        sec,
                        format!(
                            "{what}: restriction {id} is not a RiskApplied quarantine at epoch + 1"
                        ),
                    )?;
                    ensure(
                        used_links.insert(id.clone()),
                        st,
                        "v2 6.7",
                        format!("{what}: restriction {id} is linked twice"),
                    )?;
                }
                let ev = Event {
                    seq,
                    kind,
                    exec,
                    epoch,
                    label,
                    action,
                    link,
                    start,
                    trip: None,
                    closure: None,
                };
                // No overlapping same-key windows (§6.6).
                if let Some(&prev) = last_by_key.get(&ev.key()) {
                    let p = &events[prev];
                    ensure(
                        p.closure.is_some_and(|(cs, _, _)| cs < seq)
                            && p.start.checked_add(WINDOW_MS).is_some_and(|d| start >= d),
                        st,
                        "v2 6.6",
                        format!("{what}: overlaps the open window of record {}", p.seq),
                    )?;
                }
                last_by_key.insert(ev.key(), events.len());
                by_seq.insert(seq, events.len());
                events.push(ev);
            }
            "security_events_suppressed" => {
                let first = u("first_sequence");
                let idx = (first < seq).then(|| by_seq.get(&first)).flatten();
                let idx = *idx.map_or_else(
                    || {
                        bad(
                            st,
                            "v2 6.6",
                            format!(
                                "{what}: first_sequence {first} is not an earlier security event"
                            ),
                        )
                    },
                    Ok,
                )?;
                let ev = &mut events[idx];
                ensure(
                    ev.closure.is_none(),
                    st,
                    "v2 6.6",
                    format!("{what}: a second closure for record {first}"),
                )?;
                let (count, end) = (u("count"), u("window_end_ms"));
                ensure(
                    end >= ev.start && end <= ev.start + WINDOW_MS,
                    st,
                    "v2 6.6",
                    format!("{what}: window_end_ms outside [start, start + 5000]"),
                )?;
                let complete = e["complete"] == true;
                ensure(
                    !(count == u64::MAX && complete),
                    st,
                    "v2 6.6",
                    format!("{what}: a saturated count cannot be complete"),
                )?;
                ev.closure = Some((seq, count, complete));
            }
            "tripped" => {
                let trigger = s("trigger");
                if !NEW_TRIGGERS.contains(&trigger.as_str()) {
                    continue;
                }
                let es = u("security_event_sequence");
                let idx = (es < seq).then(|| by_seq.get(&es)).flatten();
                let idx = *idx.map_or_else(
                    || bad(st, "v2 6.7", format!("{what}: security_event_sequence {es} is not an earlier security event")),
                    Ok,
                )?;
                let ev = &mut events[idx];
                ensure(
                    ev.action == "quarantine" && ev.trigger() == trigger,
                    st,
                    "v2 6.7",
                    format!("{what}: trigger does not match record {es}"),
                )?;
                ensure(
                    ev.trip.is_none(),
                    st,
                    "v2 6.7",
                    format!("{what}: record {es} already has a trip"),
                )?;
                let (before, after) = (u("epoch_before"), u("epoch_after"));
                ensure(
                    before == ev.epoch && before.checked_add(1) == Some(after),
                    st,
                    "v2 6.7",
                    format!("{what}: epoch transition does not match record {es}"),
                )?;
                ensure(
                    (e["restriction_persisted"] == true) == ev.link.is_some(),
                    st,
                    "v2 6.7",
                    format!(
                        "{what}: restriction_persisted must match whether record {es} links a restriction"
                    ),
                )?;
                ensure(
                    !applied_resets.iter().any(|r| *r > ev.seq && *r < seq),
                    st,
                    "v2 6.7",
                    format!("{what}: an applied reset intervenes after record {es}"),
                )?;
                ev.trip = Some(seq);
            }
            "admission_released" => {
                let exec = s("execution_id");
                let a = adm.get_mut(&exec).map_or_else(
                    || {
                        bad(
                            st,
                            "v2 6.5",
                            format!("{what}: no earlier admission for this execution"),
                        )
                    },
                    Ok,
                )?;
                ensure(
                    !a.confirmed_end,
                    st,
                    "v2 6.5",
                    format!("{what}: after the execution's confirmed end"),
                )?;
                let confirmed = e["scope_end"] == "confirmed";
                if e["registry_released"] == true {
                    ensure(
                        m.registry && a.registry_checked && confirmed,
                        st,
                        "v2 6.5",
                        format!(
                            "{what}: a registry release needs a registry-checked admission and a confirmed end"
                        ),
                    )?;
                }
                a.confirmed_end = confirmed;
            }
            _ => {}
        }
    }

    // §6.7: every durably linked quarantine needs its later trip, except at the
    // substantive tail of the journal.
    let last_substantive = cj
        .bodies
        .iter()
        .enumerate()
        .filter(|(_, b)| !is_bookkeeping(b))
        .map(|(i, _)| i as u64 + 1)
        .max()
        .unwrap_or(0);
    for ev in &events {
        if ev.action != "quarantine" || ev.trip.is_some() {
            continue;
        }
        match &ev.link {
            Some(_) if ev.seq == last_substantive => incomplete.push(format!(
                "trip record missing (control record {}, terminal)",
                ev.seq
            )),
            Some(_) => {
                return bad(
                    st,
                    "v2 6.7",
                    format!(
                        "control record {}: durable quarantine with no trip record, and later substantive records exist",
                        ev.seq
                    ),
                );
            }
            None => incomplete.push(format!(
                "restriction not durable and no trip record (control record {})",
                ev.seq
            )),
        }
    }
    for ev in &events {
        if ev.closure.is_none() {
            incomplete.push(format!(
                "repeat window not closed (control record {})",
                ev.seq
            ));
        } else if ev.closure.is_some_and(|(_, _, c)| !c) {
            incomplete.push(format!(
                "repeat count incomplete (control record {})",
                ev.seq
            ));
        }
    }
    let mut unmatched: Vec<u64> = model_uses
        .iter()
        .filter(|(seq, mu)| {
            (mu["path"] == BV_PATH || mu["path"] == TW_PATH) && !used_companions.contains(seq)
        })
        .map(|(seq, _)| *seq)
        .collect();
    unmatched.sort_unstable();
    for seq in unmatched {
        incomplete.push(format!(
            "security companion with no event (control record {seq})"
        ));
    }
    if m.artifact_digest.is_some() {
        for exec in &adm_order {
            if !adm[exec].artifact {
                incomplete.push(format!(
                    "artifact admission missing for execution {exec} (release not shown)"
                ));
            }
        }
    }
    Ok(Bound { events, incomplete })
}

/// Control `checkpoint` entries must name checkpoints in the file (§5).
fn checkpoint_entries(cj: &Journal, chain: &[Checkpoint]) -> Result<(), Failure> {
    for (i, body) in cj.bodies.iter().enumerate() {
        let e = &body["entry"];
        if e["kind"] != "checkpoint" {
            continue;
        }
        let k = e["sequence"].as_u64().unwrap_or(0);
        let cp = usize::try_from(k)
            .ok()
            .and_then(|k| k.checked_sub(1))
            .and_then(|k| chain.get(k));
        ensure(
            cp.is_some_and(|cp| {
                cp.digest == e["statement_sha256"] && cp.statement["reason"] == e["reason"]
            }),
            5,
            "v2 5",
            format!(
                "control record {}: claims checkpoint {k}, which is not in the checkpoint file as recorded",
                i + 1
            ),
        )?;
    }
    Ok(())
}

// --------------------------------------------------- totals (§9; stage 7)

/// Totals, outcomes and completeness for a valid v2 bundle (contract §9).
/// Observed traffic totals are lower bounds.
#[derive(Debug, Default)]
pub struct Report {
    pub increment: u64,
    pub model_mode: String,
    pub artifacts: Option<u64>,
    pub model_use_recorded: BTreeMap<String, u128>,
    pub model_use_suppressed: u128,
    pub security_suppressed: BTreeMap<String, u128>,
    pub model_requests_observed_lower_bound: u128,
    pub model_refusals_observed_lower_bound: u128,
    /// Keyed `reason:action`.
    pub boundary_violations_observed_lower_bound: BTreeMap<String, u128>,
    /// Keyed by marker ID.
    pub tripwire_presentations_observed_lower_bound: BTreeMap<String, u128>,
    pub trips_recorded: usize,
    pub kills: BTreeMap<String, usize>,
    pub resets_applied: usize,
    pub resets_refused: usize,
    pub admissions: usize,
    pub admissions_registry_checked: usize,
    pub releases: BTreeMap<String, usize>,
    pub security_counts_complete: bool,
    /// Why the record is incomplete, in journal order. Empty when nothing is known missing.
    pub incomplete: Vec<String>,
}

fn add(a: u128, b: u128) -> Result<u128, Failure> {
    a.checked_add(b)
        .map_or_else(|| limit(7, "v2 9", "a total overflowed"), Ok)
}

fn report(
    cj: &Journal,
    m: &Manifest,
    arts: Option<&Artifacts>,
    bound: Bound,
    chain: &[Checkpoint],
    is_sealed: bool,
) -> Result<Report, Failure> {
    let mut r = Report {
        increment: m.increment,
        model_mode: m.model_mode.clone(),
        artifacts: arts.map(|a| a.count),
        incomplete: bound.incomplete,
        ..Report::default()
    };
    let mut model_uses: u128 = 0;
    let mut refused: u128 = 0;
    for b in &cj.bodies {
        let e = &b["entry"];
        let n = |k: &str| u128::from(e[k].as_u64().unwrap_or(0));
        match e["kind"].as_str().unwrap_or_default() {
            "model_use" => {
                let o = e["outcome"].as_str().unwrap_or_default().to_owned();
                *r.model_use_recorded.entry(o).or_default() += 1;
                model_uses += 1;
                if e["outcome"] == "refused" {
                    refused += 1;
                }
            }
            "model_uses_suppressed" => {
                r.model_use_suppressed = add(r.model_use_suppressed, n("count"))?
            }
            "tripped" => r.trips_recorded += 1,
            "kill" => {
                *r.kills
                    .entry(e["outcome"].as_str().unwrap_or_default().to_owned())
                    .or_default() += 1;
            }
            "reset" if e["applied"] == true => r.resets_applied += 1,
            "reset" => r.resets_refused += 1,
            "launch_admission" => {
                r.admissions += 1;
                if e["registry_checked"] == true {
                    r.admissions_registry_checked += 1;
                }
            }
            "admission_released" => {
                *r.releases
                    .entry(e["scope_end"].as_str().unwrap_or_default().to_owned())
                    .or_default() += 1;
            }
            _ => {}
        }
    }
    let mut security_total: u128 = 0;
    for ev in &bound.events {
        let extra = u128::from(ev.closure.map_or(0, |(_, c, _)| c));
        security_total = add(security_total, extra)?;
        let g = r.security_suppressed.entry(ev.group()).or_default();
        *g = add(*g, extra)?;
        let (map, key) = if ev.kind == "boundary_violation" {
            (
                &mut r.boundary_violations_observed_lower_bound,
                format!("{}:{}", ev.label, ev.action),
            )
        } else {
            (
                &mut r.tripwire_presentations_observed_lower_bound,
                ev.label.clone(),
            )
        };
        let slot = map.entry(key).or_default();
        *slot = add(*slot, add(1, extra)?)?;
    }
    r.model_requests_observed_lower_bound =
        add(add(model_uses, r.model_use_suppressed)?, security_total)?;
    r.model_refusals_observed_lower_bound =
        add(add(refused, r.model_use_suppressed)?, security_total)?;
    let shutdown = chain
        .last()
        .is_some_and(|cp| cp.statement["reason"] == "shutdown");
    r.security_counts_complete = is_sealed && shutdown && r.incomplete.is_empty();
    if !is_sealed {
        r.incomplete
            .push("records after the last checkpoint are not covered (unsealed)".into());
    } else if !shutdown {
        r.incomplete
            .push("last checkpoint is not a shutdown checkpoint".into());
    }
    Ok(r)
}

// --------------------------------------------------------------- verify

pub(crate) fn verify(o: &Options, keys: GatewayKeys) -> Result<Summary, Failure> {
    // Stage 2: manifest and required files.
    let m = manifest(o.bundle)?;
    inventory(o.bundle)?;
    // Stage 3: decision journal (v1 §2, unchanged), then the v2 control journal.
    let dj = decision_journal(&o.bundle.join("decision.jsonl"))?;
    decision_subjects(&dj, &m)?;
    let cj = control_journal(&o.bundle.join("control.jsonl"), &m)?;
    // Stage 4: artifacts.json, then cross-record bindings.
    let arts = artifacts(o.bundle, &m)?;
    let bound = bindings(&cj, &dj, &m, arts.as_ref())?;
    // Stage 5: checkpoints (v1 §4 with the v2 control heads).
    let chain = checkpoints(&o.bundle.join("checkpoints.jsonl"), &keys, &dj, &cj)?;
    checkpoint_entries(&cj, &chain)?;
    // Stage 6: anchors and receipts (v1 §6, §5).
    let (anchors, receipts_checked, log_key) = anchors_and_receipts(o, &keys, &cj, &chain)?;
    // Stage 7: flags and totals.
    let is_sealed = sealed(&chain, &dj, &cj);
    let rep = report(&cj, &m, arts.as_ref(), bound, &chain, is_sealed)?;
    Ok(Summary {
        format: 2,
        key_id: keys.key_id,
        decision_records: dj.bodies.len(),
        control_records: cj.bodies.len(),
        checkpoints: chain.len(),
        anchors,
        receipts_checked,
        sealed: is_sealed,
        trips: rep.trips_recorded,
        log_key,
        v2: Some(rep),
    })
}
