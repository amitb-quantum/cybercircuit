//! Builds synthetic, signed format-v2 bundles for tests.
//!
//! Everything here is written from the v2 contract and the v1 spec: the
//! builder signs real checkpoints with throwaway keys, so the verifier is
//! exercised end to end. No gateway code is involved.

#![allow(dead_code)]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use sha2::{Digest, Sha256};
use slh_dsa::{Sha2_128f, SigningKey};

pub const DJ: &str = "00000000-0000-4000-8000-0000000000d1";
pub const CJ: &str = "00000000-0000-4000-8000-0000000000c1";
pub const EXEC: &str = "00000000-0000-4000-8000-0000000000e1";
pub const EXEC2: &str = "00000000-0000-4000-8000-0000000000e2";
pub const BOOT: &str = "00000000-0000-4000-8000-0000000000b0";

pub fn sha(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn hexs(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

pub struct Keys {
    slh: SigningKey<Sha2_128f>,
    ecdsa: EcdsaKeyPair,
    pub key_id: String,
    pub file: String,
}

pub fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    K.get_or_init(|| {
        let slh = SigningKey::<Sha2_128f>::slh_keygen_internal(&[1; 16], &[2; 16], &[3; 16]);
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let ecdsa =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let slh_pk = slh.as_ref().to_bytes().to_vec();
        let point = ecdsa.public_key().as_ref().to_vec();
        let key_id = sha(&[
            b"circuitbreaker-gateway-keys-v1\0",
            &32u32.to_be_bytes(),
            &slh_pk,
            &point,
        ]);
        let file = format!(
            "{{\"schema_version\":\"circuitbreaker.gateway-keys.v1\",\"gateway_key_id\":\"{key_id}\",\"slh_dsa_sha2_128f\":\"{}\",\"ecdsa_p256\":\"{}\"}}\n",
            hexs(&slh_pk),
            hexs(&point)
        );
        Keys {
            slh,
            ecdsa,
            key_id,
            file,
        }
    })
}

/// When set, bundles are kept under this directory with their expected
/// verdicts, as a conformance set to exchange with other implementations.
pub fn export_dir() -> Option<PathBuf> {
    std::env::var_os("CC_V2_FIXTURES").map(PathBuf::from)
}

/// The trusted copy of the keys, outside any bundle.
pub fn trusted_keys() -> PathBuf {
    let p = export_dir().map_or_else(
        || std::env::temp_dir().join(format!("cc-v2-keys-{}.json", std::process::id())),
        |d| d.join("trusted-gateway-keys.pub.json"),
    );
    if !p.exists() {
        fs::write(&p, &keys().file).unwrap();
    }
    p
}

pub fn sign(statement: &str) -> String {
    let k = keys();
    let digest = sha(&[statement.as_bytes()]);
    let slh = k
        .slh
        .try_sign_with_context(statement.as_bytes(), b"circuitbreaker-checkpoint-v1", None)
        .unwrap();
    let ecdsa = k
        .ecdsa
        .sign(&SystemRandom::new(), statement.as_bytes())
        .unwrap();
    format!(
        "{{\"statement\":{statement},\"statement_sha256\":\"{digest}\",\"slh_dsa_sha2_128f\":\"{}\",\"ecdsa_p256_sha256\":\"{}\"}}",
        hexs(&slh.to_bytes()),
        hexs(ecdsa.as_ref())
    )
}

#[derive(Clone)]
pub struct Profile {
    pub increment: u8,
    pub model_mode: &'static str,
    pub trip_on_endpoint: bool,
    pub artifacts: Option<String>,
    pub tripwire_ids: Vec<&'static str>,
}

impl Default for Profile {
    fn default() -> Self {
        Profile {
            increment: 1,
            model_mode: "anthropic",
            trip_on_endpoint: false,
            artifacts: None,
            tripwire_ids: vec![],
        }
    }
}

pub fn manifest(p: &Profile) -> String {
    let model = p.model_mode != "none";
    let tripwires = p.increment >= 2 && model;
    let ids: Vec<String> = p.tripwire_ids.iter().map(|i| format!("\"{i}\"")).collect();
    format!(
        "{{\"schema_version\":\"circuitbreaker.bundle.v2\",\"run_id\":\"run-1\",\"subject_id\":\"demo\",\"session_id\":\"session-1\",\"operator_uid\":1000,\"decision_journal_id\":\"{DJ}\",\"control_journal_id\":\"{CJ}\",\"hardening\":{{\"increment\":{},\"model_mode\":\"{}\",\"gateway_observed\":{model},\"trip_on_model_endpoint_not_allowlisted\":{},\"package_mode\":\"pre_staged_ro\",\"artifact_manifest_sha256\":{},\"tripwires\":{tripwires},\"tripwire_ids\":[{}],\"tripwire_catalogue_sha256\":{},\"registry\":{}}}}}\n",
        p.increment,
        p.model_mode,
        p.trip_on_endpoint,
        p.artifacts.as_ref().map_or("null".to_owned(), |a| format!(
            "\"{}\"",
            sha(&[a.as_bytes()])
        )),
        ids.join(","),
        if tripwires {
            format!("\"{}\"", "ab".repeat(32))
        } else {
            "null".to_owned()
        },
        p.increment == 3
    )
}

pub enum Step {
    /// A decision payload (fields after `sequence`, as JSON text without braces).
    Decision(String),
    /// A control entry, exact JSON text.
    Control(String),
    /// Sign a checkpoint with this reason, then record its bookkeeping entry.
    Checkpoint(&'static str),
}

pub struct Bundle {
    pub dir: PathBuf,
}

impl Bundle {
    pub fn path(&self) -> &Path {
        &self.dir
    }
    pub fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
    pub fn read(&self, name: &str) -> String {
        fs::read_to_string(self.file(name)).unwrap()
    }
    pub fn write(&self, name: &str, text: &str) {
        fs::write(self.file(name), text).unwrap();
    }
}

pub struct Builder {
    pub profile: Profile,
    pub manifest_override: Option<String>,
    pub steps: Vec<Step>,
}

/// Fixed-name scratch directory per test.
pub fn scratch(name: &str) -> PathBuf {
    let dir = export_dir().map_or_else(
        || std::env::temp_dir().join(format!("cc-v2-{}-{name}", std::process::id())),
        |d| d.join(name),
    );
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn decision_id(n: u64) -> String {
    format!("{DJ}:{n:016x}")
}

impl Builder {
    pub fn new(profile: Profile) -> Self {
        Builder {
            profile,
            manifest_override: None,
            steps: Vec::new(),
        }
    }
    pub fn d(mut self, payload: &str) -> Self {
        self.steps.push(Step::Decision(payload.to_owned()));
        self
    }
    pub fn c(mut self, entry: &str) -> Self {
        self.steps.push(Step::Control(entry.to_owned()));
        self
    }
    pub fn cp(mut self, reason: &'static str) -> Self {
        self.steps.push(Step::Checkpoint(reason));
        self
    }

    pub fn build(self, name: &str) -> Bundle {
        let dir = scratch(name);
        let manifest = self
            .manifest_override
            .clone()
            .unwrap_or_else(|| manifest(&self.profile));
        fs::write(dir.join("bundle.json"), &manifest).unwrap();
        if let Some(a) = &self.profile.artifacts {
            fs::write(dir.join("artifacts.json"), a).unwrap();
        }
        fs::write(dir.join("gateway-keys.pub.json"), &keys().file).unwrap();

        let dh = format!("{{\"format\":\"circuitbreaker-m2.1\",\"journal_id\":\"{DJ}\"}}");
        let mut dlines = vec![dh.clone()];
        let mut dhead = sha(&[b"circuitbreaker.m2.genesis\0", dh.as_bytes()]);
        let (mut depoch, mut dstate) = (0u64, "Active".to_owned());

        let ch = format!(
            "{{\"format\":\"circuitbreaker-control.2\",\"journal_id\":\"{CJ}\",\"bundle_manifest_sha256\":\"{}\"}}",
            sha(&[manifest.as_bytes()])
        );
        let mut clines = vec![ch.clone()];
        let mut chead = sha(&[b"circuitbreaker-control-v2/genesis\0", ch.as_bytes()]);

        let mut cps: Vec<String> = Vec::new();
        let mut prev_cp = "0".repeat(64);

        let push_control = |clines: &mut Vec<String>, chead: &mut String, entry: &str| {
            let n = clines.len();
            let body = format!(
                "{{\"format\":\"circuitbreaker-control.2\",\"sequence\":{n},\"previous_sha256\":\"{chead}\",\"entry\":{entry}}}"
            );
            let h = sha(&[b"circuitbreaker-control-v2/entry\0", body.as_bytes()]);
            clines.push(format!("{{\"body\":{body},\"sha256\":\"{h}\"}}"));
            *chead = h;
        };

        for step in &self.steps {
            match step {
                Step::Decision(p) => {
                    let n = dlines.len();
                    let v: serde_json::Value = serde_json::from_str(&format!("{{{p}}}")).unwrap();
                    if let Some(e) = v["epoch"].as_u64() {
                        depoch = e;
                    }
                    if let Some(s) = v["state"].as_str() {
                        dstate = s.to_owned();
                    }
                    let body = format!(
                        "{{\"format\":\"circuitbreaker-m2.1\",\"sequence\":{n},\"previous_sha256\":\"{dhead}\",\"decision_id\":\"{}\",\"payload\":{{\"schema_version\":\"phase1.1\",\"sequence\":{n},{p}}}}}",
                        decision_id(n as u64)
                    );
                    let h = sha(&[b"circuitbreaker.m2.record\0", body.as_bytes()]);
                    dlines.push(format!("{{\"body\":{body},\"sha256\":\"{h}\"}}"));
                    dhead = h;
                }
                Step::Control(e) => push_control(&mut clines, &mut chead, e),
                Step::Checkpoint(reason) => {
                    let k = cps.len() + 1;
                    let statement = format!(
                        "{{\"schema_version\":\"circuitbreaker.checkpoint.v1\",\"gateway_key_id\":\"{}\",\"sequence\":{k},\"reason\":\"{reason}\",\"decision\":{{\"journal_id\":\"{DJ}\",\"sequence\":{},\"head_sha256\":\"{dhead}\",\"epoch\":{depoch},\"state\":\"{dstate}\"}},\"control\":{{\"journal_id\":\"{CJ}\",\"sequence\":{},\"head_sha256\":\"{chead}\"}},\"previous_checkpoint_sha256\":\"{prev_cp}\",\"wall_time_unix_ms\":1761000000000}}",
                        keys().key_id,
                        dlines.len() - 1,
                        clines.len() - 1
                    );
                    let line = sign(&statement);
                    prev_cp = sha(&[statement.as_bytes()]);
                    cps.push(line);
                    let entry = format!(
                        "{{\"kind\":\"checkpoint\",\"sequence\":{k},\"reason\":\"{reason}\",\"statement_sha256\":\"{prev_cp}\"}}"
                    );
                    push_control(&mut clines, &mut chead, &entry);
                }
            }
        }
        let join = |l: &[String]| l.iter().map(|x| format!("{x}\n")).collect::<String>();
        fs::write(dir.join("decision.jsonl"), join(&dlines)).unwrap();
        fs::write(dir.join("control.jsonl"), join(&clines)).unwrap();
        fs::write(dir.join("checkpoints.jsonl"), join(&cps)).unwrap();
        Bundle { dir }
    }
}

// ------------------------------------------------------- entry helpers

pub fn admission(exec: &str, epoch: u64) -> String {
    format!(
        "{{\"kind\":\"launch_admission\",\"execution_id\":\"{exec}\",\"epoch\":{epoch},\"boot_id\":\"{BOOT}\",\"cgroup_dev\":1,\"cgroup_ino\":2,\"registry_checked\":false,\"registry_id\":null,\"inventory_sha256\":null}}"
    )
}

pub fn admission_registry(exec: &str, epoch: u64) -> String {
    format!(
        "{{\"kind\":\"launch_admission\",\"execution_id\":\"{exec}\",\"epoch\":{epoch},\"boot_id\":\"{BOOT}\",\"cgroup_dev\":1,\"cgroup_ino\":2,\"registry_checked\":true,\"registry_id\":\"00000000-0000-4000-8000-0000000000f0\",\"inventory_sha256\":\"{}\"}}",
        "cd".repeat(32)
    )
}

pub fn release(exec: &str, end: &str, registry: bool) -> String {
    format!(
        "{{\"kind\":\"admission_released\",\"execution_id\":\"{exec}\",\"scope_end\":\"{end}\",\"registry_released\":{registry}}}"
    )
}

pub fn model_use(
    method: &str,
    path: &str,
    status: u16,
    outcome: &str,
    refusal: Option<&str>,
) -> String {
    let refusal = refusal.map_or("null".to_owned(), |r| format!("\"{r}\""));
    let bytes = if outcome == "refused" { 0 } else { 120 };
    format!(
        "{{\"kind\":\"model_use\",\"method\":\"{method}\",\"path\":\"{path}\",\"request_bytes\":{bytes},\"status\":{status},\"response_bytes\":{bytes},\"outcome\":\"{outcome}\",\"refusal\":{refusal}}}"
    )
}

pub fn ok_use() -> String {
    model_use("POST", "/v1/messages", 200, "completed", None)
}

pub fn bv_companion(method: &str) -> String {
    model_use(
        method,
        "[boundary_violation]",
        403,
        "refused",
        Some("request not allowed"),
    )
}

pub fn tw_companion() -> String {
    model_use(
        "POST",
        "[tripwire_presented]",
        403,
        "refused",
        Some("gateway tripped"),
    )
}

pub fn bv(
    exec: &str,
    epoch: u64,
    reason: &str,
    action: &str,
    mus: u64,
    link: Option<u64>,
    start: u64,
) -> String {
    let link = link.map_or("null".to_owned(), |n| format!("\"{}\"", decision_id(n)));
    format!(
        "{{\"kind\":\"boundary_violation\",\"execution_id\":\"{exec}\",\"epoch\":{epoch},\"reason\":\"{reason}\",\"action\":\"{action}\",\"model_use_sequence\":{mus},\"restriction_decision_id\":{link},\"window_start_ms\":{start}}}"
    )
}

pub fn tw(exec: &str, epoch: u64, marker: &str, mus: u64, link: Option<u64>, start: u64) -> String {
    let link = link.map_or("null".to_owned(), |n| format!("\"{}\"", decision_id(n)));
    format!(
        "{{\"kind\":\"tripwire_presented\",\"execution_id\":\"{exec}\",\"epoch\":{epoch},\"marker_id\":\"{marker}\",\"action\":\"quarantine\",\"model_use_sequence\":{mus},\"restriction_decision_id\":{link},\"window_start_ms\":{start}}}"
    )
}

pub fn closure(first: u64, count: u64, end: u64, complete: bool) -> String {
    format!(
        "{{\"kind\":\"security_events_suppressed\",\"first_sequence\":{first},\"count\":{count},\"window_end_ms\":{end},\"complete\":{complete}}}"
    )
}

pub fn trip(trigger: &str, persisted: bool, event: u64, before: u64) -> String {
    format!(
        "{{\"kind\":\"tripped\",\"trigger\":\"{trigger}\",\"restriction_persisted\":{persisted},\"security_event_sequence\":{event},\"epoch_before\":{before},\"epoch_after\":{}}}",
        before + 1
    )
}

pub fn legacy_trip(trigger: &str) -> String {
    format!("{{\"kind\":\"tripped\",\"trigger\":\"{trigger}\",\"restriction_persisted\":true}}")
}

pub fn kill(outcome: &str) -> String {
    format!("{{\"kind\":\"kill\",\"outcome\":\"{outcome}\"}}")
}

pub fn reset(applied: bool, before: u64) -> String {
    if applied {
        format!(
            "{{\"kind\":\"reset\",\"operator_uid\":1000,\"reason\":\"reviewed\",\"applied\":true,\"refusal\":null,\"epoch_before\":{before},\"epoch_after\":{}}}",
            before + 1
        )
    } else {
        format!(
            "{{\"kind\":\"reset\",\"operator_uid\":1000,\"reason\":null,\"applied\":false,\"refusal\":\"not quarantined\",\"epoch_before\":{before},\"epoch_after\":{before}}}"
        )
    }
}

pub fn artifact_admitted(exec: &str, set: &str, count: u64, total: u64) -> String {
    format!(
        "{{\"kind\":\"artifact_set_admitted\",\"execution_id\":\"{exec}\",\"manifest_sha256\":\"{}\",\"artifact_count\":{count},\"total_bytes\":{total}}}",
        sha(&[set.as_bytes()])
    )
}

/// A RiskApplied quarantine at `epoch` (the event's epoch + 1).
/// Decision payloads in the producer's full shape (v1 §2 payload, "phase1.1").
const POLICY: &str = "\"instance\":1,\"policy_version\":\"test-v1\",\"policy_sha256\":\"2546fb093f2b7a9bc575ad3ca4dc3d8839e71cc0014f504ed36ff78a0462b7c7\",\"tick\":0";

/// A RiskApplied quarantine at `epoch` (the event's epoch + 1).
pub fn quarantine_decision(epoch: u64) -> String {
    format!(
        "{POLICY},\"epoch\":{epoch},\"state\":\"Quarantined\",\"event\":\"RiskApplied\",\"subject\":null,\"action\":null,\"resource_digest\":null,\"capability_id\":null,\"lease_id\":null,\"lease\":null,\"requested_authority\":null,\"restriction\":\"Quarantine\",\"outcome\":\"RESTRICTED\",\"reason\":\"RISK_RESTRICTED\",\"exercised_units\":0"
    )
}

/// An allowed tool use by `subject` in session-1.
pub fn use_decision(epoch: u64, subject: &str) -> String {
    format!(
        "{POLICY},\"epoch\":{epoch},\"state\":\"Active\",\"event\":\"BrokerUse\",\"subject\":{{\"id\":\"{subject}\",\"session\":\"session-1\"}},\"action\":\"CallTool\",\"resource_digest\":\"06941c3703e82d49a278c4520fffb6af5f4161f99172508a9c5da1d7f59d76ca\",\"capability_id\":\"allow-mark\",\"lease_id\":1,\"lease\":null,\"requested_authority\":null,\"restriction\":null,\"outcome\":\"ALLOW\",\"reason\":\"POLICY_SATISFIED\",\"exercised_units\":1"
    )
}

pub fn allow_decision(epoch: u64) -> String {
    use_decision(epoch, "demo")
}

pub fn artifact_set(entries: &[(&str, &str, u64)]) -> String {
    let items: Vec<String> = entries
        .iter()
        .map(|(id, name, bytes)| {
            format!(
                "{{\"id\":\"{id}\",\"filename\":\"{name}\",\"bytes\":{bytes},\"sha256\":\"{}\"}}",
                sha(&[id.as_bytes()])
            )
        })
        .collect();
    format!(
        "{{\"schema_version\":\"circuitbreaker.artifact-set.v1\",\"artifacts\":[{}]}}\n",
        items.join(",")
    )
}
