//! Independent verifier for CircuitBreaker evidence bundles, format version 1
//! (spec revision 1.1, `evidence-bundle-format-v1.md`).
//!
//! Written from the published spec, not from the gateway's code. It only
//! checks evidence; it cannot produce or sign any. Checks run in the order
//! the spec gives for reporting the first failure: trusted keys (§1, §4.1),
//! decision journal (§2), control journal (§3), checkpoints (§4), anchors
//! (§6), receipts (§5).

use std::fmt;
use std::fs;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use slh_dsa::{Sha2_128f, Signature as SlhSignature, VerifyingKey as SlhKey};

const SLH_CONTEXT: &[u8] = b"circuitbreaker-checkpoint-v1";
const P256_SPKI_PREFIX: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200";
const ZERO64: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The first failed check: the spec section and what failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub section: &'static str,
    pub detail: String,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "§{}: {}", self.section, self.detail)
    }
}

fn fail<T>(section: &'static str, detail: impl Into<String>) -> Result<T, Failure> {
    Err(Failure {
        section,
        detail: detail.into(),
    })
}

fn need(cond: bool, section: &'static str, detail: impl Into<String>) -> Result<(), Failure> {
    if cond { Ok(()) } else { fail(section, detail) }
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && unhex(s).is_some()
}

fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => matches!(c, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// Lines of a JSON-lines file: every line ends in `\n`, none is empty.
fn read_lines(path: &Path, section: &'static str, ascii: bool) -> Result<Vec<String>, Failure> {
    let name = path.display().to_string();
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => return fail(section, format!("cannot read {name}: {e}")),
    };
    if data.is_empty() {
        return Ok(Vec::new());
    }
    need(
        data.ends_with(b"\n"),
        section,
        format!("{name}: last line has no newline"),
    )?;
    if ascii {
        need(data.is_ascii(), section, format!("{name}: not ASCII"))?;
    }
    let text = match String::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return fail(section, format!("{name}: not UTF-8")),
    };
    let lines: Vec<String> = text[..text.len() - 1]
        .split('\n')
        .map(str::to_owned)
        .collect();
    need(
        lines.iter().all(|l| !l.is_empty()),
        section,
        format!("{name}: blank line"),
    )?;
    Ok(lines)
}

fn json(text: &str, section: &'static str, what: &str) -> Result<Value, Failure> {
    serde_json::from_str(text).or_else(|_| fail(section, format!("{what}: not JSON")))
}

fn jstr(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

fn get_str<'a>(
    v: &'a Value,
    key: &str,
    section: &'static str,
    what: &str,
) -> Result<&'a str, Failure> {
    v.get(key).and_then(Value::as_str).map_or_else(
        || fail(section, format!("{what}: `{key}` missing or not a string")),
        Ok,
    )
}

fn get_u64(v: &Value, key: &str, section: &'static str, what: &str) -> Result<u64, Failure> {
    v.get(key).and_then(Value::as_u64).map_or_else(
        || {
            fail(
                section,
                format!("{what}: `{key}` missing or not an integer"),
            )
        },
        Ok,
    )
}

fn exact_keys(v: &Value, keys: &[&str], section: &'static str, what: &str) -> Result<(), Failure> {
    let obj = v
        .as_object()
        .map_or_else(|| fail(section, format!("{what}: not an object")), Ok)?;
    need(
        obj.len() == keys.len() && keys.iter().all(|k| obj.contains_key(*k)),
        section,
        format!("{what}: fields must be exactly {keys:?}"),
    )
}

// ---------------------------------------------------------------- keys §4.1

/// The gateway's public keys.
#[derive(Clone)]
pub struct GatewayKeys {
    pub key_id: String,
    slh: SlhKey<Sha2_128f>,
    ecdsa_point: Vec<u8>,
}

pub fn load_gateway_keys(path: &Path) -> Result<GatewayKeys, Failure> {
    let text = fs::read_to_string(path)
        .or_else(|e| fail("4.1", format!("cannot read {}: {e}", path.display())))?;
    let v = json(&text, "4.1", "gateway key file")?;
    exact_keys(
        &v,
        &[
            "schema_version",
            "gateway_key_id",
            "slh_dsa_sha2_128f",
            "ecdsa_p256",
        ],
        "4.1",
        "gateway key file",
    )?;
    need(
        get_str(&v, "schema_version", "4.1", "gateway key file")?
            == "circuitbreaker.gateway-keys.v1",
        "4.1",
        "unsupported key file schema",
    )?;
    let slh_pk = unhex(get_str(&v, "slh_dsa_sha2_128f", "4.1", "gateway key file")?)
        .filter(|k| k.len() == 32);
    let point = unhex(get_str(&v, "ecdsa_p256", "4.1", "gateway key file")?)
        .filter(|p| p.len() == 65 && p[0] == 4);
    let (Some(slh_pk), Some(point)) = (slh_pk, point) else {
        return fail("4.1", "malformed public keys");
    };
    let id = hex(&sha(&[
        b"circuitbreaker-gateway-keys-v1\0",
        &32u32.to_be_bytes(),
        &slh_pk,
        &point,
    ]));
    need(
        get_str(&v, "gateway_key_id", "4.1", "gateway key file")? == id,
        "4.1",
        "gateway_key_id does not match the keys",
    )?;
    let slh = SlhKey::<Sha2_128f>::try_from(slh_pk.as_slice())
        .or_else(|_| fail("4.1", "malformed SLH-DSA key"))?;
    Ok(GatewayKeys {
        key_id: id,
        slh,
        ecdsa_point: point,
    })
}

// ------------------------------------------------------------ journals §2 §3

struct Journal {
    journal_id: String,
    /// heads[n] is the head after n records; heads[0] is genesis.
    heads: Vec<String>,
    bodies: Vec<Value>,
}

fn journal(
    path: &Path,
    section: &'static str,
    format: &str,
    genesis: &[u8],
    record: &[u8],
) -> Result<Journal, Failure> {
    let lines = read_lines(path, section, true)?;
    need(!lines.is_empty(), section, "journal has no header")?;
    let header = json(&lines[0], section, "header")?;
    let jid = get_str(&header, "journal_id", section, "header")?.to_owned();
    need(
        is_uuid(&jid),
        section,
        "header journal_id is not a lowercase UUID",
    )?;
    let expected = format!(
        "{{\"format\":{},\"journal_id\":{}}}",
        jstr(&Value::from(format)),
        jstr(&Value::from(jid.clone()))
    );
    need(
        lines[0] == expected,
        section,
        "header must be exactly {\"format\":…,\"journal_id\":…}",
    )?;
    let mut heads = vec![hex(&sha(&[genesis, lines[0].as_bytes()]))];
    let mut bodies = Vec::new();
    for (i, line) in lines.iter().enumerate().skip(1) {
        let what = format!("record {i}");
        let Some(rest) = line.strip_prefix("{\"body\":") else {
            return fail(section, format!("{what}: line must start with {{\"body\":"));
        };
        let Some(cut) = rest.rfind(",\"sha256\":\"") else {
            return fail(section, format!("{what}: no sha256"));
        };
        let (body_text, tail) = rest.split_at(cut);
        let digest = tail
            .strip_prefix(",\"sha256\":\"")
            .and_then(|t| t.strip_suffix("\"}"))
            .unwrap_or("");
        need(
            is_hex64(digest),
            section,
            format!("{what}: line must end with ,\"sha256\":\"<64 hex>\"}}"),
        )?;
        let body = json(body_text, section, &what)?;
        need(
            get_str(&body, "format", section, &what)? == format,
            section,
            format!("{what}: wrong format"),
        )?;
        need(
            get_u64(&body, "sequence", section, &what)? == i as u64,
            section,
            format!("{what}: sequence is not {i}"),
        )?;
        need(
            get_str(&body, "previous_sha256", section, &what)? == heads[i - 1],
            section,
            format!("{what}: previous_sha256 does not link"),
        )?;
        need(
            hex(&sha(&[record, body_text.as_bytes()])) == digest,
            section,
            format!("{what}: sha256 does not match the body"),
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

fn decision_journal(path: &Path) -> Result<Journal, Failure> {
    let j = journal(
        path,
        "2",
        "circuitbreaker-m2.1",
        b"circuitbreaker.m2.genesis\0",
        b"circuitbreaker.m2.record\0",
    )?;
    for (i, body) in j.bodies.iter().enumerate() {
        let n = i as u64 + 1;
        let what = format!("record {n}");
        let payload = body
            .get("payload")
            .map_or_else(|| fail("2", format!("{what}: no payload")), Ok)?;
        need(
            get_u64(payload, "sequence", "2", &what)? == n,
            "2",
            format!("{what}: payload.sequence is not {n}"),
        )?;
        need(
            get_str(body, "decision_id", "2", &what)? == format!("{}:{n:016x}", j.journal_id),
            "2",
            format!("{what}: decision_id"),
        )?;
    }
    Ok(j)
}

fn control_journal(path: &Path) -> Result<Journal, Failure> {
    journal(
        path,
        "3",
        "circuitbreaker-control.1",
        b"circuitbreaker-control/genesis\0",
        b"circuitbreaker-control/entry\0",
    )
}

fn is_bookkeeping(body: &Value) -> bool {
    let entry = &body["entry"];
    match entry["kind"].as_str() {
        Some("checkpoint") | Some("anchor") => true,
        Some("alarm") => entry["event"] == "checkpoint",
        _ => false,
    }
}

// ---------------------------------------------------------- checkpoints §4

/// Canonical statement bytes (§4.3) from a parsed statement, any key order.
fn statement_bytes(s: &Value, what: &str) -> Result<String, Failure> {
    exact_keys(
        s,
        &[
            "schema_version",
            "gateway_key_id",
            "sequence",
            "reason",
            "decision",
            "control",
            "previous_checkpoint_sha256",
            "wall_time_unix_ms",
        ],
        "4.3",
        what,
    )?;
    let d = &s["decision"];
    let c = &s["control"];
    exact_keys(
        d,
        &["journal_id", "sequence", "head_sha256", "epoch", "state"],
        "4.3",
        what,
    )?;
    exact_keys(c, &["journal_id", "sequence", "head_sha256"], "4.3", what)?;
    let st = |v: &Value, k: &str| get_str(v, k, "4.3", what).map(|x| jstr(&Value::from(x)));
    let int = |v: &Value, k: &str| get_u64(v, k, "4.3", what);
    Ok(format!(
        "{{\"schema_version\":{},\"gateway_key_id\":{},\"sequence\":{},\"reason\":{},\
\"decision\":{{\"journal_id\":{},\"sequence\":{},\"head_sha256\":{},\"epoch\":{},\"state\":{}}},\
\"control\":{{\"journal_id\":{},\"sequence\":{},\"head_sha256\":{}}},\
\"previous_checkpoint_sha256\":{},\"wall_time_unix_ms\":{}}}",
        st(s, "schema_version")?,
        st(s, "gateway_key_id")?,
        int(s, "sequence")?,
        st(s, "reason")?,
        st(d, "journal_id")?,
        int(d, "sequence")?,
        st(d, "head_sha256")?,
        int(d, "epoch")?,
        st(d, "state")?,
        st(c, "journal_id")?,
        int(c, "sequence")?,
        st(c, "head_sha256")?,
        st(s, "previous_checkpoint_sha256")?,
        int(s, "wall_time_unix_ms")?,
    ))
}

/// A checkpoint that passed §4.4.
#[derive(Clone)]
struct Checkpoint {
    statement: Value,
    digest: String,
    ecdsa_sig: Vec<u8>,
}

/// §4.4 checks 1–5 on a signed checkpoint object.
fn check_signed(cp: &Value, keys: &GatewayKeys, what: &str) -> Result<Checkpoint, Failure> {
    exact_keys(
        cp,
        &[
            "statement",
            "statement_sha256",
            "slh_dsa_sha2_128f",
            "ecdsa_p256_sha256",
        ],
        "4.2",
        what,
    )?;
    let s = &cp["statement"];
    let bytes = statement_bytes(s, what)?;
    need(
        get_str(s, "schema_version", "4.4", what)? == "circuitbreaker.checkpoint.v1",
        "4.4",
        format!("{what}: check 1, schema_version"),
    )?;
    need(
        get_str(s, "gateway_key_id", "4.4", what)? == keys.key_id,
        "4.4",
        format!("{what}: check 1, names a different gateway key"),
    )?;
    let digest = get_str(cp, "statement_sha256", "4.4", what)?;
    need(
        hex(&sha(&[bytes.as_bytes()])) == digest,
        "4.4",
        format!("{what}: check 2, statement_sha256 does not match the statement"),
    )?;
    let ecdsa_sig = unhex(get_str(cp, "ecdsa_p256_sha256", "4.4", what)?).unwrap_or_default();
    let ecdsa_ok = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &keys.ecdsa_point)
        .verify(bytes.as_bytes(), &ecdsa_sig)
        .is_ok();
    need(
        ecdsa_ok,
        "4.4",
        format!("{what}: check 3, ECDSA signature does not verify"),
    )?;
    let slh_sig = unhex(get_str(cp, "slh_dsa_sha2_128f", "4.4", what)?).unwrap_or_default();
    let slh_ok = slh_sig.len() == 17088
        && SlhSignature::<Sha2_128f>::try_from(slh_sig.as_slice())
            .ok()
            .is_some_and(|sig| {
                keys.slh
                    .try_verify_with_context(bytes.as_bytes(), SLH_CONTEXT, &sig)
                    .is_ok()
            });
    need(
        slh_ok,
        "4.4",
        format!("{what}: check 4, SLH-DSA signature does not verify"),
    )?;
    Ok(Checkpoint {
        statement: s.clone(),
        digest: digest.to_owned(),
        ecdsa_sig,
    })
}

fn checkpoints(
    path: &Path,
    keys: &GatewayKeys,
    dj: &Journal,
    cj: &Journal,
) -> Result<Vec<Checkpoint>, Failure> {
    let lines = read_lines(path, "4.2", true)?;
    let mut chain: Vec<Checkpoint> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let k = i as u64 + 1;
        let what = format!("checkpoint {k}");
        let v = json(line, "4.2", &what)?;
        let cp = check_signed(&v, keys, &what)?;
        let expected = format!(
            "{{\"statement\":{},\"statement_sha256\":{},\"slh_dsa_sha2_128f\":{},\"ecdsa_p256_sha256\":{}}}",
            statement_bytes(&v["statement"], &what)?,
            jstr(&v["statement_sha256"]),
            jstr(&v["slh_dsa_sha2_128f"]),
            jstr(&v["ecdsa_p256_sha256"])
        );
        need(
            *line == expected,
            "4.2",
            format!("{what}: line is not in canonical form and key order"),
        )?;
        chain.push(cp);
    }
    // §4.5 chain, §4.6 heads
    let mut previous = ZERO64.to_owned();
    for (i, cp) in chain.iter().enumerate() {
        let k = i as u64 + 1;
        let what = format!("checkpoint {k}");
        let s = &cp.statement;
        let (d, c) = (&s["decision"], &s["control"]);
        need(
            s["sequence"].as_u64() == Some(k),
            "4.5",
            format!("{what}: sequence is not {k}"),
        )?;
        need(
            s["previous_checkpoint_sha256"] == previous.as_str(),
            "4.5",
            format!("{what}: previous_checkpoint_sha256 does not link"),
        )?;
        need(
            d["journal_id"] == dj.journal_id.as_str() && c["journal_id"] == cj.journal_id.as_str(),
            "4.5",
            format!("{what}: journal_id differs from the journals"),
        )?;
        if i > 0 {
            let p = &chain[i - 1].statement;
            need(
                d["sequence"].as_u64() >= p["decision"]["sequence"].as_u64()
                    && c["sequence"].as_u64() >= p["control"]["sequence"].as_u64(),
                "4.5",
                format!("{what}: a journal sequence goes backwards"),
            )?;
        }
        previous = cp.digest.clone();
    }
    for (i, cp) in chain.iter().enumerate() {
        let what = format!("checkpoint {}", i + 1);
        let (d, c) = (&cp.statement["decision"], &cp.statement["control"]);
        let at = |j: &Journal, v: &Value| {
            v["sequence"]
                .as_u64()
                .and_then(|n| j.heads.get(n as usize))
                .is_some_and(|h| v["head_sha256"] == h.as_str())
        };
        need(
            at(dj, d),
            "4.6",
            format!("{what}: decision head is not in the decision journal"),
        )?;
        need(
            at(cj, c),
            "4.6",
            format!("{what}: control head is not in the control journal"),
        )?;
    }
    Ok(chain)
}

// ------------------------------------------------------------- anchors §6

/// The Rekor log's public key (ECDSA P-256 SPKI).
pub struct LogKey {
    spki: Vec<u8>,
    point: Vec<u8>,
}

fn pem_spki(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN PUBLIC KEY-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END PUBLIC KEY-----"))
        .collect();
    B64.decode(body.trim()).ok()
}

pub fn load_log_key(path: &Path) -> Result<LogKey, Failure> {
    let pem = fs::read_to_string(path)
        .or_else(|e| fail("6", format!("cannot read {}: {e}", path.display())))?;
    let spki = pem_spki(&pem).map_or_else(|| fail("6", "log key is not a PEM PUBLIC KEY"), Ok)?;
    let prefix = unhex(P256_SPKI_PREFIX).unwrap_or_default();
    need(
        spki.len() == 91 && spki.starts_with(&prefix),
        "6",
        "log key is not ECDSA P-256",
    )?;
    Ok(LogKey {
        point: spki[26..].to_vec(),
        spki,
    })
}

fn ecdsa_ok(point: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
        .verify(msg, sig)
        .is_ok()
}

fn inclusion(index: u64, size: u64, leaf: [u8; 32], proof: &[[u8; 32]], root: &[u8]) -> bool {
    if index >= size {
        return false;
    }
    let (mut fnode, mut snode, mut r) = (index, size - 1, leaf);
    for p in proof {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = sha(&[&[1], p, &r]);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = sha(&[&[1], &r, p]);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && r.as_slice() == root
}

/// §6 checks 1–7 for one anchor against the checkpoint it names.
fn check_anchor(
    a: &Value,
    cp: &Checkpoint,
    keys: &GatewayKeys,
    log: &LogKey,
    what: &str,
) -> Result<(), Failure> {
    need(
        a["schema_version"] == "circuitbreaker.rekor-anchor.v1",
        "6",
        format!("{what}: schema_version"),
    )?;
    need(
        a["statement_sha256"] == cp.digest.as_str(),
        "6",
        format!("{what}: check 7, names a different checkpoint"),
    )?;
    let e = &a["entry"];
    let log_id = hex(&sha(&[&log.spki]));
    need(
        e["logID"] == log_id.as_str(),
        "6",
        format!("{what}: check 1, logID is not this log's"),
    )?;
    let body_b64 = get_str(e, "body", "6", what)?;
    let payload = format!(
        "{{\"body\":{},\"integratedTime\":{},\"logID\":{},\"logIndex\":{}}}",
        jstr(&e["body"]),
        get_u64(e, "integratedTime", "6", what)?,
        jstr(&e["logID"]),
        get_u64(e, "logIndex", "6", what)?
    );
    let set = B64
        .decode(get_str(
            &e["verification"],
            "signedEntryTimestamp",
            "6",
            what,
        )?)
        .unwrap_or_default();
    need(
        ecdsa_ok(&log.point, payload.as_bytes(), &set),
        "6",
        format!("{what}: check 2, signed entry timestamp does not verify"),
    )?;
    let body = B64
        .decode(body_b64)
        .or_else(|_| fail("6", format!("{what}: body is not base64")))?;
    let leaf = sha(&[&[0], &body]);
    let uuid = get_str(a, "uuid", "6", what)?;
    need(
        matches!(uuid.len(), 64 | 80) && unhex(uuid).is_some() && uuid.ends_with(&hex(&leaf)),
        "6",
        format!("{what}: check 3, uuid does not end with the leaf hash"),
    )?;
    let p = &e["verification"]["inclusionProof"];
    let hashes: Option<Vec<[u8; 32]>> = p["hashes"].as_array().map(|hs| {
        hs.iter()
            .filter_map(|h| {
                h.as_str()
                    .and_then(unhex)
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
            })
            .collect()
    });
    let hashes = hashes.unwrap_or_default();
    let root = unhex(get_str(p, "rootHash", "6", what)?).unwrap_or_default();
    let size = get_u64(p, "treeSize", "6", what)?;
    need(
        hashes.len() == p["hashes"].as_array().map_or(0, Vec::len)
            && inclusion(
                get_u64(p, "logIndex", "6", what)?,
                size,
                leaf,
                &hashes,
                &root,
            ),
        "6",
        format!("{what}: check 4, inclusion proof does not reach rootHash"),
    )?;
    let note = get_str(p, "checkpoint", "6", what)?;
    let split = note.rfind("\n\n").map_or_else(
        || fail("6", format!("{what}: check 5, malformed signed tree head")),
        Ok,
    )?;
    let (text, sigs) = (&note[..split + 1], &note[split + 2..]);
    let mut tl = text.lines();
    let _origin = tl.next();
    let note_size = tl.next().and_then(|n| n.parse::<u64>().ok());
    let note_root = tl.next().and_then(|r| B64.decode(r).ok());
    need(
        note_size == Some(size) && note_root.as_deref() == Some(root.as_slice()),
        "6",
        format!("{what}: check 5, tree head size/root differ from the proof"),
    )?;
    let hint = unhex(&log_id).unwrap_or_default()[..4].to_vec();
    let signed = sigs.lines().any(|l| {
        l.strip_prefix("\u{2014} ")
            .and_then(|r| r.rsplit_once(' '))
            .and_then(|(_, b)| B64.decode(b).ok())
            .is_some_and(|raw| {
                raw.len() > 4
                    && raw[..4] == hint[..]
                    && ecdsa_ok(&log.point, text.as_bytes(), &raw[4..])
            })
    });
    need(
        signed,
        "6",
        format!("{what}: check 5, tree head is not signed by the log key"),
    )?;
    let b: Value = serde_json::from_slice(&body)
        .or_else(|_| fail("6", format!("{what}: check 6, body is not JSON")))?;
    let bound = b["apiVersion"] == "0.0.1"
        && b["kind"] == "hashedrekord"
        && b["spec"]["data"]["hash"]["algorithm"] == "sha256"
        && b["spec"]["data"]["hash"]["value"] == cp.digest.as_str()
        && b["spec"]["signature"]["content"]
            .as_str()
            .and_then(|s| B64.decode(s).ok())
            == Some(cp.ecdsa_sig.clone())
        && b["spec"]["signature"]["publicKey"]["content"]
            .as_str()
            .and_then(|s| B64.decode(s).ok())
            .and_then(|pem| String::from_utf8(pem).ok())
            .and_then(|pem| pem_spki(&pem))
            .is_some_and(|spki| {
                hex(&spki) == format!("{P256_SPKI_PREFIX}{}", hex(&keys.ecdsa_point))
            });
    need(
        bound,
        "6",
        format!("{what}: check 6, logged entry does not bind this checkpoint"),
    )
}

// --------------------------------------------------------------- verdict

pub struct Options<'a> {
    pub bundle: &'a Path,
    pub trusted_keys: &'a Path,
    pub trusted_log_key: Option<&'a Path>,
    pub receipts: Option<&'a Path>,
}

#[derive(Debug, Default)]
pub struct Summary {
    pub key_id: String,
    pub decision_records: usize,
    pub control_records: usize,
    pub checkpoints: usize,
    pub anchors: usize,
    pub receipts_checked: usize,
    pub sealed: bool,
    pub trips: usize,
    /// "trusted", "bundle copy", or "none".
    pub log_key: &'static str,
}

pub fn verify(o: &Options) -> Result<Summary, Failure> {
    // §1, §4.1
    let keys = load_gateway_keys(o.trusted_keys)?;
    let bundle_keys = load_gateway_keys(&o.bundle.join("gateway-keys.pub.json"))?;
    need(
        bundle_keys.key_id == keys.key_id,
        "1",
        "bundle is signed by a different gateway key than the trusted one",
    )?;
    // §2, §3
    let dj = decision_journal(&o.bundle.join("decision.jsonl"))?;
    let cj = control_journal(&o.bundle.join("control.jsonl"))?;
    // §4
    let chain = checkpoints(&o.bundle.join("checkpoints.jsonl"), &keys, &dj, &cj)?;
    // §6
    let anchors_path = o.bundle.join("rekor-anchors.jsonl");
    let anchored_records: Vec<(u64, u64)> = cj
        .bodies
        .iter()
        .filter(|b| b["entry"]["kind"] == "anchor" && b["entry"]["outcome"] == "anchored")
        .map(|b| {
            (
                b["entry"]["checkpoint_sequence"].as_u64().unwrap_or(0),
                b["entry"]["log_index"].as_u64().unwrap_or(u64::MAX),
            )
        })
        .collect();
    let bundle_log = o.bundle.join("rekor-log.pub.pem");
    let (log, log_label) = match o.trusted_log_key {
        Some(p) => {
            let trusted = load_log_key(p)?;
            if bundle_log.exists() {
                need(
                    load_log_key(&bundle_log)?.spki == trusted.spki,
                    "6",
                    "bundle's anchors are from a different log key",
                )?;
            }
            (Some(trusted), "trusted")
        }
        None if bundle_log.exists() => (Some(load_log_key(&bundle_log)?), "bundle copy"),
        None => (None, "none"),
    };
    let mut anchors = 0;
    if anchors_path.exists() {
        let log = log
            .as_ref()
            .map_or_else(|| fail("6", "anchors present but no log key"), Ok)?;
        let lines = read_lines(&anchors_path, "6", false)?;
        let mut last = 0;
        let mut url: Option<String> = None;
        let mut seen = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let what = format!("anchor line {}", i + 1);
            let a = json(line, "6", &what)?;
            let n = get_u64(&a, "checkpoint_sequence", "6", &what)?;
            need(
                n > last,
                "6",
                format!("{what}: check 7, not in strictly increasing order"),
            )?;
            let u = get_str(&a, "log_url", "6", &what)?.to_owned();
            need(
                url.as_ref().is_none_or(|x| *x == u),
                "6",
                format!("{what}: check 7, a second log_url"),
            )?;
            let cp = chain.get(n as usize - 1).map_or_else(
                || {
                    fail(
                        "6",
                        format!(
                            "{what}: check 7, names checkpoint {n}, which is not in the bundle"
                        ),
                    )
                },
                Ok,
            )?;
            check_anchor(&a, cp, &keys, log, &what)?;
            seen.push((n, a["entry"]["logIndex"].as_u64().unwrap_or(0)));
            last = n;
            url = Some(u);
        }
        anchors = lines.len();
        for (n, idx) in &anchored_records {
            need(
                seen.contains(&(*n, *idx)),
                "6",
                format!("check 8, anchored checkpoint {n} is missing from the anchors file"),
            )?;
        }
    } else {
        need(
            anchored_records.is_empty(),
            "6",
            "check 8, the control journal records anchors but the bundle has no anchors file",
        )?;
    }
    // §5
    let mut receipts_checked = 0;
    if let Some(path) = o.receipts {
        for (i, line) in read_lines(path, "5", false)?.iter().enumerate() {
            let what = format!("receipt line {}", i + 1);
            let v = json(line, "5", &what)?;
            let (seq, digest, anchor) = if v["schema_version"] == "circuitbreaker.alarm.v1" {
                if v["event"] != "checkpoint" {
                    continue;
                }
                let cp = check_signed(&v["checkpoint"], &keys, &what)?;
                (
                    cp.statement["sequence"].as_u64().unwrap_or(0),
                    cp.digest,
                    None,
                )
            } else if v["schema_version"] == "circuitbreaker.rekor-anchor.v1" {
                (
                    get_u64(&v, "checkpoint_sequence", "5", &what)?,
                    get_str(&v, "statement_sha256", "5", &what)?.to_owned(),
                    Some(v.clone()),
                )
            } else {
                let cp = check_signed(&v, &keys, &what)?;
                (
                    cp.statement["sequence"].as_u64().unwrap_or(0),
                    cp.digest,
                    None,
                )
            };
            let bundled = (seq >= 1).then(|| chain.get(seq as usize - 1)).flatten();
            let bundled = bundled.map_or_else(
                || {
                    fail(
                        "5",
                        format!(
                            "{what}: check 2, received checkpoint {seq} is missing from the bundle"
                        ),
                    )
                },
                Ok,
            )?;
            need(
                bundled.digest == digest,
                "5",
                format!("{what}: check 3, received checkpoint {seq} conflicts with the bundle"),
            )?;
            if let Some(a) = anchor {
                let log = log.as_ref().map_or_else(
                    || fail("5", format!("{what}: anchor receipts need a log key")),
                    Ok,
                )?;
                check_anchor(&a, bundled, &keys, log, &what)?;
            }
            receipts_checked += 1;
        }
    }
    // §4.7
    let sealed = chain.last().is_some_and(|last| {
        let s = &last.statement;
        s["decision"]["sequence"].as_u64() == Some(dj.bodies.len() as u64)
            && cj
                .bodies
                .iter()
                .skip(s["control"]["sequence"].as_u64().unwrap_or(u64::MAX) as usize)
                .all(is_bookkeeping)
    });
    Ok(Summary {
        key_id: keys.key_id,
        decision_records: dj.bodies.len(),
        control_records: cj.bodies.len(),
        checkpoints: chain.len(),
        anchors,
        receipts_checked,
        sealed,
        trips: cj
            .bodies
            .iter()
            .filter(|b| b["entry"]["kind"] == "tripped")
            .count(),
        log_key: log_label,
    })
}
