#!/usr/bin/env python3
"""A second verifier, written from spec/evidence-bundle-format-v1.md only.

It exists to test the spec: if it and the Rust verifier disagree on a bundle,
the spec is incomplete or wrong. Needs `cryptography` and `slh-dsa`
(pip install cryptography slh-dsa).

Usage: spec_check.py BUNDLE_DIR TRUSTED_KEYS TRUSTED_LOG_PEM [RECEIPTS]
Prints VALID, or INVALID with the first failed check.
"""
import base64, hashlib, json, sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from slhdsa import PublicKey as SlhPublicKey, sha2_128f


class Invalid(Exception):
    pass


def need(cond, why):
    if not cond:
        raise Invalid(why)


def H(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def lines(path):
    data = open(path, "rb").read()
    need(data.endswith(b"\n") or data == b"", f"{path}: last line not terminated")
    out = data.split(b"\n")[:-1]
    need(all(out), f"{path}: blank line")
    return out


def journal(path, header_format, genesis_domain, record_domain, record_checks):
    ls = lines(path)
    need(ls, f"{path}: empty")
    header = json.loads(ls[0])
    need(list(header) == ["format", "journal_id"] and header["format"] == header_format, f"{path}: bad header")
    heads = [H(genesis_domain, ls[0]).hex()]
    records = []
    for n, line in enumerate(ls[1:], start=1):
        need(line.startswith(b'{"body":'), f"{path}: record {n} shape")
        cut = line.rindex(b',"sha256":"')
        need(line[cut:].endswith(b'"}') and len(line) - cut == len(',"sha256":"') + 64 + 2, f"{path}: record {n} shape")
        body_bytes = line[len(b'{"body":'):cut]
        rec = json.loads(line)
        body = rec["body"]
        need(body["format"] == header_format and body["sequence"] == n, f"{path}: record {n} sequence/format")
        need(body["previous_sha256"] == heads[-1], f"{path}: record {n} previous_sha256")
        need(rec["sha256"] == H(record_domain, body_bytes).hex(), f"{path}: record {n} hash")
        record_checks(n, header, body)
        heads.append(rec["sha256"])
        records.append(body)
    return header, heads, records


def decision_checks(n, header, body):
    need(body["payload"]["sequence"] == n, f"decision record {n} payload sequence")
    need(body["decision_id"] == f"{header['journal_id']}:{n:016x}", f"decision record {n} decision_id")


STATEMENT_ORDER = ["schema_version", "gateway_key_id", "sequence", "reason", "decision", "control",
                   "previous_checkpoint_sha256", "wall_time_unix_ms"]
DECISION_ORDER = ["journal_id", "sequence", "head_sha256", "epoch", "state"]
CONTROL_ORDER = ["journal_id", "sequence", "head_sha256"]


def statement_bytes(s):
    need(set(s) == set(STATEMENT_ORDER), "statement fields")
    ordered = {k: s[k] for k in STATEMENT_ORDER}
    need(set(s["decision"]) == set(DECISION_ORDER) and set(s["control"]) == set(CONTROL_ORDER), "statement head fields")
    ordered["decision"] = {k: s["decision"][k] for k in DECISION_ORDER}
    ordered["control"] = {k: s["control"][k] for k in CONTROL_ORDER}
    return json.dumps(ordered, separators=(",", ":")).encode()


def load_keys(path):
    k = json.load(open(path))
    slh = bytes.fromhex(k["slh_dsa_sha2_128f"])
    pt = bytes.fromhex(k["ecdsa_p256"])
    need(len(slh) == 32 and len(pt) == 65 and pt[0] == 4, "key sizes")
    kid = H(b"circuitbreaker-gateway-keys-v1\0", (32).to_bytes(4, "big"), slh, pt).hex()
    need(kid == k["gateway_key_id"], "gateway_key_id does not match the keys")
    return {"id": kid, "slh": SlhPublicKey.from_digest(slh, sha2_128f),
            "ecdsa": ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pt), "point": pt}


def check_signed(cp, keys, where):
    s = cp["statement"]
    sb = statement_bytes(s)
    need(s["schema_version"] == "circuitbreaker.checkpoint.v1", f"{where}: schema")
    need(s["gateway_key_id"] == keys["id"], f"{where}: names a different gateway key")
    need(cp["statement_sha256"] == hashlib.sha256(sb).hexdigest(), f"{where}: statement_sha256")
    try:
        keys["ecdsa"].verify(bytes.fromhex(cp["ecdsa_p256_sha256"]), sb, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Invalid(f"{where}: ECDSA signature does not verify")
    sig = bytes.fromhex(cp["slh_dsa_sha2_128f"])
    need(len(sig) == 17088, f"{where}: SLH-DSA signature length")
    need(keys["slh"].verify_pure(sb, sig, b"circuitbreaker-checkpoint-v1"), f"{where}: SLH-DSA signature does not verify")
    return sb


def verify_log_key(pem):
    key = serialization.load_pem_public_key(pem)
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, spki


def ecdsa_ok(key, sig, msg):
    try:
        key.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def inclusion(index, size, leaf, proof, root):
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = H(b"\x01", p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = H(b"\x01", r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def check_anchor(a, cp, keys, log_key, log_spki, where):
    need(a["schema_version"] == "circuitbreaker.rekor-anchor.v1", f"{where}: schema")
    need(a["checkpoint_sequence"] == cp["statement"]["sequence"] and a["statement_sha256"] == cp["statement_sha256"],
         f"{where}: names a different checkpoint")
    e = a["entry"]
    log_id = hashlib.sha256(log_spki).hexdigest()
    need(e["logID"] == log_id, f"{where}: logID")
    payload = '{"body":"%s","integratedTime":%d,"logID":"%s","logIndex":%d}' % (e["body"], e["integratedTime"], e["logID"], e["logIndex"])
    need(ecdsa_ok(log_key, base64.b64decode(e["verification"]["signedEntryTimestamp"]), payload.encode()), f"{where}: SET")
    body = base64.b64decode(e["body"])
    leaf = H(b"\x00", body)
    need(len(a["uuid"]) in (64, 80) and a["uuid"].endswith(leaf.hex()), f"{where}: uuid")
    p = e["verification"]["inclusionProof"]
    need(inclusion(p["logIndex"], p["treeSize"], leaf, [bytes.fromhex(h) for h in p["hashes"]], bytes.fromhex(p["rootHash"])),
         f"{where}: inclusion proof")
    note = p["checkpoint"]
    split = note.rindex("\n\n")
    text, sigs = note[:split + 1], note[split + 2:]
    origin, size, root = text.split("\n")[:3]
    need(int(size) == p["treeSize"] and base64.b64decode(root).hex() == p["rootHash"], f"{where}: tree head size/root")
    hint = bytes.fromhex(log_id)[:4]
    signed = False
    for line in sigs.strip("\n").split("\n"):
        if line.startswith("— "):
            raw = base64.b64decode(line.rsplit(" ", 1)[1])
            signed |= raw[:4] == hint and ecdsa_ok(log_key, raw[4:], text.encode())
    need(signed, f"{where}: tree head signature")
    b = json.loads(body)
    need(b.get("apiVersion") == "0.0.1" and b.get("kind") == "hashedrekord", f"{where}: body kind")
    need(b["spec"]["data"]["hash"] == {"algorithm": "sha256", "value": cp["statement_sha256"]}, f"{where}: body digest")
    need(base64.b64decode(b["spec"]["signature"]["content"]) == bytes.fromhex(cp["ecdsa_p256_sha256"]), f"{where}: body signature")
    pem = base64.b64decode(b["spec"]["signature"]["publicKey"]["content"])
    spki = serialization.load_pem_public_key(pem).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    need(spki == bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + keys["point"], f"{where}: body key")


def main(bundle, trusted_keys, trusted_log, receipts=None):
    keys = load_keys(trusted_keys)
    need(load_keys(f"{bundle}/gateway-keys.pub.json")["id"] == keys["id"], "bundle signed by a different gateway key")
    dh, dheads, drecs = journal(f"{bundle}/decision.jsonl", "circuitbreaker-m2.1",
                                b"circuitbreaker.m2.genesis\0", b"circuitbreaker.m2.record\0", decision_checks)
    ch, cheads, crecs = journal(f"{bundle}/control.jsonl", "circuitbreaker-control.1",
                                b"circuitbreaker-control/genesis\0", b"circuitbreaker-control/entry\0", lambda *a: None)
    chain = []
    prev = "0" * 64
    for k, line in enumerate(lines(f"{bundle}/checkpoints.jsonl"), start=1):
        cp = json.loads(line)
        need(list(cp) == ["statement", "statement_sha256", "slh_dsa_sha2_128f", "ecdsa_p256_sha256"], f"checkpoint {k}: line keys")
        sb = check_signed(cp, keys, f"checkpoint {k}")
        need(line[len(b'{"statement":'):len(b'{"statement":') + len(sb)] == sb, f"checkpoint {k}: statement not canonical")
        s = cp["statement"]
        need(s["sequence"] == k and s["previous_checkpoint_sha256"] == prev, f"checkpoint {k}: chain")
        need(s["decision"]["journal_id"] == dh["journal_id"] and s["control"]["journal_id"] == ch["journal_id"], f"checkpoint {k}: journal ids")
        if chain:
            p = chain[-1]["statement"]
            need(s["decision"]["sequence"] >= p["decision"]["sequence"] and s["control"]["sequence"] >= p["control"]["sequence"], f"checkpoint {k}: goes backwards")
        need(s["decision"]["sequence"] < len(dheads) and dheads[s["decision"]["sequence"]] == s["decision"]["head_sha256"],
             f"checkpoint {k}: decision head not in the journal")
        need(s["control"]["sequence"] < len(cheads) and cheads[s["control"]["sequence"]] == s["control"]["head_sha256"],
             f"checkpoint {k}: control head not in the journal")
        prev = cp["statement_sha256"]
        chain.append(cp)

    log_key, log_spki = verify_log_key(open(trusted_log, "rb").read())
    try:
        anchors = [json.loads(l) for l in lines(f"{bundle}/rekor-anchors.jsonl")]
    except FileNotFoundError:
        anchors = []
    if anchors:
        _, bundle_spki = verify_log_key(open(f"{bundle}/rekor-log.pub.pem", "rb").read())
        need(bundle_spki == log_spki, "bundle's anchors are from a different log key")
    last = 0
    for a in anchors:
        n = a["checkpoint_sequence"]
        need(n > last and 1 <= n <= len(chain), f"anchor {n}: order or missing checkpoint")
        check_anchor(a, chain[n - 1], keys, log_key, log_spki, f"anchor {n}")
        last = n
    for c in crecs:
        e = c["entry"]
        if e["kind"] == "anchor" and e["outcome"] == "anchored":
            need(any(a["checkpoint_sequence"] == e["checkpoint_sequence"] and a["entry"]["logIndex"] == e["log_index"] for a in anchors),
                 f"anchored checkpoint {e['checkpoint_sequence']} missing from the anchors file")

    checked = 0
    if receipts:
        for i, line in enumerate(lines(receipts), start=1):
            v = json.loads(line)
            if v.get("schema_version") == "circuitbreaker.alarm.v1":
                if v.get("event") != "checkpoint":
                    continue
                cp, anchor = v["checkpoint"], None
            elif v.get("schema_version") == "circuitbreaker.rekor-anchor.v1":
                cp, anchor = None, v
            else:
                cp, anchor = v, None
            seq = cp["statement"]["sequence"] if cp else anchor["checkpoint_sequence"]
            digest = cp["statement_sha256"] if cp else anchor["statement_sha256"]
            if cp:
                check_signed(cp, keys, f"receipt line {i}")
            need(1 <= seq <= len(chain), f"receipt line {i}: received checkpoint {seq} is missing from the bundle")
            need(chain[seq - 1]["statement_sha256"] == digest, f"receipt line {i}: received checkpoint {seq} conflicts with the bundle")
            if anchor:
                check_anchor(anchor, chain[seq - 1], keys, log_key, log_spki, f"receipt line {i}")
            checked += 1

    last = chain[-1]["statement"] if chain else None
    sealed = bool(last) and last["decision"]["sequence"] == len(drecs) and all(
        c["entry"]["kind"] in ("checkpoint", "anchor") or (c["entry"]["kind"] == "alarm" and c["entry"]["event"] == "checkpoint")
        for c in crecs[last["control"]["sequence"]:])
    return {"checkpoints": len(chain), "anchors": len(anchors), "receipts_checked": checked, "sealed": sealed,
            "tripped": sum(c["entry"]["kind"] == "tripped" for c in crecs)}


if __name__ == "__main__":
    try:
        print("VALID", json.dumps(main(*sys.argv[1:])))
    except Invalid as e:
        print("INVALID:", e)
        sys.exit(1)
