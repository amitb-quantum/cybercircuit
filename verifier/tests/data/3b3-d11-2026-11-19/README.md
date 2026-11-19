# Increment 3 (host-wide storage registry) conformance bundles

Version 2 bundles at hardening increment 3, exported by the CircuitBreaker gateway during its Phase 3B-3 work in November 2026, re-exported after review. No real agents, provider credentials, private signing keys, registry inventories or tripwire values are included.

| Bundle | What it is | This verifier's result |
| --- | --- | --- |
| `valid-admission-release/` | A real synthetic scope: a registry-checked admission, then a confirmed end and a registry release, covered by the shutdown checkpoint | VALID, sealed; 1 registry release |
| `confirmed-end-ownership-retained/` | A real synthetic scope that was confirmed dead, but whose registry entry could not be retired (the release lock was held) | VALID, sealed; confirmed end, 0 registry releases |
| `death-uncertain-ownership-retained/` | A real synthetic scope whose death could not be observed | VALID, sealed; end `unknown`, 0 registry releases |
| `released-without-checked-increment1/` | An increment-1 admission with no registry check, followed by a claimed registry release | INVALID, v2 §6.5 |
| `released-without-checked-increment3/` | An increment-3 admission without a registry check | INVALID, v2 §6.1 |
| `security-after-release/` | A security event recorded for an execution after its confirmed end | INVALID, v2 §6.5 |
| `missing-admission/` | A release for an execution that was never admitted | INVALID, v2 §6.5 |
| `header-only-preflight/` | A header-only export after a refused launch: no records, an empty `checkpoints.jsonl` and the gateway's public keys | VALID, unsealed, incomplete; no admission invented |

Use `trusted-keys/<bundle>.pub.json` for the three real captures, and `trusted-keys/valid-admission-release.pub.json` for every other bundle. The negative cases are isolated chains re-signed with that key, each breaking one rule; they are not byte edits of a valid bundle.

An earlier export of the header-only case omitted `checkpoints.jsonl` and `gateway-keys.pub.json`, which v2 §3 requires; this verifier refused it while the producer's own checker accepted it. The producer's export and checker were fixed, and `verifier/tests/increment3.rs` keeps a test that a bundle missing a required file is refused.

On increment-3 bundles the command-line summary adds a `registry releases: N` line: the number of releases recorded with `registry_released: true`. A release with a confirmed end is not necessarily a registry release.

```bash
D=verifier/tests/data/3b3-d11-2026-11-19
target/release/cybercircuit-verify $D/valid-admission-release \
  --keys $D/trusted-keys/valid-admission-release.pub.json \
  --receipts $D/valid-admission-release/receipts.jsonl
```
