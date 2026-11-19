# Increment 3 (host-wide storage registry) conformance bundles

Version 2 bundles at hardening increment 3, exported by the CircuitBreaker gateway during its Phase 3B-3 work in November 2026. No real agents, provider credentials, private signing keys, registry inventories or tripwire values are included.

| Bundle | What it is | This verifier's result |
| --- | --- | --- |
| `valid-admission-release/` | A real synthetic scope captured in a disposable VM: a registry-checked admission, then a confirmed end and a registry release, covered by the shutdown checkpoint | VALID, sealed |
| `unknown-ownership-retained/` | A real synthetic scope whose registry release could not be completed: the release is recorded as `unknown`, with no registry release | VALID, sealed; no release counted as confirmed |
| `released-without-checked-increment1/` | An increment-1 admission with no registry check, followed by a claimed registry release | INVALID, v2 §6.5 |
| `released-without-checked-increment3/` | An increment-3 admission without a registry check | INVALID, v2 §6.1 |
| `security-after-release/` | A security event recorded for an execution after its confirmed end | INVALID, v2 §6.5 |
| `missing-admission/` | A release for an execution that was never admitted | INVALID, v2 §6.5 |
| `header-only-missing-required-files/` | A header-only export after a refused launch, missing `checkpoints.jsonl` and `gateway-keys.pub.json` | INVALID: v2 §3 requires both files |

The two real captures are signed with their own lab keys; use `trusted-keys/unknown-ownership-retained.pub.json` for that bundle and `trusted-keys/valid-admission-release.pub.json` for every other one. The negative cases are isolated chains re-signed with the second key, each breaking one rule; they are not byte edits of a valid bundle.

The last case records a disagreement: the producer's own checker accepted it. With the two required files added (an empty `checkpoints.jsonl` and the gateway's public keys), this verifier reports it VALID and unsealed, as the producer expected. The fix belongs in the producer's export.

```bash
D=verifier/tests/data/3b3-d11-2026-11-19
target/release/cybercircuit-verify $D/valid-admission-release \
  --keys $D/trusted-keys/valid-admission-release.pub.json \
  --receipts $D/valid-admission-release/receipts.jsonl
```

The expected results are asserted by `verifier/tests/increment3.rs`.
