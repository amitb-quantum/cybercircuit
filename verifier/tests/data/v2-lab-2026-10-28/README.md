# Format v2 lab bundles (producer interoperability)

Nine evidence bundles exported by the private CircuitBreaker gateway at commit `fecd284` in synthetic lab runs on 2026-10-28. They use synthetic model credentials and lab-only signing keys; only the public keys are included. `tests/v2_lab.rs` checks that this independent verifier reaches the producer's own verdicts:

- **VALID, sealed and complete, with all receipts:** `connect-trip`, `proxy-trip`, `endpoint-optin-trip`, `endpoint-misses-50`, `evidence-failure-null-link`, `f1-artifacts` and `explicit-hardening-demo`.
- **`pre-go-artifact-append-failure`:** VALID but incomplete. The admission was recorded, then the artifact admission could not be, so GO was refused.
- **`terminal-missing-trip`:** a whole-record prefix of a real CONNECT run, cut after the violation event. On its own it is VALID-but-incomplete ("trip record missing"). With the source run's receipts it is INVALID, because the received checkpoints are missing.
