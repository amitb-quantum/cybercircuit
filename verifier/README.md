# cybercircuit-verify

An independent verifier for CircuitBreaker evidence bundles, format version 1 ([spec](../spec/evidence-bundle-format-v1.md), revision 1.1). Licensed Apache-2.0.

It was written from the published spec, not from the gateway's code, and it can only check evidence: it holds no signing keys and cannot produce a bundle.

```
cybercircuit-verify BUNDLE_DIR --keys GATEWAY_KEYS [--log-key REKOR_PEM] [--receipts FILE]
```

- `--keys`: the gateway's `gateway-keys.pub.json`, obtained separately from the bundle (from its operator, a repository, or a website you trust).
- `--log-key`: the Rekor log's public key, if the bundle has anchors. Without it, the bundle's own copy is used and the output says so.
- `--receipts`: checkpoints held outside the gateway's machine, such as an alarm receiver's log or a copy of the anchors file.

Prints `RESULT: VALID`, or `RESULT: INVALID` with the first failing check and its spec section. Exit status 0 valid, 1 invalid, 2 usage error.

Checks: journal hash chains (§2, §3); both checkpoint signatures, SLH-DSA-SHA2-128f (FIPS 205) and ECDSA P-256 (§4.4); the checkpoint chain and that each checkpoint's heads are in the journals (§4.5, §4.6); Rekor anchors, offline (§6); receipts (§5).

Dependencies: `sha2`, `ring` (ECDSA verification), `slh-dsa` (RustCrypto, verification only), `serde_json`, `base64`. The SLH-DSA crate is a pre-release that has not been independently audited. For a second opinion, [`python/spec_check.py`](../python/spec_check.py) uses an unrelated Python SLH-DSA implementation.

Tests: `tests/challenge.rs` checks the four bundles of evidence challenge 1 against the published answer key, plus targeted tampering (wrong trusted key, edited record, truncated journal, missing anchors file, changed log time, non-canonical checkpoint line).
