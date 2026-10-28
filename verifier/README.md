# cybercircuit-verify

An independent verifier for CircuitBreaker evidence bundles, format version 1 ([spec](../spec/evidence-bundle-format-v1.md), revision 1.1) and format version 2 (contract v0.3; the published v2 spec is pending). Licensed Apache-2.0.

It was written from the published spec, not from the gateway's code, and it can only check evidence: it holds no signing keys and cannot produce a bundle.

```
cybercircuit-verify BUNDLE_DIR --keys GATEWAY_KEYS [--log-key REKOR_PEM] [--receipts FILE]
```

- `--keys`: the gateway's `gateway-keys.pub.json`, obtained separately from the bundle (from its operator, a repository, or a website you trust).
- `--log-key`: the Rekor log's public key, if the bundle has anchors. Without it, the bundle's own copy is used and the output says so.
- `--receipts`: checkpoints held outside the gateway's machine, such as an alarm receiver's log or a copy of the anchors file.

Prints `RESULT: VALID`, or `RESULT: INVALID` with the first failing check and its spec section, followed by `STAGE: <1-7>; REASON: <code>` (`invalid`, `unsupported_format`, `format_mismatch` or `resource_limit`). Exit status: 0 only for VALID; 1 for anything else, including an unsupported format or an unreadable file; 2 only for a usage error.

For a v2 bundle it also prints the hardening profile, observed traffic and violation totals (lower bounds), kill and reset outcomes, admissions and releases, whether the security counts are complete, and every reason they are not.

Checks: journal hash chains (§2, §3); both checkpoint signatures, SLH-DSA-SHA2-128f (FIPS 205) and ECDSA P-256 (§4.4); the checkpoint chain and that each checkpoint's heads are in the journals (§4.5, §4.6); Rekor anchors, offline (§6); receipts (§5).

Dependencies: `sha2`, `ring` (ECDSA verification), `slh-dsa` (RustCrypto, verification only), `serde_json`, `base64`. The SLH-DSA crate is a pre-release that has not been independently audited. For a second opinion, [`python/spec_check.py`](../python/spec_check.py) uses an unrelated Python SLH-DSA implementation.

Format v2 adds: the authenticated `bundle.json` manifest and its profile rules; the v2 control chain and exact canonical bytes of every record; the artifact manifest; launch admissions, gateway-observed violations, tripwire presentations, repeat windows and releases, and their bindings to model-use records, decision-journal restrictions and trips; and §9 totals. v1 bundles are checked exactly as before.

Tests: `tests/v2.rs` builds signed synthetic v2 bundles and checks 48 valid and invalid cases from the contract, including its Appendix A hash vector. With `CC_V2_FIXTURES=DIR` the suite keeps every bundle with its expected verdict, for comparison with other implementations. `tests/challenge.rs` checks the four bundles of evidence challenge 1 against the published answer key, plus targeted tampering (wrong trusted key, edited record, truncated journal, missing anchors file, changed log time, non-canonical checkpoint line).
