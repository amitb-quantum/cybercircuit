# Public evidence sources

The fixture scripts use the public Cyber-Circuit repository at `6f720a6429341b4c56f4290f80f86769d3eca366`. The SHA-256 lists identify every downloaded input.

The viewer uses the public [bundle format v1](https://github.com/amitb-quantum/cybercircuit/blob/6f720a6429341b4c56f4290f80f86769d3eca366/spec/evidence-bundle-format-v1.md) and [bundle format v2](https://github.com/amitb-quantum/cybercircuit/blob/6f720a6429341b4c56f4290f80f86769d3eca366/spec/evidence-bundle-format-v2.md). The Activity and Trips views show selected fields from the decision and control journals. Evidence displays stored hashes, signed checkpoint statements and receipt matches. Approximate times use covering checkpoint timestamps. Records without a covering timestamp show UNKNOWN.

The recorded public `cybercircuit-verify` output and exit code determine the verdict. An invalid result reports the first failure and its stage. Missing or unrecognised output shows UNKNOWN or NOT VERIFIED. A match in the browser between two stored fields is a display relationship. The verifier establishes cryptographic validity.

The v2 profile comes from `bundle.json` (§3), and admission, release, tripwire and suppression rows come from the control journal (§6). The viewer shows marker IDs only. Security totals and incomplete reasons come from the verifier output (§9–10). Coverage ranges compare recorded checkpoint heads with recorded sequence numbers. A matching receipt is a lookup by sequence and statement digest. The published agent timelines use the session sequence described by the public fixture README and link to the corresponding stored control records.
