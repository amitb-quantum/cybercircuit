# cybercircuit

Public verification material for **CircuitBreaker**, the agent guardrail behind [cybercircuit.ai](https://cybercircuit.ai).

CircuitBreaker sits between an AI agent and its tools. When the agent crosses a limit, it trips: the agent's process is killed, the agent stays stopped until a person resets it, and every decision is written to signed, hash-chained journals. Those journals are exported as an **evidence bundle**.

This repository is for checking a bundle without having to trust us. It holds the bundle format and two verifiers written from that format.

## What is here

| Path | What it is | Licence |
| --- | --- | --- |
| [`spec/evidence-bundle-format-v1.md`](spec/evidence-bundle-format-v1.md) | The evidence bundle format, version 1, revision 1.1: every file, byte layout, signature and check | Apache-2.0 |
| [`verifier/`](verifier/) | `cybercircuit-verify`, a Rust verifier written from the spec | Apache-2.0 |
| [`python/spec_check.py`](python/spec_check.py) | A second verifier in Python, with a different SLH-DSA implementation, used to test the spec | Apache-2.0 |
| [`verifier/tests/data/challenge-1/`](verifier/tests/data/challenge-1/) | The four bundles of [evidence challenge 1](https://cybercircuit.ai/challenge-1/), its receipts and keys | Apache-2.0 |
| [`tools/agree.sh`](tools/agree.sh) | Runs both verifiers on every challenge case; CI fails if they disagree with each other or with the answer key | Apache-2.0 |
| [`allowed_signers`](allowed_signers) | The public key that signs gateway builds | |

## What is not here

The gateway, the breaker, the sandbox launcher, the model relay, and the checkpoint signer and Rekor anchor client are closed source. Nothing in this repository can produce evidence, make an enforcement decision or build a sandbox. It can only check a bundle someone else produced.

The gateway itself is not published here; signed builds go to design partners (see below).

## Getting the gateway

The gateway is not publicly downloadable. Signed Linux x86_64 builds go to design partners on request: write to info@quantum-clarity.com. Each build comes with a quickstart, and with this repository's verifier as a static binary.

### Release signing key

Every build we send is signed with one Ed25519 key, held offline. Its public half is in [`allowed_signers`](allowed_signers):

```
release@cybercircuit.ai namespaces="cybercircuit-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBFu0A1fDzovoVloCtVVa424IDdQRDILbFqm8WosiOhT
```

Fingerprint: `SHA256:yp+kIpuLgQ9ENakbk0Sm0y3uSf2WYW4NhtaqT+BRcT4`

The same fingerprint is published on [cybercircuit.ai/get.html](https://cybercircuit.ai/get.html). Check that both agree before trusting the key. Verify a build with OpenSSH, which every Linux has:

```bash
ssh-keygen -Y verify -f allowed_signers -I release@cybercircuit.ai -n cybercircuit-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c SHA256SUMS
```

A new key would be announced in both places and signed by this one.

## Verify a bundle

You need Rust 1.98.1 (the toolchain file pins it).

```bash
git clone https://github.com/amitb-quantum/cybercircuit && cd cybercircuit
cargo build --release --locked
D=verifier/tests/data/challenge-1
target/release/cybercircuit-verify $D/bundle-C \
  --keys $D/gateway-keys.pub.json \
  --log-key $D/rekor-log.pub.pem \
  --receipts $D/receipts.jsonl
```

The verifier prints `RESULT: VALID`, or `RESULT: INVALID` with the first failing check and the spec section it comes from. Exit status is 0 for valid, 1 for invalid and 2 for a usage error. A bundle or key file that is missing or unreadable is reported as INVALID (exit 1): the verifier fails closed.

Get the gateway keys, the log key and any receipts from somewhere other than the bundle. The bundle carries its own copies, but a forger can replace those as easily as the journals.

The Python checker needs `pip install -r python/requirements.txt`:

```bash
python3 python/spec_check.py $D/bundle-C $D/gateway-keys.pub.json $D/rekor-log.pub.pem $D/receipts.jsonl
```

## What a VALID result does and does not mean

VALID means the journals are intact, every checkpoint carries a valid SLH-DSA-SHA2-128f and ECDSA P-256 signature from the trusted gateway key, each checkpoint's journal heads are in the journals, the Rekor anchors verify offline against the trusted log key, and every receipt you supplied is in the bundle.

It does not show that the gateway's policy was the right one, or that the machine running the gateway was not compromised before a checkpoint was signed. Receipts and Rekor anchors limit how far back a compromise can rewrite history: whatever left the machine before the compromise cannot be taken back.

The Rust SLH-DSA crate is a pre-release that has not been independently audited. That is one reason the Python checker exists.

## Reporting a problem

If the two verifiers disagree on a bundle, or the spec is ambiguous, please open an issue. A disagreement means the spec is incomplete or one of the verifiers is wrong, and we want to know either way.
