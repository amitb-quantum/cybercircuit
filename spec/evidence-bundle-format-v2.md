# CircuitBreaker evidence bundle format, version 2

**Revision 1.0 (2026-11-08), from wire contract v0.4.** This document is enough to build a v2 verifier from scratch. The verifier in this repository was written from it, without the gateway's code, and agrees with the gateway's own verdicts on the synthetic conformance cases and on bundles from real agent runs (see `verifier/tests/`).

Version 2 is produced by gateways running the incident-hardening profile, increment 1 or later. Increments 2 (tripwires) and 3 (host-wide registry) are fully specified here so that verifiers accept them from the start; a released gateway does not yet produce them.

Version 1 remains valid for runs that started under it. [Version 1, revision 1.1](evidence-bundle-format-v1.md) is a normative dependency of this document.

## 1. Scope, normative inheritance and version selection

This document defines the complete v2 delta, new schemas and checks. [Bundle v1, specification revision 1.1](evidence-bundle-format-v1.md) is a normative dependency: inherit its §2 decision journal, §4 key/checkpoint/signature/chain/head rules, §5 receipts and §6 Rekor rules **unchanged**, except that control heads are computed by this document’s §4. These inherited definitions include canonical checkpoint statement order, SLH-DSA context, ECDSA encoding, gateway key ID, anchor inclusion/signatures and receipt comparison. They are not inferred from a producer implementation. The v1 control entry fields needed by v2 are explicitly specified in §5 below.

- Runs started under the incident-hardening profile use v2 from inception, even with zero violations. Historical v1 files are neither rewritten nor wrapped/re-signed as v2.
- Version selection checks both `bundle.json` and the control header. `bundle.json` present with unknown version, missing required v2 files, or a v2 control header with no manifest is an error; never fall back to v1 after a v2 error.
- A v1-only verifier must fail nonzero on the required `circuitbreaker-control.2` header even if it ignores the new manifest or no new event exists. New verifiers report `unsupported_format` for unsupported discriminators.
- v2 supports all reserved event kinds here from its first wire revision. A producer may not emit a kind outside its enabled increment. Unknown kind/field/version always refuses; adding future semantics requires a reviewed wire revision/version, not silent ignore.
- Cryptographic validity authenticates recorded claims and covered history, not the completeness/truth of host observations or static policy safety. No verifier executes an artifact, agent or host command. No network needed for verification; optional live Rekor comparison remains v1 behavior.

## 2. General encoding, bounds and types

Required JSON/JSONL objects have exactly the specified keys and types; reject duplicate keys at every depth, missing/extra keys, trailing data, blank JSONL lines, BOM, CRLF and missing final LF. Canonical files below are compact ASCII JSON in specified key order plus one final LF. Each JSON string uses standard JSON escaping: quote/backslash escaped, backspace/form-feed/LF/CR/tab as `\b`, `\f`, `\n`, `\r`, `\t`; other U+0000 through U+001F controls as lowercase `\u00xx`; no escaped slash or needless escaping of printable ASCII. New bounded identifiers contain only their stated printable alphabet. Legacy text is ASCII as in v1; encode controls by these rules. U+007F (DEL) is emitted literally as byte 0x7f in text fields that permit it, matching serde_json; this does not admit it into IDs, filenames, HTTP tokens or other closed alphabets. v1-inherited files retain their exact v1 serialization (the key file may be pretty printed; Rekor notes are UTF-8).

JSON-shaped blocks containing `<T>` are schema notation, not literal fixture JSON; Appendix A contains literal data. Types used below:

| Type | Meaning |
| --- | --- |
| `U` | JSON integer 0..2^64−1, plain decimal, no sign/fraction/exponent/leading zero except `0`. Never use floating-point rounding. |
| `P` | `U` ≥1. All arithmetic checked; no wrap. |
| `UID` | Integer 0..2^32−1. |
| `H` | Exactly 64 lowercase hex characters, a SHA-256 value. |
| `UUID` | Lowercase canonical hyphenated UUID, 36 characters; exact spelling participates in hashes. |
| `ID` | 1..128 ASCII letters/digits/dot/underscore/hyphen; neither `.` nor `..`. |
| `AID` | Same alphabet as ID, maximum 64 characters. |
| `TWID` | `tw-01` through `tw-16`; unique IDs, not marker bytes. |
| `Text` | ASCII string, at most 4,096 bytes before JSON escaping, subject to whole-record bound. |
| `DecisionID` | `<decision journal UUID>:` plus 16 lowercase hex digits of a positive decision sequence. |
| `?T` | JSON null or exactly T, never omitted. |

Maximum control header/record: 16,384 bytes **excluding** LF. Maximum `bundle.json`: 16,384 bytes including LF. Maximum artifact manifest: 262,144 bytes including LF. All integers must be checked before size/count conversion. A verifier may apply documented streaming/resource ceilings, but exceeding one must return nonzero `resource_limit`, never VALID or silent truncation. No new arbitrary whole-bundle size assertion is imposed on historical v1.

## 3. Bundle files and authenticated manifest

| File | Required | Contract |
| --- | --- | --- |
| `bundle.json` | yes | Canonical manifest below. |
| `decision.jsonl` | yes | Unchanged v1 §2. |
| `control.jsonl` | yes | v2 §4–§7. |
| `checkpoints.jsonl` | yes | Unchanged v1 §4; control heads use v2 chain. |
| `gateway-keys.pub.json` | yes | Unchanged v1 key schema; independently trusted keys still required. |
| `artifacts.json` | iff manifest artifact digest non-null | Exact frozen artifact manifest, §3.2. No artifact bytes in bundle. |
| `rekor-anchors.jsonl`, `rekor-log.pub.pem` | same conditions as v1 | Unchanged v1 §6. |
| `report.json` | optional | Untrusted summary; verifier recomputes totals, never uses it as evidence. |

Read these as regular files; do not follow a bundle path symlink to unrelated host data. Unrecognized extra ordinary files carry no authority and need not be read. A required known file may not be substituted by an unknown file. Trusted key/log-key/receipt inputs are supplied independently exactly as in v1.

### 3.1 `bundle.json`

Exact key order (line breaks here are explanatory; file is compact):

```json
{"schema_version":"circuitbreaker.bundle.v2","run_id":<ID>,"subject_id":<ID>,"session_id":<ID>,"operator_uid":<UID>,"decision_journal_id":<UUID>,"control_journal_id":<UUID>,"hardening":{"increment":<1|2|3>,"model_mode":<"none"|"anthropic"|"openai"|"gemini">,"gateway_observed":<bool>,"trip_on_model_endpoint_not_allowlisted":<bool>,"package_mode":"pre_staged_ro","artifact_manifest_sha256":<?H>,"tripwires":<bool>,"tripwire_ids":[<TWID>...],"tripwire_catalogue_sha256":<?H>,"registry":<bool>}}
```

Constraints:

- Journal IDs equal the respective file headers and checkpoint bindings. `run_id`/subject/session are frozen host-supplied attribution, not caller claims or authorization. For every decision payload with non-null `subject`, its `id` and `session` must equal manifest `subject_id` and `session_id`; records with null subject do not assert an identity. Manifest fields do not replace kernel/peer identity enforcement.
- `gateway_observed` is true iff model mode is not `none`. CONNECT/proxy trips are mandatory when true. Endpoint-trip opt-in is false by default; true requires the operator’s explicit frozen project choice. If no model ingress it must be false.
- `tripwires` is true iff increment ≥2 **and** model mode is not `none`. If false, IDs are `[]` and catalogue digest is null. If true, 1..16 IDs, sorted by ASCII bytes with no duplicates, plus a non-null digest of the frozen private catalogue. Values/catalogue bytes are **not exported**; verifier authenticates its recorded digest, not its contents or a match it cannot observe.
- `registry` is true iff increment is 3. Package mode is always `pre_staged_ro`; a null artifact digest explicitly means no additional staged artifact set/no `/packages` mount, not a network fallback. A present set satisfies §3.2.
- The manifest is immutable for this run and every resume. A new increment or changed opt-in requires an explicit project/new-run operation under existing fresh/quarantine rules, never editing this history.

Let `M = SHA256(exact complete bundle.json bytes, including its final LF)`. The control header includes lowercase hex(M); therefore a checkpoint covering control head **including C0** authenticates this manifest. A sidecar hash absent from the chain would not suffice. Without a trusted signed checkpoint, the manifest/chain are structurally checked but not authenticated.

### 3.2 `artifacts.json`

```json
{"schema_version":"circuitbreaker.artifact-set.v1","artifacts":[{"id":<AID>,"filename":<filename>,"bytes":<U>,"sha256":<H>}...]}
```

Canonical order as shown; array sorted by ASCII `id`. `filename` is 1..128 ASCII letters/digits/dot/underscore/hyphen, neither `.` nor `..`, no path separators. IDs and filenames individually unique. There are 1..256 entries; each size ≤67,108,864 and checked sum ≤536,870,912. A zero-byte regular artifact is valid; an empty present set is not. Digest in bundle manifest equals SHA256(**entire** artifacts.json including LF). If manifest digest is null, this known file must be absent. Host source paths and file contents are never exported.

Verifier checks the manifest bytes/limits and event binding, **not the unbundled artifact content**. Content digest verification before launch is an attested host operation; a valid bundle does not independently prove what was mounted.

## 4. v2 control chain

Exact canonical header:

```json
{"format":"circuitbreaker-control.2","journal_id":<UUID>,"bundle_manifest_sha256":<H>}
```

`bundle_manifest_sha256 == hex(M)` from §3.1. `header_bytes` excludes LF.

- `C0 = hex(SHA256("circuitbreaker-control-v2/genesis\0" || header_bytes))`.
- For record n≥1, line is `{"body":<BODY>,"sha256":<H>}`.
- Exact BODY order: `{"format":"circuitbreaker-control.2","sequence":<P>,"previous_sha256":<H>,"entry":<ENTRY>}`.
- `sequence == n`, `previous_sha256 == C(n−1)`.
- `Cn = hex(SHA256("circuitbreaker-control-v2/entry\0" || BODY_BYTES))`; `sha256 == Cn`.

`\0` denotes one NUL byte, not two visible backslash/zero bytes. BODY_BYTES are the exact canonical body substring, not a reserialization with different key order. Envelope/header/body/entry must all match canonical encoding. No v1 domain/header reuse. Sequence overflow is invalid. Checkpoint `control.head_sha256` uses Cn or C0 with unchanged v1 checkpoint statement/schema/signature contexts.

Epochs are U (including 0): the existing kernel starts at epoch 0; its first quarantine advances to 1 and a later manual reset to 2. This contract does not change that authority behavior. Positive sequence numbers remain P.

## 5. Legacy event schemas carried into v2

ENTRY has `kind` first, then **exactly** the fields below in the listed order. No optional omission; nullable fields are present as null. Their operational meaning is unchanged. Only their v2 envelope/hash domain differs. `B` means JSON boolean; quoted choices are enum strings, not arbitrary text.

| kind | Remaining fields, in canonical order |
| --- | --- |
| `tripped` | Legacy trigger: `trigger:Text`, `restriction_persisted:B`. New trigger: those fields followed by `security_event_sequence:P`, `epoch_before:U`, `epoch_after:P` (all three mandatory). See §6.7. |
| `kill` | `outcome:"not_applicable"|"confirmed"|"failed"|"unknown"` |
| `scope_lost` | `cgroup_dev:U`, `cgroup_ino:U` |
| `daemon_lost` | `kill:<kill outcome>`, `elapsed_ms:U` |
| `alarm` | `event:Text`, `outcome:"delivered"|"failed"|"timed_out"|"dropped"` |
| `peer_rejected` | `reason:Text` |
| `peers_suppressed` | `count:P` |
| `model_use` | `method:Text`, `path:Text`, `request_bytes:U`, `status:<integer 100..599>`, `response_bytes:U`, `outcome:"completed"|"refused"|"aborted"|"upstream_error"|"client_closed"`, `refusal:?Text` |
| `model_uses_suppressed` | `count:P` |
| `checkpoint` | `sequence:P`, `reason:"start"|"tripped"|"reset"|"periodic"|"shutdown"`, `statement_sha256:H` |
| `anchor` | `checkpoint_sequence:P`, `outcome:"anchored"|"unverified"|"failed"|"timed_out"|"dropped"`, `log_index:?U`, `detail:?Text` |
| `reset` | `operator_uid:UID`, `reason:?Text`, `applied:B`, `refusal:?Text`, `epoch_before:U`, `epoch_after:U` |

An applied reset has non-null, nonblank printable-ASCII reason of 1..256 bytes, null refusal and checked `epoch_after == epoch_before + 1`; a refused reset has unchanged epoch. Existing quota is never inferred refunded. `anchored` needs non-null log index and the matching verified anchor line; other outcomes are not proof of anchoring. Checkpoint-entry references must match the signed checkpoint at that sequence/reason/digest when present in the bundle; a record claiming a checkpoint absent from the required checkpoint file is invalid.

`model_uses_suppressed` counts only later **already-closed gateway** refusals as in v1. It does not count unallowlisted-endpoint denials or the boundary and tripwire events that are accounted under §6.6. New v2 tripped responses are 403; historical v1 503s remain accepted under v1, not rewritten. A `model_use` with outcome refused has non-null refusal; a completed/aborted/upstream_error/client_closed record has null refusal. Security refusal companions use §7’s safe values; other legacy traffic retains its existing accounting and privacy boundary (no bodies, credentials or headers).

## 6. New substantive event schemas

Every event in this section is substantive, including zero-count window closures. No new security kind can be classified as checkpoint bookkeeping. Field order below follows `kind` first, as written.

### 6.1 `launch_admission`

```json
{"kind":"launch_admission","execution_id":<UUID>,"epoch":<U>,"boot_id":<UUID>,"cgroup_dev":<U>,"cgroup_ino":<U>,"registry_checked":<bool>,"registry_id":<?UUID>,"inventory_sha256":<?H>}
```

A new execution ID for each proposed agent release (including same-run resume sessions); exactly one such record per ID. It records completed **pre-GO approval**, not proof GO was received or that the kernel granted any tool operation. Host-resolved subject/session come from the authenticated manifest; peer/cgroup verification remains a producer duty, not an agent assertion.

In increments 1 and 2, `registry_checked` is false and both nullable fields are null: local launch approval is **not host-wide registry evidence**. In increment 3, true is mandatory, with non-null fixed-host registry UUID and inventory digest. Boot/cgroup identity is the pinned host instance. Digest authenticates the host’s inventory claim; an offline verifier does not independently inspect the filesystem or other runs. Increment 3 still trusts host/kernel and the one configured operator UID.

The producer persists required admission/artifact observations before GO. When even evidence cannot be persisted, refuse GO; no verifier can recover an unwritten observation. A bundle containing only headers after preflight failure need not fabricate an admission.

### 6.2 `artifact_set_admitted`

```json
{"kind":"artifact_set_admitted","execution_id":<UUID>,"manifest_sha256":<H>,"artifact_count":<P>,"total_bytes":<U>}
```

Required once per admitted execution iff the bundle’s artifact digest is non-null; it follows that execution’s `launch_admission` and precedes its model/security observations. Digest equals both manifest binding and hash of artifacts.json; count/sum equal §3.2. Forbidden if no staged set was declared. Producer has verified the pinned source/materialized bytes before GO; event is a signed-recorded claim of that check, not proof from bundled artifacts. No per-fetch quota/read audit is implied.

An execution whose launch_admission is its final execution-bound record may be a pre-GO failure prefix. If its profile declares an artifact set and artifact_set_admitted is absent, accept the otherwise valid prefix as incomplete; never infer GO, artifact verification or release. An artifact-admission-missing diagnostic is permitted, not required (§9). Boundary/tripwire events before required artifact admission remain INVALID. This prefix does not prove cleanup or authorize use.

### 6.3 `boundary_violation`

```json
{"kind":"boundary_violation","execution_id":<UUID>,"epoch":<U>,"reason":<reason>,"action":<"deny"|"quarantine">,"model_use_sequence":<P>,"restriction_decision_id":<?DecisionID>,"window_start_ms":<U>}
```

Closed reasons: `model_connect_forbidden`, `model_proxy_target_forbidden`, `model_endpoint_not_allowlisted`, in that priority. A parsed request receives only the first applicable reason. CONNECT/proxy actions are `quarantine`. Endpoint action is **deny** unless the frozen manifest’s `trip_on_model_endpoint_not_allowlisted` is true, then `quarantine`. `gateway_observed` must be true. An opted-out endpoint event labeled quarantine is invalid, even if correctly signed: it contradicts the recorded profile.

`action` is the required response/intent, not a confirmed kill. For `deny`, restriction ID must be null; event creates no RiskApplied/tripped/kill. Existing independent budget/operator triggers may still trip. For `quarantine`, a non-null restriction ID must reference an actual same-bundle decision record with event `RiskApplied`, outcome `RESTRICTED`, state `Quarantined` and epoch exactly this event’s checked `epoch + 1`. Null denotes unavailable restriction durability; do not manufacture a successful decision/kill. Report durability unknown/failed from available outcome records, never ALLOW. This preserves emergency restriction despite evidence failure.

The execution must have an earlier launch admission and event epoch cannot precede its epoch. `window_start_ms` is elapsed monotonic milliseconds since that execution’s pre-GO admission; ≤2^64−1−5000. These times are local accounting, not UTC, security-token validity or a cross-restart lifetime promise.

### 6.4 `tripwire_presented`

```json
{"kind":"tripwire_presented","execution_id":<UUID>,"epoch":<U>,"marker_id":<TWID>,"action":"quarantine","model_use_sequence":<P>,"restriction_decision_id":<?DecisionID>,"window_start_ms":<U>}
```

Allowed only when tripwires are enabled; marker ID must belong to manifest list. Same epoch/time/restriction-link rules as §6.3. This records a host matcher’s claim of marker **presentation at model ingress**, never its being read, motive, raw marker value, successful escape or provider acceptance. No auto-loaded CLI config/credential file may be a fixture source. The producer never forwards a matched request.

### 6.5 `admission_released`

```json
{"kind":"admission_released","execution_id":<UUID>,"scope_end":<"confirmed"|"failed"|"unknown">,"registry_released":<bool>}
```

Requires an earlier admission. A true registry release requires `registry_checked == true` and scope_end confirmed. Before increment 3 the bool is false even on confirmed local end. Failed/unknown end retains registry ownership; timeout is not eviction. Multiple failed/unknown reports may precede one confirmed end, but none may follow a confirmed end. New security observations after a recorded confirmed scope end are invalid. A valid incomplete prefix may have no release record; do not invent success. Boot/cgroup-name reuse does not equate different executions.

### 6.6 `security_events_suppressed`

```json
{"kind":"security_events_suppressed","first_sequence":<P>,"count":<U>,"window_end_ms":<U>,"complete":<bool>}
```

`first_sequence` references an earlier boundary_violation or tripwire_presented record in this control chain, never a bookkeeping/legacy entry. Exactly one closure per first record; count counts **additional** matching classified requests, not the first. Count 0 is an explicit zero-repeat closure. The producer coalesces within `[window_start_ms, window_start_ms+5000)`, by execution/epoch/kind/reason-or-marker/action; no attacker-controlled free-form bucket. At most 32 live buckets per run; saturation/loss marks complete false and never delays restriction.

Window end is between start and start+5000 inclusive. Reset/normal execution end can close early. Before a new first event with the same execution/epoch/kind/reason-or-marker/action key, the previous closure must already occur earlier in the control journal, and new window_start_ms must be at least previous window_start_ms + 5000 (checked arithmetic). An early window_end_ms does not shorten that same-key minimum. Different execution/epoch keys retain their existing rules. Next recorded event at/after the deadline flushes the old window before starting a new one; no same-key overlapping window. Delayed physical flush after idle does not extend the membership interval. u64 saturation uses max value and complete false, never wraps. Unknown lost events may also make complete false at a smaller count. Missing closure after crash means unknown repeats, not zero. Normal finalization must flush all windows; closings are substantive and need coverage.

Every suppressed request still consumes existing model budgets exactly as before, independently of journal coalescing. An already-closed request counted by legacy model_uses_suppressed is never also counted here. Classification/identity errors are not folded into another run’s bucket.

### 6.7 Closed new trip triggers and event binding

New security trips write exactly these trigger values:

| Event | Closed trigger |
| --- | --- |
| boundary_violation / model_connect_forbidden | `boundary_violation:model_connect_forbidden` |
| boundary_violation / model_proxy_target_forbidden | `boundary_violation:model_proxy_target_forbidden` |
| boundary_violation / model_endpoint_not_allowlisted, operator opt-in true only | `boundary_violation:model_endpoint_not_allowlisted` |
| tripwire_presented | `tripwire_presented` |

A new-trigger tripped entry has exact order `kind,trigger,restriction_persisted,security_event_sequence,epoch_before,epoch_after`. The referenced security event is earlier in this same control journal, has action quarantine and the matching reason/marker kind, and its epoch equals epoch_before. Checked epoch_after equals epoch_before+1. If the event’s restriction link is non-null it references the RiskApplied record at epoch_after, restriction_persisted must be true, and exactly one later matching tripped record is required for a complete trip account, subject only to the terminal-prefix exception below. No applied reset may intervene. A new-trigger tripped record must always have its matching event (including null-link evidence-failure cases, where restriction_persisted is false). A null-link event without a trip record remains an incomplete restriction attempt; it never proves a completed trip.

Every present event/trip counterpart is one-to-one. A durably linked quarantine event with no later matching tripped record is **VALID-but-incomplete**, with the diagnostic **`trip record missing`**, if it is the **last substantive record** in the control journal. Later checkpoint bookkeeping (§8) alone does not change that outcome. If any later substantive record exists (including a kill, release, reset, another security event, or a zero-count window closure), the missing trip counterpart is **INVALID**. A present new-trigger tripped record without its matching earlier event is always INVALID. Duplicate event/trip/restriction-link use, incorrect direction, trigger, opt-in, persisted flag or epoch transition is INVALID, even if signatures verify. This exception never bypasses restriction-link validation, signatures, heads, receipts or any other consistency check, and it never authorizes resume or infers kill/trip completion. Legacy/operator/budget triggers are not paired by this new rule. Unknown strings in the boundary_violation: family are refused, not treated as legacy triggers. Default action-deny endpoint events cannot pair with a new trip.

## 7. Cross-record bindings and privacy

- `[ingress_limit]` is a fixed non-companion model_use path for hardening ingress-limit refusals: fixed method `UNKNOWN`, status 403, outcome refused, request_bytes/response_bytes 0, refusal `request not allowed`; it contains no raw method, target or headers and never pairs with a boundary/TW event.
- Every new execution event references exactly one earlier launch admission in this run. A repeated execution UUID or marker absent from the manifest is invalid. Boundary and tripwire events refer only to model ingress; no direct-network telemetry kind exists in v2.
- Each first boundary or tripwire event references a distinct earlier model_use at `model_use_sequence`. Companion has status 403, outcome refused, request_bytes/response_bytes 0. Boundary companion uses path `[boundary_violation]`, refusal `request not allowed`; the tripwire companion uses path `[tripwire_presented]`, refusal `gateway tripped`. Method is `CONNECT` for CONNECT reason and must never be `CONNECT` for any other boundary reason or a tripwire companion. CONNECT has `model_connect_forbidden` priority and is not also counted as a tripwire request. Otherwise method is the actual bounded ASCII HTTP token (at most 32 bytes); larger tokens are refused at parsing and never forwarded/partially represented. Safe fixed paths prevent leaking attacker-supplied URL/query/token bytes. No raw header/body/marker enters these records.
- Companions and new events do **not** represent two requests. Additional same-window security denials emit no per-request model_use; only the closing count. A companion may precede its event in a captured partial prefix; report incomplete linkage rather than infer no attempted operation. A new event with a nonexistent or reused companion is invalid. Normal producer finalization must pair every safe-path companion with one first event. An unmatched companion yields incomplete accounting even if a checkpoint seals that prefix; a missing-event diagnostic may also be reported (§9); never invent its action or treat it as zero additional activity.
- Quarantine intent alone does not confirm durable restriction or kill. A valid restriction link establishes the recorded RiskApplied outcome; actual tripped/kill/alarm/daemon_lost events establish their separate recorded outcomes. Absence of kill/alarm outcomes is unknown, never confirmed; the required later tripped counterpart for a non-null quarantine link is enforced by §6.7. The verifier never turns a denial/marker/counter into authority or operator recovery.
- Session/run attribution and artifact/private-catalogue digests are host assertions authenticated by the chain/checkpoints. Do not claim independent proof of policy correctness, marker matching, runtime mounts, filesystem isolation or completeness from those digests.
- Security-event companion linkage must remain within the run/control chain. Neither forged execution IDs nor foreign markers confer victim attribution. Values outside the frozen private catalogue are not claimed detected.

## 8. Checkpoints, receipts, anchors and sealing

Apply every v1 §4–§6 requirement with the new Cn chain: key ID/externally trusted key equality, both signatures, exact checkpoint canonical bytes/context, checkpoint sequence/previous digest, nondecreasing journal sequences, head bounds, anchor log-key/proof/signature/binding, and every supplied receipt. A v2 control header’s manifest digest is bound even by control sequence 0 through C0; never compare C0 computed with a v1 domain or stripped header fields.

Both checkpoint signatures remain mandatory; one is insufficient. Checkpoint schema remains `circuitbreaker.checkpoint.v1`, with unchanged SLH-DSA context `circuitbreaker-checkpoint-v1`, ECDSA P-256/SHA-256 and statement digest. Rekor anchor and alarm receipt schemas remain v1; their checkpoint’s control head commits to v2 bytes. No bypass of v1 checks when decoding them for v2. A receipt for another run or an absent checkpoint invalidates the bundle as in v1. A changed manifest with unchanged receipt/checkpoint must fail via the control head.

Empty checkpoint file is structurally valid but authenticates nothing, gives `sealed:false`, and fails any supplied checkpoint-bearing receipt as missing. Without receipt/anchor independently retained elsewhere, consistent trailing deletion may be undetectable. Authenticated start/C0 alone does not cover later records. Bundled keys/report/local receipts do not establish external trust or off-host retention by themselves.

**Bookkeeping remains exactly:** `checkpoint`, `anchor`, and `alarm` with event `checkpoint`. Everything else, including zero-count closures/admission outcomes, is substantive. Do not add a security event to this set to make sealing pass.

`sealed` uses unchanged v1 definition: at least one valid checkpoint; the last checkpoint’s decision sequence equals the entire decision journal record count; every control entry after its control sequence is bookkeeping. New record beyond that head means unsealed, not automatically invalid. A valid hash chain without signed coverage is not evidence of authenticity. No “sealed means all real actions were recorded” claim.

All admission/release/window-closing records must precede the producer’s final covering checkpoint on normal completion. A crash/copy can omit them; report the available prefix and incomplete outcome/count evidence. The verifier does not repair journals, generate missing checkpoints, reset a run, or treat missing evidence as permission.

## 9. Derived totals and outcome reporting

`report.json` is never an input to validation/totals. Calculate from verified records using exact integer arithmetic (arbitrary precision for sums, not wrapping u64). Integers may be displayed as decimal strings when exceeding an output API’s integer range; never round. A new report schema must document that representation rather than produce float approximations.

Required semantic totals:

| Total | Formula / meaning |
| --- | --- |
| `model_use_recorded` | Count every legacy model_use once, grouped by its outcome. Includes security-event companions. |
| `model_use_suppressed` | Sum legacy model_uses_suppressed.count; already-closed gateway refusals only. |
| `security_suppressed` | Sum security_events_suppressed.count, grouped by the referenced first event’s kind/reason-or-marker/action. |
| `model_requests_observed_lower_bound` | Total number of model_use entries + model_use_suppressed + security_suppressed. **Do not add first security events again.** |
| `model_refusals_observed_lower_bound` | model_use entries with outcome refused + both suppressed sums. |
| `boundary_violations_observed_lower_bound` | First boundary_violation entries + counts referencing them, grouped by reason and action. |
| `tripwire_presentations_observed_lower_bound` | First tripwire_presented entries + counts referencing them, grouped by marker ID. Never raw marker. |
| `trips_recorded`, kill/alarm/reset outcomes | Count actual legacy events/outcomes, not inferred from violation intent or missing response. Preserve v1 distinctions. |
| admissions/releases | Count new context/release entries separately; `registry_checked:false` is not a successful host-wide registry check. Retained unknown ownership is not a release. |

A saturated/incomplete window is a lower bound even if its count equals u64 max. A missing closure never means zero repeats. `security_counts_complete` is true only if (a) sealed, (b) last checkpoint reason shutdown, (c) every first security event has exactly one closure with complete true, (d) every safe-path companion is linked, and (e) no recorded loss/overflow is known, and (f) no terminal missing-trip incompleteness is present. Producer report field `security.incomplete_reasons` contains `trip record missing` in the terminal case; this is the one required incomplete-reason string. Verifiers may report additional incomplete reasons, and their absence or wording is not a conformance mismatch. The array is empty when no diagnostic is reported. If any completeness condition fails, security_counts_complete is false. It describes complete **recorded security-window accounting under this contract**, not all agent actions. Legacy/refused-peer counts remain subject to their own coverage limits. Always label observed traffic totals as lower bounds; no claim about hidden/unmediated traffic.

Examples, independent of storage order interleaving:

- Fifty default endpoint misses in one window: one refused model_use companion, one boundary_violation with action deny, one closing count 49. Totals: 50 observed requests/refusals/endpoint violations, **zero trips due to that reason**. Request/byte budgets remain independent and may separately trip; choose sufficient request budget for this fixture.
- First CONNECT: one companion + one boundary event with required action quarantine. Only actual RiskApplied/tripped/kill records establish their recorded outcomes. Later already-tripped requests use existing legacy refusal accounting, not the same boundary window’s count.
- Local marker read: no model-use/security event implied. Tripwire match on otherwise allowed request: one companion + one tripwire event; no upstream effect. A deterministic host harness can test 50 attributed events; cannot require a killed live agent to finish sending them.

Producer may flush counts before/after checkpoint bookkeeping, but only covered substantive counts qualify for a seal. Default endpoint violations must not accidentally enter the tripped-refusal counter or make the report say quarantined. Opt-in changes affect new frozen run profiles only, not historical interpretations.

## 10. Verification algorithm and failures

Use this deterministic first-failure order; within a stage process files/records in order:

1. Load/validate independently trusted gateway keys under v1 §4.1.
2. Select version; validate canonical manifest and safe required-file inventory; refuse unknown/mixed versions with `unsupported_format`/`format_mismatch`, no fallback. Check manifest scalar/profile bounds. A v1 selector uses v1 only when no v2 marker is present.
3. Verify unchanged decision journal (§1 dependency), then the v2 control header/chain/entry grammar. Compare manifest hash, journal IDs and new-kind increment/profile permissions. Non-null decision subjects must match manifest attribution, as §3.1 requires. Hash/order/syntax mismatch fails, never skipped.
4. Check artifacts.json presence/bytes/hash/counts; then new cross-record bindings in control sequence order (admission, companion, restriction links, windows, release), including the later-trip bijection/epoch checks and terminal-prefix incomplete exception in §6.7. Missing referenced earlier records/digests, duplicate bindings, wrong action for frozen opt-in or inconsistent metadata fail.
5. Verify each checkpoint’s key/signatures/canonical digest in file order, then chain and both heads per v1 §4. Verify matching checkpoint bookkeeping claims and head bounds.
6. Verify anchors under v1 §6, then externally supplied receipts in input order under v1 §5, including missing-checkpoint precedence.
7. Compute sealed/outcome/count flags and totals (§8–§9). Incomplete legitimate prefixes may be valid/unsealed or valid with incomplete counts; never silently upgrade those flags.

**Verifier output and exit interface.** The following output and exit-code rules apply to the verifier in this repository and to any verifier claiming conformance. The gateway's own built-in check need not implement this command-line interface, but it must also never report VALID on failure.

A bundle is VALID only if all required structural, hash, binding and signature checks pass under trusted keys, with all supplied receipts/anchors satisfied. A correctly signed but profile-inconsistent action is invalid. Unsupported format, missing required inputs, resource limit or verification error exits nonzero with stage/reason; none may output VALID. Exit statuses are fixed: **0 only for VALID; 1 for anything not VALID** (including unsupported_format, format_mismatch, resource_limit, missing/untrusted inputs or cryptographic/binding failures); **2 only for usage errors** (invalid CLI syntax/options). Each non-VALID verification emits a distinct `STAGE: <stage>; REASON: <reason>` line and never RESULT: VALID. Usage emits usage/help diagnostics, not a verification verdict. These match the v1 verifier's convention. Unsupported/resource-limited results do not receive special exit codes.

A valid bundle with an empty checkpoint file or an uncovered suffix is not a complete/authenticated account. Return at least format, validity, trusted-key status, checkpoint count, sealed flag, count-completeness flag, observed totals and explicit missing/unconfirmed outcomes. Any finer JSON report schema is secondary; it cannot change the normative validity checks or hide uncertainty.

## 11. Conformance cases

A conforming verifier, and the gateway's exporter, must each give the expected result for these cases. The synthetic fixtures in `verifier/tests/` cover them with synthetic data and keys only.

- Valid profiles for increments 1/2/3; each of the three model modes and none; nullable artifact set; every legacy/new event kind. Supply signed synthetic checkpoints/trusted-key files and expected sealed/count outcomes. No generated fixture is accepted solely because exporter and verifier share code.
- Header-only/no-violation v2 rejected by actual v1-only verifiers; manifest removed, changed or mixed with v1 header, unknown version/kind and unknown/duplicate nested fields all fail closed. Historical v1 fixtures keep their old results.
- Exact-byte vectors: domains/NUL/LF, key order/escaping, leading-zero/exponent/fraction/rounded integers, max-u64 fields, malformed UUID/hex and length/line bounds. Hashing a reserialized different string is not accepted.
- Event/trip binding: a durably linked terminal quarantine without a later trip is VALID-but-incomplete (`trip record missing`), including with only bookkeeping afterward. Appending any substantive record without its matching trip makes it INVALID. Missing earlier event, trip before event, wrong trigger/epoch/opt-in/persisted flag, reused restriction link and duplicate trip fail; valid pairs pass. Exercise null-link restriction-failure pairing separately.
- Default endpoint action deny accepted with no new trip, opt-in true action quarantine accepted; their opposites invalid. CONNECT/proxy action deny invalid. Fake model_use link, reused companion, missing admission, foreign marker and after-confirmed-release event invalid. New evidence never contains marker/header/prompt bytes.
- Artifact manifest modified/reordered/oversized/duplicate filename/ID/hash mismatch/count overflow fails; missing known file and orphan known file fail. Correct content digest in a manifest does not let verifier claim it checked unbundled artifact bytes.
- Single-signature-only/incorrect key/incorrect context, mixed journal ID or digest, decreased checkpoint head, missing claimed checkpoint, malformed anchor and missing/changed external receipt checkpoint all fail exactly as inherited v1 requires.
- Fifty default endpoint misses count 50 without double counting/trip; 50 matcher-harness events count first+49; exact 5-second boundary produces separate windows; duplicate closures, overlapping same-key/epoch windows, and malformed closure timing fail; saturated/lost counts require the specified incomplete flags. A closure inherits its bucket/epoch from first_sequence, never an unvalidated new caller-supplied identity. Closed-gateway suppression never added twice.
- Substantive security or zero-count closure after last signed head is unsealed; receipt-covered consistent truncation is invalid; later undelivered suffix may be cut without detection. Missing outcome/release/window closure or an unmatched safe-path companion reports unknown/incomplete, not false confirmation. A dangling new event that references a nonexistent earlier companion is invalid.
- Wire fixtures test the format only. Whether a gateway enforces its profile correctly against real agents is tested separately and is not established by any bundle being VALID.

## 12. Limitations

This is evidence of recorded host claims, not proof of every action, tamper-proof storage, future truthfulness of a key holder, absence of all shared storage, real-time detector coverage, kernel-resistant isolation or incident prevention. The pre-staged package mode gives no file-read audit or per-fetch quota. Direct network attempts that bypass model ingress are blocked by the sandbox but are not observed or recorded in v2. State, authority, quota and reset semantics are not redefined by the wire format. Host and kernel remain trusted; local receipts do not become off-host retention.

Any change to this format after a published revision requires a new revision with its own fixtures and an explicit compatibility analysis.

## Appendix A. Serialization/hash known-answer vector (unsigned)

The following vector is canonical data, not a complete valid bundle: it has no keys, signatures or checkpoints. It tests bytes/hashes only. All IDs/data are synthetic. SHA-256 values are provided so the independent implementation can reproduce them without a producer implementation.

bundle.json (one final LF)

```json
{"schema_version":"circuitbreaker.bundle.v2","run_id":"demo","subject_id":"demo","session_id":"session-1","operator_uid":1000,"decision_journal_id":"00000000-0000-4000-8000-000000000001","control_journal_id":"00000000-0000-4000-8000-000000000002","hardening":{"increment":1,"model_mode":"none","gateway_observed":false,"trip_on_model_endpoint_not_allowlisted":false,"package_mode":"pre_staged_ro","artifact_manifest_sha256":null,"tripwires":false,"tripwire_ids":[],"tripwire_catalogue_sha256":null,"registry":false}}
```

control header (one final LF)

```json
{"format":"circuitbreaker-control.2","journal_id":"00000000-0000-4000-8000-000000000002","bundle_manifest_sha256":"4124d1ca3bfcf8681a9c0db24ae52ce192055360025b21a9b039d5a73d3c1186"}
```

control record 1 (one final LF)

```json
{"body":{"format":"circuitbreaker-control.2","sequence":1,"previous_sha256":"e7e24f0b4b25f8ed9fa05729d1fef7bdca8397b5937dd8bd8239eed33f2e2282","entry":{"kind":"launch_admission","execution_id":"00000000-0000-4000-8000-000000000004","epoch":1,"boot_id":"00000000-0000-4000-8000-000000000003","cgroup_dev":1,"cgroup_ino":2,"registry_checked":false,"registry_id":null,"inventory_sha256":null}},"sha256":"afd396221c2f9453cc4dfa98a1680e725be962b2e186aca5a82ac2bf015d2896"}
```

- Manifest SHA-256 (includes LF): `4124d1ca3bfcf8681a9c0db24ae52ce192055360025b21a9b039d5a73d3c1186`.
- C0 (header excludes LF): `e7e24f0b4b25f8ed9fa05729d1fef7bdca8397b5937dd8bd8239eed33f2e2282`.
- C1 (BODY_BYTES excludes wrapper/LF): `afd396221c2f9453cc4dfa98a1680e725be962b2e186aca5a82ac2bf015d2896`.
