#!/usr/bin/env bash
# Run both verifiers on every challenge-1 case and fail if they disagree,
# or if either disagrees with the published answer key.
# Usage: tools/agree.sh PATH_TO_cybercircuit-verify
set -euo pipefail
VERIFY=${1:?path to the cybercircuit-verify binary}
D=verifier/tests/data/challenge-1
fail=0
# case, receipts?, expected verdict
while read -r b r want; do
    rargs=(); pargs=()
    if [ "$r" = yes ]; then rargs=(--receipts "$D/receipts.jsonl"); pargs=("$D/receipts.jsonl"); fi
    rust=$("$VERIFY" "$D/bundle-$b" --keys "$D/gateway-keys.pub.json" \
        --log-key "$D/rekor-log.pub.pem" "${rargs[@]}" | tail -1 | grep -oE 'VALID|INVALID' | head -1) || true
    py=$(python3 python/spec_check.py "$D/bundle-$b" "$D/gateway-keys.pub.json" \
        "$D/rekor-log.pub.pem" "${pargs[@]}" | tail -1 | grep -oE '^(VALID|INVALID)') || true
    status=ok
    if [ "$rust" != "$want" ] || [ "$py" != "$want" ]; then status=MISMATCH; fail=1; fi
    printf '%-2s receipts=%-3s expected=%-7s rust=%-7s python=%-7s %s\n' "$b" "$r" "$want" "$rust" "$py" "$status"
done <<'CASES'
A no  INVALID
A yes INVALID
B no  VALID
B yes INVALID
C no  VALID
C yes VALID
D no  INVALID
D yes INVALID
CASES
exit $fail
