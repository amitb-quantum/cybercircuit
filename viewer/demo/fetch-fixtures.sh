#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
commit=6f720a6429341b4c56f4290f80f86769d3eca366
base="https://raw.githubusercontent.com/amitb-quantum/cybercircuit/$commit/verifier/tests/data"
mkdir -p -- fixtures
download() {
local manifest=$1 prefix=$2
while read -r digest file; do
  [[ "$digest" =~ ^[0-9a-f]{64}$ && "$file" =~ ^[a-zA-Z0-9][a-zA-Z0-9./-]*$ && "$file" != *..* ]] || exit 1
  if [[ "$manifest" == SHA256SUMS ]]; then
    [[ "$file" =~ ^(bundle-[ABCD]/(decision\.jsonl|control\.jsonl|checkpoints\.jsonl|gateway-keys\.pub\.json|rekor-anchors\.jsonl|rekor-log\.pub\.pem)|gateway-keys\.pub\.json|receipts\.jsonl|rekor-log\.pub\.pem)$ ]] || exit 1
  else
    [[ "$file" =~ ^(t-ih14-2026-11-05/(claude|codex|gemini)/(alarms\.jsonl|gateway-keys\.pub\.json|bundle/(bundle\.json|decision\.jsonl|control\.jsonl|checkpoints\.jsonl|gateway-keys\.pub\.json))|v2-lab-2026-10-28/(bundles/[a-z0-9-]+/(bundle\.json|artifacts\.json|decision\.jsonl|control\.jsonl|checkpoints\.jsonl|gateway-keys\.pub\.json)|keys/[a-z0-9-]+\.pub\.json|receipts/[a-z0-9-]+\.jsonl))$ ]] || exit 1
  fi
  dest="fixtures/$file"
  mkdir -p -- "$(dirname -- "$dest")"
  if [[ -f "$dest" ]] && printf '%s  %s\n' "$digest" "$dest" | sha256sum --status --check; then
    continue
  fi
  part=$(mktemp -- "$(dirname -- "$dest")/.fixture.XXXXXXXX")
  trap 'rm -f -- "$part"' EXIT
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 45 --retry 2 --max-filesize 8000000 --output "$part" "$base/$prefix$file"
  printf '%s  %s\n' "$digest" "$part" | sha256sum --check --status
  mv -T -- "$part" "$dest"
  trap - EXIT
done < "$manifest"
(cd fixtures && sha256sum --strict --check "../$manifest")
}
download SHA256SUMS challenge-1/
download SHA256SUMS.v2 ''
