import type { Verify } from './types';

export function recordedVerdict(result?: Verify) {
  if (!result) return { label: 'NOT VERIFIED', detail: 'No recorded verifier result', trusted: false };
  const lines = result.stdout?.split(/\r?\n/) ?? [];
  const stage = lines.find(line => /^STAGE: \d+; REASON: \S/.test(line));
  const invalid = lines.find(line => line.startsWith('RESULT: INVALID, '));
  if (result.exit_code === 1 && invalid && stage) {
    return { label: 'INVALID', detail: `${invalid.slice('RESULT: INVALID, '.length)} · ${stage}`, trusted: false };
  }
  if (result.exit_code === 0 && lines.includes('RESULT: VALID')) {
    if (lines.includes('security counts complete: no')) {
      const reasons = lines.filter(line => line.startsWith('incomplete: ')).map(line => line.slice(12));
      return { label: 'VALID, INCOMPLETE', detail: reasons.join(' · ') || 'UNKNOWN (no reason reported)', trusted: true };
    }
    const seal = lines.find(line => /^decision records .* sealed (yes|no)$/.test(line));
    return { label: 'VALID', detail: seal?.endsWith(' yes') ? 'Sealed' : seal?.endsWith(' no') ? 'Unsealed' : 'UNKNOWN (seal not reported)', trusted: true };
  }
  return { label: 'UNKNOWN', detail: result.message ?? 'Verifier unavailable or output unrecognised', trusted: false };
}
