export function tone(value: string, fresh = false) {
  if (/^(PROVISIONAL|OBSERVED|APPROX|Restricted|unsealed|bundle.copy|same.host|not configured|DENY$|NOT VERIFIED$|VALID, INCOMPLETE$)/i.test(value)) return 'amber';
  if (/^(MISMATCH|Quarantined|Terminated|INVALID|failed|timed_out|dropped|REFUSED|trip$)/i.test(value)) return 'red';
  if (fresh && /^(Active|VALID|confirmed|delivered|passed|ALLOW)$/.test(value)) return 'green';
  if (/^UNKNOWN/i.test(value) || value === 'unknown') return 'unknown';
  return 'neutral';
}

export function StatusPill({ value, fresh = false, detail, adverse = false }: { value: string | null | undefined; fresh?: boolean; detail?: string; adverse?: boolean }) {
  const label = value || 'UNKNOWN';
  return <span className={`pill ${adverse ? 'red' : tone(label, fresh)}`} title={detail}>{label}</span>;
}

export function ReadLabel({ label }: { label: string }) {
  return <StatusPill value={label === 'PROVISIONAL' ? 'PROVISIONAL (run not ready)' : label}
    detail={label === 'VERIFIED' ? 'Matched the ready reread. Cryptographic verification requires the exported evidence.' : undefined} />;
}
