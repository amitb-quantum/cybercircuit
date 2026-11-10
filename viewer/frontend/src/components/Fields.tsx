import type { ReactNode } from 'react';
import { copyText } from './HashCell';

export function Value({ value, empty = 'UNKNOWN' }: { value: unknown; empty?: string }) {
  if (value === null || value === undefined) return <span className="muted">{empty}</span>;
  if (typeof value === 'boolean') return <>{String(value)}</>;
  if (Array.isArray(value)) return <>{value.length ? value.join(', ') : 'none recorded'}</>;
  if (typeof value === 'object') return <code>{JSON.stringify(value)}</code>;
  return <>{String(value)}</>;
}

export function Fields({ items }: { items: [string, ReactNode][] }) {
  return <dl className="fields">{items.map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value ?? <Value value={null} />}</dd></div>)}</dl>;
}

export function Raw({ value, label = 'Redacted record' }: { value: unknown; label?: string }) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  return <div className="raw"><div className="section-bar"><strong>{label}</strong><button type="button" onClick={e => {
    const button = e.currentTarget;
    void copyText(text).then(ok => { button.textContent = ok ? 'Copied' : 'Clipboard unavailable'; });
  }}>Copy</button></div><pre tabIndex={0}>{text}</pre></div>;
}

export function time(ms: number | null | undefined) {
  if (ms == null) return 'UNKNOWN';
  try { return new Date(ms).toISOString().replace('T', ' '); } catch { return 'UNKNOWN (invalid timestamp)'; }
}
