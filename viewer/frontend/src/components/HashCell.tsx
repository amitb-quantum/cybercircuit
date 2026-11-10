function highlight(value: string, on: boolean) {
  for (const element of document.querySelectorAll<HTMLElement>('[data-hash]')) {
    if (element.dataset.hash === value) element.toggleAttribute('data-highlight', on);
  }
}

export async function copyText(value: string) {
  try { await navigator.clipboard.writeText(value); return true; } catch { return false; }
}

export function HashCell({ value }: { value?: string | null }) {
  if (!value) return <span className="muted">UNKNOWN</span>;
  return <button type="button" className="hash" data-hash={value} title={`${value} · click to copy`} aria-label={`Copy hash ${value}`}
    onMouseEnter={() => highlight(value, true)} onMouseLeave={() => highlight(value, false)}
    onFocus={() => highlight(value, true)} onBlur={() => highlight(value, false)} onClick={e => {
      e.stopPropagation();
      void copyText(value).then(ok => { const el = document.querySelector<HTMLElement>('[data-copy-feedback]'); if (el) el.textContent = ok ? 'Hash copied' : 'Clipboard unavailable'; });
    }}>{value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value}</button>;
}
