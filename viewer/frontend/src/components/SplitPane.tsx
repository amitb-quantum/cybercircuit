import { useState, type ReactNode } from 'react';

export function load<T>(key: string, fallback: T): T {
  try { const data = localStorage.getItem(`cc-ui.${key}`); return data ? JSON.parse(data) as T : fallback; } catch { return fallback; }
}
export function save(key: string, value: unknown) {
  try { localStorage.setItem(`cc-ui.${key}`, JSON.stringify(value)); } catch { /* persistence is optional */ }
}

export function SplitPane({ children, detail, close }: { children: ReactNode; detail?: ReactNode; close: () => void }) {
  const [width, setWidth] = useState(() => Number(load('detail-width', 36)) || 36);
  return <div className={`split ${detail ? 'has-detail' : ''}`} style={{ '--detail-width': `${Math.min(60, Math.max(25, width))}%` } as React.CSSProperties}>
    <div className="split-list">{children}</div>
    {detail && <aside className="detail" aria-label="Record detail">
      <div className="detail-actions"><label>Pane width <input aria-label="Detail pane width" type="range" min="25" max="60" value={width}
        onChange={e => { const v = e.target.valueAsNumber; setWidth(v); save('detail-width', v); }} /></label>
        <button type="button" onClick={close}>Close <kbd>Esc</kbd></button></div>{detail}
    </aside>}
  </div>;
}
