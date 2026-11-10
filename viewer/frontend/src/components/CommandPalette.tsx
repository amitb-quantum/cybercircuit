import { useEffect, useRef, useState } from 'react';
import { Icon } from './Icon';

export type Command = { label: string; icon: string; hint?: string; action: () => void };

export function CommandPalette({ commands, close }: { commands: Command[]; close: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const [query, setQuery] = useState(''), [active, setActive] = useState(0);
  const results = commands.filter(c => `${c.label} ${c.hint ?? ''}`.toLowerCase().includes(query.trim().toLowerCase()));
  useEffect(() => { ref.current?.showModal(); }, []);
  function run(command: Command) { close(); command.action(); }
  return <dialog className="command-palette" ref={ref} aria-label="Command palette" onCancel={e => { e.preventDefault(); close(); }}
    onClick={e => { if (e.target === ref.current) close(); }}>
    <div className="command-inner">
      <div className="command-search"><Icon name="search" size={20} /><input autoFocus aria-label="Search commands" placeholder="Jump to a screen…" value={query}
        onChange={e => { setQuery(e.target.value); setActive(0); }} onKeyDown={e => {
          if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            e.preventDefault(); setActive(i => results.length ? (i + (e.key === 'ArrowDown' ? 1 : -1) + results.length) % results.length : 0);
          }
          if (e.key === 'Enter' && results[active]) { e.preventDefault(); run(results[active]); }
        }} /><button onClick={close} type="button" aria-label="Close command palette"><kbd>Esc</kbd></button></div>
      <div className="command-results" aria-label="Commands">{results.map((c, i) => <button type="button" key={c.label} className={i === active ? 'highlighted' : ''}
        onMouseEnter={() => setActive(i)} onClick={() => run(c)}><Icon name={c.icon} /><span>{c.label}</span>{c.hint && <kbd>{c.hint}</kbd>}</button>)}
        {!results.length && <p className="muted">No matching commands.</p>}</div>
    </div>
  </dialog>;
}
