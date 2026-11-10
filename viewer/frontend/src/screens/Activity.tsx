import { useEffect, useMemo, useRef, useState } from 'react';
import { DataTable, type Column } from '../components/DataTable';
import { Fields, time, Value } from '../components/Fields';
import { HashCell, copyText } from '../components/HashCell';
import { Icon } from '../components/Icon';
import { SplitPane, load, save } from '../components/SplitPane';
import { ReadLabel, StatusPill } from '../components/StatusPill';
import { UnknownBanner } from '../components/UnknownBanner';
import type { Row } from '../data/types';

export const rowKey = (r: Row) => `${r.source}:${r.sequence}`;

function copyRecord(row: Row) {
  return copyText(JSON.stringify({ source: row.source, sequence: row.sequence, event: row.event,
    outcome: row.outcome, reason: row.reason, sha256: row.hash }, null, 2));
}

const allColumns: Column<Row>[] = [
  { id: 'source', title: 'D/C', width: 44, render: r => <span className={`source-mark ${r.source}`}>{r.source === 'decision' ? 'D' : 'C'}</span> },
  { id: 'seq', title: 'Seq', width: 48, render: r => <code>{r.sequence}</code> },
  { id: 'tick', title: 'Tick', width: 50, render: r => <Value value={r.tick} empty="—" /> },
  { id: 'time', title: 'Approx. wall time', width: 222, render: r => r.wall_ms == null ? <Value value={null} /> : <span className="mono" title={`${time(r.wall_ms)} · ${r.wall_source ?? 'APPROX'}`}>{time(r.wall_ms).slice(0, 19)} <small>APPROX</small></span> },
  { id: 'event', title: 'Event / kind', width: 114, render: r => r.event },
  { id: 'tool', title: 'Tool · derived', width: 109, render: r => <span title={r.resource_digest ?? ''}><Value value={r.tool} empty="—" /></span> },
  { id: 'outcome', title: 'Outcome', width: 100, render: r => r.outcome ? <StatusPill value={r.outcome}
    adverse={(r.event === 'kill' || r.event === 'daemon_lost') && r.outcome === 'unknown'} /> : '—' },
  { id: 'reason', title: 'Reason / trigger', width: 156, render: r => <span className="mono" title={r.reason ?? ''}><Value value={r.reason} empty="—" /></span> },
  { id: 'epoch', title: 'Epoch', width: 61, render: r => <Value value={r.epoch} empty="—" /> },
  { id: 'state', title: 'State after', width: 102, render: r => <Value value={r.state} empty="—" /> },
  { id: 'hash', title: 'Hash', width: 115, render: r => <HashCell value={r.hash} /> },
  { id: 'read', title: 'Read status', width: 175, render: r => <ReadLabel label={r.label} /> },
];

function DecisionSparkline({ rows, unavailable }: { rows: Row[]; unavailable: boolean }) {
  const ticks = new Map<number, number>();
  for (const row of rows) if (row.source === 'decision' && row.tick != null) ticks.set(row.tick, (ticks.get(row.tick) ?? 0) + 1);
  const entries = [...ticks.entries()].sort(([a], [b]) => a - b);
  const min = entries[0]?.[0], max = entries.at(-1)?.[0], peak = entries.reduce((p, [, count]) => Math.max(p, count), 1);
  const points = entries.map(([tick, count]) => [min == null || max == null || max === min ? 110 : 10 + (tick-min)/(max-min)*200, 48 - count / peak * 34]);
  return <div className="sparkline"><div><span className="eyebrow"><Icon name="activity" /> Decisions by tick</span>
    <strong>{unavailable ? 'UNKNOWN' : rows.filter(r => r.source === 'decision').length}<small>{unavailable ? '' : ' recorded decisions'}</small></strong>
    <span className="muted">{unavailable ? 'Decision journal unavailable' : min == null ? 'No recorded ticks' : min === max ? `Tick ${min}` : `Ticks ${min}–${max}`}</span></div>
    {!unavailable && points.length > 0 && <svg viewBox="0 0 220 55" role="img" aria-label="Recorded decision counts by engine tick" preserveAspectRatio="none">
      <path d="M7 48h206M7 28h206M7 8h206" stroke="#DCE5F4" strokeDasharray="3 4" fill="none" />
      {points.length > 1 && <><polygon points={`10,48 ${points.map(p => p.join(',')).join(' ')} 210,48`} fill="#EEE6FC" />
        <polyline points={points.map(p => p.join(',')).join(' ')} fill="none" stroke="#7C4DDB" strokeWidth="2.3" strokeLinejoin="round" /></>}
      {points.map(([x,y], i) => <circle key={i} cx={x} cy={y} r="3.5" fill="#7C4DDB"><title>Tick {entries[i][0]}: {entries[i][1]} decisions</title></circle>)}
    </svg>}</div>;
}

export function orderRows(rows: Row[]) {
  // Approximate time is a cross-stream hint. Preserve known sequence order in each stream.
  const d = rows.filter(r => r.source === 'decision').sort((a,b) => b.sequence - a.sequence);
  const c = rows.filter(r => r.source === 'control').sort((a,b) => b.sequence - a.sequence);
  const merged: Row[] = [];
  let i = 0, j = 0;
  while (i < d.length || j < c.length) {
    if (j === c.length || (i < d.length && (d[i].wall_ms ?? -1) > (c[j].wall_ms ?? -1))) merged.push(d[i++]);
    else merged.push(c[j++]);
  }
  return merged;
}

export function Activity({ rows, errors, openTrip, demo, paused, setPaused }: {
  rows: Row[]; errors: Record<string, string | null | undefined>; openTrip: (n: number) => void; demo: boolean; paused: boolean; setPaused: (value: boolean) => void;
}) {
  const [query, setQuery] = useState(''), [source, setSource] = useState(''), [tool, setTool] = useState(''), [outcome, setOutcome] = useState(''),
    [event, setEvent] = useState(''), [reason, setReason] = useState(''), [selected, setSelected] = useState(''), [focus, setFocus] = useState('');
  const [hidden, setHidden] = useState<string[]>(() => { const value = load('hidden-columns', []); return Array.isArray(value) ? value : []; });
  const [widths, setWidths] = useState<Record<string, number>>(() => load('column-widths', {}) || {});
  const frozen = useRef<Row[]>(rows);
  // A pause freezes additions, but reconciliation must still update labels on visible rows.
  if (!paused) frozen.current = rows;
  const current = useMemo(() => new Map(rows.map(r => [rowKey(r), r])), [rows]);
  const view = paused ? frozen.current.map(r => current.get(rowKey(r)) ?? r) : rows;
  const pending = paused ? rows.length - frozen.current.length : 0;
  const filters = useMemo(() => view.filter(r => {
    if ((source && r.source !== source) || (tool && r.tool !== tool) || (outcome && r.outcome !== outcome) || (event && r.event !== event) || (reason && r.reason !== reason)) return false;
    return !query || [r.source, r.sequence, r.tick, r.wall_ms == null ? '' : time(r.wall_ms), r.event, r.tool, r.outcome, r.reason, r.epoch, r.state, r.hash, r.label]
      .some(v => String(v ?? '').toLowerCase().includes(query.trim().toLowerCase()));
  }), [view, source, tool, outcome, event, reason, query]);
  const columns = allColumns.filter(c => c.id === 'source' || !hidden.includes(c.id)).map(c => ({ ...c,
    render: c.id === 'outcome' ? (r: Row) => r.outcome === 'ALLOW' ? <StatusPill value={r.outcome} fresh={r.label !== 'PROVISIONAL' && r.label !== 'MISMATCH' && !errors.stream && !errors[r.source]} /> : c.render(r) : c.render,
    width: Math.min(400, Math.max(40, widths[c.id] || c.width)) }));
  const search = useRef<HTMLInputElement>(null);
  const record = current.get(selected);
  const open = (r: Row) => { setFocus(rowKey(r)); setSelected(rowKey(r)); };
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey || (e.target instanceof HTMLElement && /INPUT|SELECT|TEXTAREA|BUTTON/.test(e.target.tagName) && e.key !== 'Escape')) return;
      if (e.key === '/') { e.preventDefault(); search.current?.focus(); }
      if (e.key === 'p') setPaused(!paused);
      if (e.key === 'Escape') setSelected('');
      if (e.key === 'c' && record) void copyRecord(record);
      if (e.key === 'j' || e.key === 'k') {
        e.preventDefault();
        const at = filters.findIndex(r => rowKey(r) === focus);
        const next = Math.min(filters.length - 1, Math.max(0, at + (e.key === 'j' ? 1 : -1)));
        if (filters[next]) setFocus(rowKey(filters[next]));
      }
      if (e.key === 'Enter' && focus && current.has(focus)) {
        const row = current.get(focus)!;
        if (row.event === 'tripped') openTrip(row.sequence); else open(row);
      }
    };
    window.addEventListener('keydown', key);
    return () => window.removeEventListener('keydown', key);
  }, [current, filters, focus, record, paused, setPaused, openTrip]);
  const options = (field: 'tool' | 'event' | 'reason') => [...new Set(view.map(r => r[field]).filter((v): v is string => !!v))].sort();
  const select = (title: string, value: string, set: (v: string) => void, values: string[]) => <label>{title} <select value={value} onChange={e => set(e.target.value)}>
    <option value="">All</option>{values.map(t => <option key={t}>{t}</option>)}</select></label>;
  return <section aria-label="Live activity" className="activity-screen"><div className="activity-heading"><div className="screen-heading"><span className="eyebrow"><Icon name="activity" /> Journal stream</span>
    <h1>{demo ? 'Activity replay' : 'Live activity'} <small>{demo ? 'recorded public evidence' : 'live, unverified until export'}</small></h1>
    <p className="muted">Newest first in each journal. Cross-journal order and times are APPROX.</p></div>
    <DecisionSparkline rows={view} unavailable={!!(errors.decision || errors.stream)} /></div>
    <UnknownBanner errors={errors} />
    <div className="panel activity-panel"><div className="activity-filters"><div className="filter-chips" role="group" aria-label="Outcome shortcuts">
      {[['', 'All events'], ['ALLOW', 'Allow'], ['DENY', 'Deny'], ['RESTRICTED', 'Restricted'], ['trip', 'Trips']].map(([value, name]) => <button key={name} type="button"
        aria-pressed={outcome === value} onClick={() => setOutcome(value)}><i className={`status-dot ${value === 'ALLOW' ? 'green' : value === 'trip' ? 'red' : value ? 'amber' : 'purple'}`} />{name}</button>)}
    </div><span className="filter-count">{filters.length} of {view.length} records</span></div>
    <div className="toolbar activity-toolbar">
      <label className="activity-search"><Icon name="search" /><input ref={search} aria-label="Filter activity" placeholder="Search displayed values" value={query} onChange={e => setQuery(e.target.value)} /></label>
      {select('Source', source, setSource, ['decision', 'control'])}{select('Tool', tool, setTool, options('tool'))}
      {select('Outcome', outcome, setOutcome, ['ALLOW', 'DENY', 'RESTRICTED', 'trip'])}{select('Event', event, setEvent, options('event'))}{select('Reason', reason, setReason, options('reason'))}
      <button type="button" onClick={() => setPaused(!paused)} aria-pressed={paused}>{paused ? 'Resume' : 'Pause'} <kbd>p</kbd></button>
      {paused && <span>{Object.values(errors).some(Boolean) || pending < 0 ? 'UNKNOWN' : pending} new rows</span>}
      <details className="columns"><summary>Columns</summary><div className="column-menu panel">{allColumns.map(c => <div key={c.id}>
        <label><input type="checkbox" disabled={c.id === 'source'} checked={c.id === 'source' || !hidden.includes(c.id)} onChange={e => {
          const next = e.target.checked ? hidden.filter(id => id !== c.id) : [...hidden, c.id]; setHidden(next); save('hidden-columns', next);
        }} /> {c.title}</label>
        <input type="number" aria-label={`${c.title} width`} min="40" max="400" value={widths[c.id] ?? c.width} onChange={e => {
          const next = { ...widths, [c.id]: e.target.valueAsNumber || c.width }; setWidths(next); save('column-widths', next);
        }} />
      </div>)}</div></details>
    </div>
    <SplitPane close={() => setSelected('')} detail={record && <><h2>{record.event} · {rowKey(record)}</h2><ReadLabel label={record.label} />
      <Fields items={[["Outcome", <Value value={record.outcome} />], ["Reason", <Value value={record.reason} />],
        ["Entry hash", <HashCell value={record.hash} />], ["Previous hash", <HashCell value={record.previous} />]]} />
      <button type="button" onClick={() => void copyRecord(record)}>Copy record summary</button></>}>
      <DataTable rows={filters} columns={columns} rowKey={rowKey} selected={selected} focused={focus} onSelect={open}
        onTrip={r => openTrip(r.sequence)} rowTone={r => r.label === 'PROVISIONAL' ? 'provisional-row' : r.label === 'MISMATCH' ? 'mismatch-row' : ''}
        trip={r => r.event === 'tripped' ? <><Icon name="bolt" size={14} /><span>TRIP · C:{r.sequence} · {r.reason}</span><ReadLabel label={r.label} /><span>Open trip detail →</span></> : null}
        label="Activity records" />
    </SplitPane>
    <div className="activity-footer muted">VERIFIED means a matching ready reread.</div></div>
  </section>;
}
