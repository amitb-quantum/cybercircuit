import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { KeyHelp } from './components/KeyHelp';
import { CommandPalette } from './components/CommandPalette';
import { Icon } from './components/Icon';
import { RecordTrust } from './components/RecordTrust';
import { recordedVerdict } from './data/verdict';
import { StatusPill } from './components/StatusPill';
import { UnknownBanner } from './components/UnknownBanner';
import type { Adapter, Dict, Event, Overview as Snapshot, Row, Source, Verify } from './data/types';
import { Activity, orderRows } from './screens/Activity';
import { Demo } from './screens/Demo';
import { Evidence } from './screens/Evidence';
import { Overview } from './screens/Overview';
import { Reset } from '@reset';
import { TripDetail } from './screens/TripDetail';

const screens = [['o', 'Overview', 'grid'], ['a', 'Activity', 'activity'], ['t', 'Trips', 'bolt'], ['e', 'Evidence', 'chain'], ['r', 'Reset', 'reset']] as const;
type Screen = typeof screens[number][0];
const sources: Source[] = ['decision', 'control'];
const empty: Snapshot = { project: null, run: null, phase: null, process: 'UNKNOWN', state: null, epoch: null,
  read_age: 0, healthy_read: false, errors: {}, reset_reasons: ['Waiting for the first project read.'] };

type List = { rows: Row[]; run: string | null; phase: string | null; error?: string | null };
const blank = (): List => ({ rows: [], run: null, phase: null });

function useConsole(adapter: Adapter, id: string) {
  const [overview, setOverview] = useState<Snapshot>(empty);
  const [lists, setLists] = useState<Record<Source, List>>({ decision: blank(), control: blank() });
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  const [clock, setClock] = useState(0);
  const [lastBeat, setLastBeat] = useState(0);
  useEffect(() => {
    let alive = true;
    const abort = new AbortController();
    let reopen: number | undefined;
    const active: Record<Source, List> = { decision: blank(), control: blank() };
    const wanted: Record<Source, Dict | null> = { decision: null, control: null };
    const loading: Record<Source, boolean> = { decision: false, control: false };
    setOverview(empty); setLists({ ...active }); setError(''); setLastBeat(0);
    const status = (v: Snapshot) => { if (alive) { setOverview(v); const now = Date.now(); setLastBeat(now); setClock(now); setError(''); } };

    const fetchRows = async (source: Source) => {
      if (loading[source] || !alive) return;
      loading[source] = true;
      try {
        while (wanted[source] && alive) {
          const signal = wanted[source]!;
          wanted[source] = null;
          const prior = active[source];
          const same = signal.run !== undefined && prior.run === signal.run && prior.phase === signal.phase;
          const append = same && !prior.error && signal.length > prior.rows.length;
          const items = append ? [...prior.rows] : [];
          let cursor = items.at(-1)?.sequence ?? 0;
          let page = await adapter.rows(id, source, cursor);
          // A transition between the notification and GET requires a full reread.
          if (append && (page.run !== prior.run || page.phase !== prior.phase || page.error)) {
            items.length = 0;
            cursor = 0;
            page = await adapter.rows(id, source, 0);
          }
          const run = page.run, phase = page.phase;
          while (alive) {
            if (page.run !== run || page.phase !== phase) { wanted[source] ??= {}; break; }
            items.push(...page.rows);
            if (!page.more) break;
            const next = items.at(-1)?.sequence ?? 0;
            if (next <= cursor) throw new Error('Journal pagination stopped advancing');
            cursor = next;
            page = await adapter.rows(id, source, cursor);
          }
          if (alive && page.run === run && page.phase === phase) {
            active[source] = { run, phase, rows: items, error: page.error };
            setLists({ ...active }); setRevision(r => r + 1);
          }
        }
      } catch (e) {
        if (alive) {
          active[source] = { ...blank(), error: e instanceof Error ? e.message : 'Journal unavailable' };
          setLists({ ...active }); setRevision(r => r + 1);
        }
      } finally { loading[source] = false; }
    };
    const event = (type: Event, data: Dict) => {
      if (!alive) return;
      if (type === 'status') status(data as Snapshot);
      else if (type === 'stale') setError('Project stream is stale.');
      else { wanted[type] = data; void fetchRows(type); }
    };
    void adapter.overview(id).then(status, e => { if (alive) setError(e.message); });
    for (const source of sources) { wanted[source] = {}; void fetchRows(source); }
    const connect = () => {
      if (!adapter.stream || !alive) return;
      void adapter.stream(event, abort.signal).catch(e => {
        if (!alive) return;
        setError(e instanceof Error ? e.message : 'Stream unavailable');
        reopen = window.setTimeout(connect, 1000);
      });
    };
    connect();
    const tick = adapter.demo ? undefined : window.setInterval(() => setClock(Date.now()), 250);
    return () => { alive = false; abort.abort(); window.clearTimeout(reopen); window.clearInterval(tick); };
  }, [adapter, id]);
  const age = lastBeat ? overview.read_age + Math.max(0, clock - lastBeat) / 1000 : Infinity;
  const connected = adapter.demo || (!error && age <= 5);
  const expectedRun = adapter.demo ? id : overview.run;
  const rows = useMemo(() => orderRows(sources.flatMap(source => lists[source].run === expectedRun ? lists[source].rows : [])), [lists, expectedRun]);
  const errors = { decision: lists.decision.error, control: lists.control.error, stream: connected ? null : error || 'Waiting for fresh status' };
  return { overview, age, connected, revision, rows, errors };
}

export function App({ adapter }: { adapter: Adapter }) {
  const [screen, setScreen] = useState<Screen>('o');
  const [caseId, setCaseId] = useState(adapter.cases[0]?.id ?? '');
  const [receipts, setReceipts] = useState(true);
  const [trip, setTrip] = useState<number | null>(null);
  const [help, setHelp] = useState(false), [paused, setPaused] = useState(false), [palette, setPalette] = useState(false);
  const [demoVerdicts, setDemoVerdicts] = useState<Record<string, { with: Verify; without: Verify }>>({});
  const [liveVerdict, setLiveVerdict] = useState<{ dataset: string; value: Verify }>();
  const prefix = useRef(0);
  const { overview, age, connected, revision, rows, errors } = useConsole(adapter, caseId);
  const view = !connected ? { ...overview, process: 'UNKNOWN', state: null, epoch: null, healthy_read: false,
    errors: { ...overview.errors, stream: errors.stream || 'stale' } } : overview;
  const dataset = adapter.demo ? caseId : overview.run ?? '';
  const navigate = useCallback((next: Screen) => { setScreen(next); if (next === 't') setTrip(null); }, []);
  const openTrip = useCallback((n: number) => { setTrip(n); setScreen('t'); }, []);
  const recordVerdict = useCallback((value: Verify) => setLiveVerdict({ dataset, value }), [dataset]);
  useEffect(() => {
    if (!adapter.demo) return;
    let current = true;
    void Promise.allSettled(adapter.cases.map(async c => {
      const [withReceipts, withoutReceipts] = await Promise.all([adapter.verify(c.id, c.id, true), adapter.verify(c.id, c.id, false)]);
      return [c.id, { with: withReceipts, without: withoutReceipts }] as const;
    })).then(results => {
      if (current) setDemoVerdicts(Object.fromEntries(results.flatMap(r => r.status === 'fulfilled' ? [r.value] : [])));
    });
    return () => { current = false; };
  }, [adapter]);
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === 'k') {
        e.preventDefault(); setHelp(false); setPalette(v => !v); return;
      }
      if (palette) return;
      if (e.key === 'Escape' && help) { e.preventDefault(); setHelp(false); return; }
      if (e.ctrlKey || e.metaKey || e.altKey || (e.target instanceof HTMLElement && /INPUT|TEXTAREA|SELECT/.test(e.target.tagName))) return;
      if (e.key === '?') { e.preventDefault(); setHelp(v => !v); return; }
      if (help) return;
      if (e.key === 'g') { prefix.current = Date.now(); return; }
      if (Date.now() - prefix.current < 1000 && screens.some(([code]) => e.key === code)) {
        e.preventDefault(); navigate(e.key as Screen);
      }
      prefix.current = 0;
    };
    window.addEventListener('keydown', key);
    return () => window.removeEventListener('keydown', key);
  }, [navigate, help, palette]);
  useEffect(() => { setTrip(null); setPaused(false); }, [dataset]);
  const provisional = overview.phase === 'preparing';
  const fault = !connected || !view.healthy_read;
  const recorded = demoVerdicts[caseId]?.[receipts ? 'with' : 'without'];
  const trust = recordedVerdict(recorded);
  return <div className={`console ${adapter.demo ? 'demo' : 'operator'}`}>
    <header className={`top ${!adapter.demo && fault ? 'top-unknown' : ''}`}>
      <strong className="brand"><span className="brand-icon"><Icon name="bolt" size={15} /></span>Cyber-Circuit</strong>
      {adapter.demo ? <span className="demo-banner"><b>DEMO</b><span>Recorded public evidence · no live gateway</span></span> : <>
        <span className="top-path" title={view.project ?? ''}>{view.project ?? 'UNKNOWN project'}</span>
        <span className="mono" title={view.run ?? ''}>run {view.run?.slice(0, 8) ?? 'UNKNOWN'}</span>
        <span>Gateway <StatusPill value={view.process} detail={view.process_reason} /> <small>derived</small></span>
        <span>Kernel <StatusPill value={view.state} fresh={view.healthy_read && view.state_source === 'live status'} /></span>
        <span>epoch {view.epoch ?? 'UNKNOWN'}</span>
        {provisional && <StatusPill value="PROVISIONAL (run not ready)" />}
        <span className="read-age" title={Object.entries(view.errors).map(([k, v]) => `${k}: ${v}`).join('\n')}>
          {!connected || fault && Object.keys(view.errors).length ? `UNKNOWN · ${Object.keys(view.errors)[0] || 'source'}` : Number.isFinite(age) ? `read ${age.toFixed(1)} s ago` : 'UNKNOWN read age'}
        </span>
      </>}
      <button type="button" className="command-button" aria-label="Open command palette" onClick={() => setPalette(true)}><Icon name="search" /> <span>Jump to…</span> <kbd>Ctrl K</kbd></button>
      <button type="button" className="help-button" aria-label="Keyboard shortcuts" onClick={() => setHelp(true)}>?</button>
    </header>
    <div className="workspace"><nav aria-label="Console screens">
      <div className="nav-label">Workspace</div>
      {screens.map(([key, name, icon]) => <button type="button" key={key} onClick={() => navigate(key)} aria-current={screen === key ? 'page' : undefined}>
        <Icon name={icon} /><span>{name}</span><kbd>g {key}</kbd></button>)}
    </nav>
    <main tabIndex={-1}>
      {adapter.demo && <Demo cases={adapter.cases} selected={caseId} select={setCaseId} verdicts={demoVerdicts} receipts={receipts} setReceipts={setReceipts} />}
      {!adapter.demo && screen !== 'a' && screen !== 'o' && <UnknownBanner errors={{ stream: errors.stream }} />}
      <div className={screen !== 'e' && !trust.trusted ? 'untrusted-records' : undefined}>
      {screen !== 'e' && <RecordTrust verdict={trust} />}
      {screen === 'o' && <Overview data={view} demo={adapter.demo} rows={rows} journalErrors={errors} openTrip={openTrip}
        trust={trust} verdict={adapter.demo ? recorded : liveVerdict?.dataset === dataset ? liveVerdict?.value : undefined} />}
      {screen === 'a' && <Activity key={dataset} rows={rows} errors={errors} openTrip={openTrip} demo={adapter.demo} paused={paused} setPaused={setPaused} />}
      {screen === 't' && <TripDetail key={dataset} adapter={adapter} id={caseId} rows={rows} selected={trip} select={setTrip} revision={revision} fresh={view.healthy_read} />}
      {screen === 'e' && <Evidence key={dataset} adapter={adapter} id={caseId} revision={`${revision}:${JSON.stringify(view.evidence_revision ?? null)}`} activity={rows} onVerdict={recordVerdict} receipts={receipts} />}
      {screen === 'r' && <Reset key={dataset} adapter={adapter} data={view} connected={connected} />}
      </div>
    </main></div>
    <div className="copy-feedback" data-copy-feedback role="status" />
    {help && <KeyHelp close={() => setHelp(false)} />}
    {palette && <CommandPalette close={() => setPalette(false)} commands={[
      ...screens.map(([key, name, icon]) => ({ label: `Open ${name}`, icon, hint: `g ${key}`, action: () => navigate(key) })),
      { label: 'Keyboard shortcuts', icon: 'search', hint: '?', action: () => setHelp(true) },
    ]} />}
  </div>;
}
