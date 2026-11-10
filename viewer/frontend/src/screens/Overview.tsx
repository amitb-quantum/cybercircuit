import type { ReactNode } from 'react';
import { Fields, time, Value } from '../components/Fields';
import { HashCell } from '../components/HashCell';
import { Icon } from '../components/Icon';
import { ReadLabel, StatusPill, tone } from '../components/StatusPill';
import { UnknownBanner } from '../components/UnknownBanner';
import type { Dict, Overview as Snapshot, Row, Verify } from '../data/types';
import { recordedVerdict } from '../data/verdict';

export function GrantTable({ grants, tick, nextCall = true }: { grants?: Dict[] | null; tick?: number; nextCall?: boolean }) {
  if (!grants) return <p className="muted">UNKNOWN (grant configuration unavailable)</p>;
  return <div className="table-scroll"><table><thead><tr>{['Tool', 'Grant ID', 'Quota', 'Used · derived', 'Remaining · derived', 'Validity (process ticks)', 'Last tick', ...(nextCall ? ['Note'] : [])]
    .map(t => <th key={t}>{t}</th>)}</tr></thead><tbody>{grants.map(g => <tr key={g.id}>
      <td>{g.tool}</td><td className="mono">{g.id}</td><td>{g.quota}</td><td><Value value={g.used} /></td><td><Value value={g.remaining} /></td>
      <td>{g.not_before}–{g.expires_at} of the current gateway process</td><td><Value value={tick} /></td>
      {nextCall && <td>{g.next_call_trips ? 'Next call trips if denied for quota' : '—'}</td>}
    </tr>)}</tbody></table>{!grants.length && <p className="muted">No grants configured.</p>}</div>;
}

function ago(ms: number) {
  const seconds = Math.floor((Date.now() - ms) / 1000);
  if (!Number.isFinite(seconds) || seconds < 0) return 'UNKNOWN';
  for (const [name, size] of [['d', 86400], ['h', 3600], ['m', 60]] as const) if (seconds >= size) return `${Math.floor(seconds / size)}${name} ago`;
  return `${seconds}s ago`;
}

function Metric({ label, icon, accent, value, note, status }: { label: string; icon: string; accent: string; value: ReactNode; note: ReactNode; status: string }) {
  return <div className="metric panel"><div className="metric-top"><span className={`icon-tile ${status === 'unknown' ? 'unknown' : accent}`}><Icon name={icon} size={17} /></span>
    <span className={`status-dot ${status}`} aria-hidden="true" /></div><div className="metric-label">{label}</div>
    <div className={`metric-value ${status === 'unknown' ? 'metric-unknown' : ''}`}>{value ?? 'UNKNOWN'}</div><div className="metric-note">{note}</div></div>;
}

function OutcomeCounts({ counts, fresh }: { counts?: Record<string, number> | null; fresh: boolean }) {
  if (!counts) return <StatusPill value="UNKNOWN" />;
  const entries = Object.entries(counts);
  return <div className="outcome-counts">
    {entries.length ? <div className="count-pills">{entries.map(([outcome, count]) => {
      let shade = tone(outcome, fresh);
      if (outcome === 'anchored' && fresh) shade = 'green';
      if (['pending', 'unverified', 'queued'].includes(outcome)) shade = 'amber';
      return <span className={`pill ${shade}`} key={outcome}>{outcome} <b>{count}</b></span>;
    })}</div> : <span className="muted">None recorded</span>}
    <details className="outcome-raw"><summary>Raw</summary><pre>{JSON.stringify(counts, null, 2)}</pre></details>
  </div>;
}

function OverviewJournal({ decisions, trip, errors, openTrip }: {
  decisions: Row[]; trip?: Row; errors: Partial<Record<'decision' | 'control' | 'stream', string | null>>; openTrip?: (sequence: number) => void;
}) {
  const decisionError = errors.decision || errors.stream;
  const tripError = errors.control || errors.stream;
  return <div className="overview-journal">
    <section className="panel recent-decisions"><div className="overview-card-title"><Icon name="activity" /><h2>Last 10 decisions</h2><small>{decisions.length} shown</small></div>
      <UnknownBanner errors={{ decisions: decisionError }} />
      {decisions.length > 0 && <table><thead><tr><th scope="col">Seq</th><th scope="col">Tick</th><th scope="col">Event</th><th scope="col">Outcome</th><th scope="col">Reason</th></tr></thead>
        <tbody>{decisions.map(row => <tr key={row.sequence}>
          <td><code>D:{row.sequence}</code></td><td><Value value={row.tick} /></td><td>{row.event}</td>
          <td><StatusPill value={row.outcome} fresh={!decisionError && row.label !== 'PROVISIONAL' && row.label !== 'MISMATCH'} /></td>
          <td className="mono">{row.reason ?? 'UNKNOWN'}</td>
        </tr>)}</tbody></table>}
      {!decisions.length && !decisionError && <p className="muted">No decisions recorded.</p>}
    </section>
    <section className="panel latest-trip"><div className="overview-card-title"><Icon name="bolt" /><h2>Latest trip</h2></div>
      <UnknownBanner errors={{ trip: tripError }} />
      {trip ? <><div className={`latest-trip-trigger ${trip.label === 'PROVISIONAL' ? 'provisional-row' : 'trip-row'}`}>
        <Icon name="warn" /><strong>{trip.reason ?? 'UNKNOWN'}</strong><ReadLabel label={trip.label} />
      </div><Fields items={[
        ['Control sequence', <code>C:{trip.sequence}</code>],
        ['Wall time', trip.wall_ms == null ? <StatusPill value="UNKNOWN" /> : <>{time(trip.wall_ms)} <small>{trip.wall_source}</small></>],
        ['Entry hash', <HashCell value={trip.hash} />],
      ]} />{openTrip && <button className="latest-trip-link" type="button" onClick={() => openTrip(trip.sequence)}>Open trip detail <Icon name="arrow" size={14} /></button>}</> :
        !tripError && <p className="muted">No trip recorded.</p>}
    </section>
  </div>;
}

export function Overview({ data, demo, rows = [], verdict, trust = recordedVerdict(verdict), journalErrors = {}, openTrip }: {
  data: Snapshot; demo: boolean; rows?: Row[]; verdict?: Verify;
  trust?: ReturnType<typeof recordedVerdict>;
  journalErrors?: Partial<Record<'decision' | 'control' | 'stream', string | null>>; openTrip?: (sequence: number) => void;
}) {
  const b = data.breaker, u = data.upstream, m = data.model, last = data.last_decision, cfg = data.settings;
  const unavailable = demo ? 'not applicable: recorded evidence' : data.process === 'STOPPED' ? 'UNKNOWN (gateway stopped)' : 'UNKNOWN (live status unavailable)';
  const decision = rows.find(row => row.source === 'decision' && (demo || row.sequence === last?.sequence));
  const recent = last ?? (demo ? decision : undefined);
  const provisional = data.phase === 'preparing';
  const showVerification = trust.label !== 'VALID';
  const hero = showVerification ? trust.label : provisional ? 'PROVISIONAL' : data.state ?? 'UNKNOWN';
  const kernelLabel = demo ? 'Recorded kernel state' : 'Kernel state';
  const stateTone = tone(hero, data.healthy_read && data.state_source === 'live status');
  const delivered = data.alarms != null ? data.alarms.delivered ?? 0 : null;
  const anchored = data.anchors != null ? data.anchors.anchored ?? 0 : null;
  const passes = verdict?.checks.filter(c => c.status === 'passed').length ?? 0;
  const failures = verdict?.checks.filter(c => c.status === 'failed').length ?? 0;
  const hasVerdict = verdict?.verdict === 'VALID' || verdict?.verdict === 'INVALID';
  const recentDecisions = rows.filter(row => row.source === 'decision').slice(0, 10);
  const latestTrip = rows.find(row => row.source === 'control' && row.event === 'tripped');
  const absent: string[] = [];
  if (demo && !b) absent.push('Gateway process', 'Trip in this process', 'Scope registered', 'Restrictions');
  const field = (label: string, value: ReactNode, missing = value == null): [string, ReactNode][] => {
    if (demo && missing) { absent.push(label); return []; }
    return [[label, value]];
  };
  const showGrants = !demo || !!data.grants, showTriggers = !demo || !!data.triggers, showModel = !demo || !!m;
  if (!showGrants) absent.push('Grants', 'Last gateway tick');
  if (!showTriggers) absent.push('Trigger configuration');
  if (!showModel) absent.push('Model forwarder configuration');
  return <section aria-label="Overview" className="overview-screen">
    <section className="state-hero"><div className="hero-kicker"><Icon name="shield" size={17} /><h1>Overview</h1><span> / </span><span>{showVerification ? 'Verification result' : kernelLabel}</span></div>
      <div className={`hero-state ${stateTone}`}>{hero}</div>
      <div className="hero-decision"><span className="hero-kicker"><Icon name="activity" size={16} /> Last decision</span>
        <strong>{recent?.event ?? 'UNKNOWN'}</strong>{recent && <><div className="hero-decision-meta"><span className="mono">#{recent.sequence} · tick {recent.tick}</span><StatusPill value={recent.outcome} /></div>
          <span className="mono hero-reason">{recent.reason ?? 'UNKNOWN'}</span></>}
        <span className="hero-time"><Icon name="clock" size={14} /> {decision?.wall_ms != null ? `${ago(decision.wall_ms)} · ${decision.wall_source ?? 'APPROX'}` : 'Time since decision: UNKNOWN'}</span>
      </div>
      <div className="hero-meta"><span>Epoch <b className="mono">{data.epoch ?? 'UNKNOWN'}</b></span><span className="hero-divider" />
        <span>{trust.label} · {trust.detail}</span>
        {!trust.trusted && <small>Recorded state (untrusted): {data.state ?? 'UNKNOWN'}</small>}
        {provisional ? <span>Run not ready · kernel state UNKNOWN</span> : <span>{data.state_source ?? 'State unavailable'}</span>}
        {!demo && data.phase === 'ready' && <span className={`pill ${data.healthy_read ? 'green' : 'neutral'}`} title="Run phase; distinct from kernel state">ready</span>}</div>
    </section>
    <UnknownBanner errors={data.errors} />
    <div className="metric-grid" aria-label="Evidence metrics">
      <Metric label="Checkpoints" icon="stack" accent="purple" value={data.checkpoint_count} note={data.last_checkpoint?.reason ? `Latest: ${data.last_checkpoint.reason}` : 'Signed checkpoints'} status={data.checkpoint_count == null ? 'unknown' : 'purple'} />
      <Metric label="Receipts / checkpoints" icon="receipt" accent="blue" value={data.receipt_lines == null || data.receipt_checkpoints == null ? null : `${data.receipt_lines} / ${data.receipt_checkpoints}`} note={demo ? 'Published receipt lines' : 'Same-host receipt lines'} status={data.receipt_lines == null || data.receipt_checkpoints == null ? 'unknown' : demo ? 'blue' : 'amber'} />
      <Metric label="Alarms delivered" icon="bell" accent={demo || data.healthy_read ? 'green' : 'blue'} value={delivered} note="Notifier outcome" status={delivered == null ? 'unknown' : 'blue'} />
      <Metric label="Rekor anchors" icon="chain" accent="purple" value={anchored} note="Recorded anchored outcomes" status={anchored == null ? 'unknown' : 'purple'} />
      <Metric label="Verifier result" icon="shield" accent="blue" value={hasVerdict ? <StatusPill value={verdict?.verdict} fresh={demo && !!verdict?.trusted_key && verdict?.log_key !== 'bundle copy'} /> : null}
        note={hasVerdict ? `${passes} passed · ${failures} failed${demo ? verdict?.with_receipts === false ? ' · without receipts' : ' · with receipts' : ' · last result'}` : 'No result available'} status={!hasVerdict ? 'unknown' : verdict?.verdict === 'INVALID' ? 'red' : demo && verdict?.trusted_key && verdict?.log_key !== 'bundle copy' ? 'green' : 'blue'} />
    </div>
    <OverviewJournal decisions={recentDecisions} trip={latestTrip} errors={journalErrors} openTrip={openTrip} />
    <div className="panels overview-panels">
      {(!demo || !!b) && <section className="panel"><h2>Gateway and restrictions</h2><Fields items={[
        ['Gateway process · derived', <StatusPill value={data.process} detail={data.process_reason} />],
        ['Trip in this process', b ? <Value value={b.tripped_this_process} /> : unavailable],
        ['Scope registered', b ? <Value value={b.scope_registered} /> : unavailable],
      ]} />
        <h3>Restrictions</h3>{b ? <div className="table-scroll"><table><thead><tr><th>Epoch</th><th>Restriction</th></tr></thead><tbody>
          {b.restrictions.map((r: Dict) => <tr key={r.epoch}><td>{r.epoch}</td><td><Value value={r.restriction} /></td></tr>)}
        </tbody></table>{!b.restrictions.length && <p>None in force.</p>}</div> : <p className="muted">{unavailable}</p>}
      </section>}
      <section className="panel"><h2>Identity</h2><Fields items={[
        ...field('Subject', data.subject?.id), ...field('Session', data.subject?.session), ...field('Policy version', data.policy_version),
        ...field('Policy SHA-256 · recorded', <HashCell value={data.policy_sha256} />, !data.policy_sha256), ...field('Scope unit', data.scope_unit),
        ...(demo ? field('Run sessions', data.sessions) : field('Run phase / sessions', <><Value value={data.phase} /> / <Value value={data.sessions} /></>)), ...field('Agent preset', data.preset),
        ...field('Upstream program', u?.program), ...field('Arguments', u ? <Value value={u.args} /> : null), ...field('Environment names', u ? <Value value={u.env_names} /> : null),
        ...field('Credential file entries', u ? <Value value={u.credential_files.map((v: Dict) => `${v.name}: ${v.status}`)} /> : null),
      ]} /></section>
      {showGrants && <section className="panel wide"><h2>Grants <small>Usage is derived from durable lease reservations.</small></h2><GrantTable grants={data.grants} tick={data.last_tick} /></section>}
      {showTriggers && <section className="panel"><h2>Triggers</h2>{data.triggers ? <div className="table-scroll"><table><thead><tr><th>Rule</th><th>Fired · derived</th></tr></thead><tbody>
        {data.triggers.map((t: Dict) => <tr key={t.rule}><td className="mono">{t.rule}</td><td><Value value={t.count} /></td></tr>)}</tbody></table>
        {!data.triggers.length && <p>No configured triggers.</p>}</div> : <p className="muted">UNKNOWN (trigger config unavailable)</p>}</section>}
      {showModel && <section className="panel"><h2>Model forwarder</h2>{m?.configured === false ? <StatusPill value="not configured" /> : m ? <>
        <Fields items={[
          ['Upstream', m.upstream], ['Socket', m.listen], ['Allowlist', <Value value={m.target_allowlist.map((p: string[]) => p.join(' '))} />], ['Credential', m.credential],
          ['Requests', <><StatusPill value="OBSERVED" /> <Value value={m.observed?.requests} /> / {m.max_requests}</>],
          ['Request bytes', <><StatusPill value="OBSERVED" /> <Value value={m.observed?.request_bytes} /> / {m.max_request_bytes}</>],
          ['Refusals by type', <><StatusPill value="OBSERVED" /> <Value value={m.observed?.refusals} /></>],
          ['Suppressed records', <><StatusPill value="OBSERVED" /> <Value value={m.observed?.suppressed} /></>],
        ]} /><p className="muted">Recorded lower bounds since the last start checkpoint. Exact counters: UNKNOWN (not exposed).</p>
      </> : <p className="muted">UNKNOWN (model configuration unavailable)</p>}</section>}
      <section className="panel"><h2>Evidence health</h2><Fields items={[
        ['Checkpoints', data.checkpoint_count], ['Last checkpoint', data.last_checkpoint ? `${data.last_checkpoint.reason} · ${time(data.last_checkpoint.wall_time_unix_ms)}` : null],
        ['Alarms by outcome', <OutcomeCounts counts={data.alarms} fresh={demo || data.healthy_read} />], ['Receipt lines / checkpoints', <><Value value={data.receipt_lines} /> / <Value value={data.receipt_checkpoints} /></>],
        ['Receipt locality', <StatusPill value={demo ? 'published receipts' : 'same-host'} />],
        ...field('Rekor configuration', <StatusPill value={data.rekor_configured == null ? null : data.rekor_configured ? 'configured' : 'not configured'} />, data.rekor_configured == null),
        ['Anchors by outcome', <OutcomeCounts counts={data.anchors} fresh={demo || data.healthy_read} />],
        ...field('Last activity · derived', data.last_activity ? `${time(data.last_activity[0])} · ${data.last_activity[1]}` : null),
      ]} /></section>
      {!demo && <section className="panel"><h2>Gateway configuration</h2>{cfg ? <Fields items={[
        ['Listen socket', cfg.listen], ['Control socket', cfg.control], ['Control journal', cfg.control_journal], ['Decision journal', cfg.decision_journal],
        ['Start mode', cfg.start], ['Alarm notifier', cfg.alarm?.notifier], ['Alarm timeout (ms)', cfg.alarm?.timeout_ms], ['Checkpoint file', cfg.checkpoint?.file],
        ['Interval (s)', cfg.checkpoint?.interval_s], ['Signing directory', cfg.checkpoint?.signing_directory],
      ]} /> : <p className="muted">UNKNOWN (gateway configuration unavailable)</p>}</section>}
      {demo && absent.length > 0 && <details className="panel missing-fields wide"><summary>Not in recorded evidence ({absent.length} fields)</summary>
        <p>These fields require project configuration or a live gateway.</p><Fields items={absent.map(label => [label, <StatusPill value="UNKNOWN" />])} /></details>}
    </div>
  </section>;
}
