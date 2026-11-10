import { useEffect, useState } from 'react';
import { Fields, time, Value } from '../components/Fields';
import { HashCell } from '../components/HashCell';
import { ReadLabel, StatusPill } from '../components/StatusPill';
import { UnknownBanner } from '../components/UnknownBanner';
import type { Adapter, Row, Trip } from '../data/types';

function RecordList({ records, fresh = false }: { records: Row[]; fresh?: boolean }) {
  if (!records.length) return <p className="muted">No matching records observed.</p>;
  return <div className="table-scroll"><table><thead><tr><th>Source</th><th>Seq</th><th>Event</th><th>Outcome</th><th>Reason / detail</th><th>Read status</th></tr></thead>
    <tbody>{records.map(r => {
      const e = r.raw.body.entry;
      return <tr key={`${r.source}:${r.sequence}`} className={r.label === 'PROVISIONAL' ? 'provisional-row' : r.label === 'MISMATCH' ? 'mismatch-row' : ''}>
        <td>{r.source}</td><td>{r.sequence}</td><td>{r.event}{e?.event ? ` · ${e.event}` : ''}</td>
        <td>{r.outcome ? <StatusPill value={r.outcome} fresh={fresh && r.label !== 'PROVISIONAL' && r.label !== 'MISMATCH'}
          adverse={(r.event === 'kill' || r.event === 'daemon_lost') && r.outcome === 'unknown'} /> : '—'}</td>
        <td><Value value={r.reason ?? (e?.log_index != null ? `Rekor index ${e.log_index}` : e?.elapsed_ms != null ? `${e.elapsed_ms} ms` : e?.count)} empty="—" /></td>
        <td><ReadLabel label={r.label} /></td>
      </tr>;
    })}</tbody></table></div>;
}

export function TripDetail({ adapter, id, rows, selected, select, revision, fresh }: {
  adapter: Adapter; id: string; rows: Row[]; selected: number | null; select: (n: number) => void; revision: number; fresh: boolean;
}) {
  const trips = rows.filter(r => r.event === 'tripped');
  const n = selected ?? trips[0]?.sequence;
  const [result, setResult] = useState<{ key: string; data?: Trip; error?: string }>({ key: '' });
  const key = `${id}:${n}`;
  useEffect(() => {
    let active = true;
    if (n != null) void adapter.trip(id, n).then(data => { if (active) setResult({ key, data }); }, e => { if (active) setResult({ key, error: String(e.message || e) }); });
    return () => { active = false; };
  }, [adapter, id, key, n, revision]);
  const d = result.key === key ? result.data : undefined;
  const error = result.key === key ? result.error : undefined;
  const provisional = d?.trip.label === 'PROVISIONAL';
  const entry = d?.trip.raw.body.entry;
  return <section aria-label="Trip detail"><h1>Trip detail</h1>
    <div className="split trip-layout has-detail"><div className="split-list panel trip-list"><h2>Trips</h2>
      {trips.map(r => <button type="button" key={r.sequence} className={`trip-list-button ${r.label === 'PROVISIONAL' ? 'provisional-row' : ''}`} aria-pressed={r.sequence === n}
        onClick={() => select(r.sequence)}><code>C:{r.sequence}</code> <span>{r.reason}</span> <ReadLabel label={r.label} /></button>)}
      {!trips.length && <p className="muted">No trip records observed.</p>}
    </div>
    <div className={`detail trip-detail ${provisional ? 'provisional-detail' : ''}`}>
      <UnknownBanner errors={{ detail: error, ...d?.errors }} />
      {n != null && !d && !error && <p className="muted">Reading C:{n}…</p>}
      {d && <>
        <section className="panel"><h2><span className="mono">C:{d.trip.sequence}</span> {d.trip.reason} <ReadLabel label={d.trip.label} /></h2>
          {d.trip.label === 'VERIFIED' && <p className="muted">Matched the ready reread. Live journal evidence remains cryptographically unverified.</p>}
          <Fields items={[
            ['Configured rule', d.matched_rule ?? (d.trip.reason === 'operator' ? 'operator (manual)' : null)],
            ['Restriction persisted', <Value value={entry?.restriction_persisted} />],
            ['Quarantine transition', d.risk ? <>D:{d.risk.sequence} · {d.risk.event} · {d.risk.state} · epoch {d.risk.epoch} <ReadLabel label={d.risk.label} /></> : 'UNKNOWN (transition not persisted or not uniquely linkable)'],
            ['Time', d.trip.wall_ms == null ? null : `${time(d.trip.wall_ms)} · ${d.trip.wall_source}`], ['Hash', <HashCell value={d.trip.hash} />],
          ]} />
        </section>
        <section className="panel"><h2>Leading records <small>candidate context</small></h2><RecordList records={d.leading} />
          {d.trip.reason === 'journal_fault' && <p>UNKNOWN: a failed write may have left no journal record.</p>}</section>
        <section className="panel"><h2>Kill, daemon, alarms and anchor outcomes</h2><RecordList records={d.effects} fresh={fresh && d.trip.label !== 'MISMATCH' && !provisional} />
          <p className="muted">Process list not recorded by the engine.</p></section>
        <section className="panel"><h2>Trip checkpoint</h2>{d.checkpoint ? <Fields items={[
          ['Sequence', d.checkpoint.statement.sequence], ['Wall time', time(d.checkpoint.statement.wall_time_unix_ms)], ['Statement hash', <HashCell value={d.checkpoint.hash} />],
          ['Receipt lookup', d.checkpoint.receipt == null ? null : d.checkpoint.receipt ? 'matching receipt present (lookup)' : 'no matching receipt'],
        ]} /> : <p className="muted">UNKNOWN (no matching trip checkpoint)</p>}</section>
        <section className="panel"><h2>Later resets</h2>{d.resets.length ? d.resets.map(item => {
          const e = item.row.raw.body.entry;
          return <Fields key={item.row.sequence} items={[
            ['Control sequence', item.row.sequence], ['Outcome', <StatusPill value={e.applied ? 'APPLIED' : 'REFUSED'} />],
            ['Operator UID', e.operator_uid], ['Reason', e.reason], ['Refusal', <Value value={e.refusal} empty="—" />], ['Epochs', `${e.epoch_before} → ${e.epoch_after}`],
            ['Lifted this trip', <Value value={item.lifted_trip} />], ['Recovery', item.recovery ? <>D:{item.recovery.sequence} · reason SHA-256 <HashCell value={item.recovery.raw.body.payload.recovery?.reason_sha256} /></> : <Value value={null} />],
          ]} />;
        }) : <p className="muted">{d.errors.control ? 'UNKNOWN (control journal unavailable)' : 'No later reset recorded.'}</p>}</section>
      </>}
    </div></div>
  </section>;
}
