import { useState } from 'react';
import { Fields, Value } from './Fields';
import { HashCell } from './HashCell';
import { StatusPill } from './StatusPill';
import { recordedVerdict } from '../data/verdict';
import type { Dict, Verify } from '../data/types';

type Reference = { source: 'Control' | 'Decision'; record: Dict };

function countBy(records: Dict[], key: (entry: Dict) => string) {
  const counts = new Map<string, number>();
  for (const record of records) {
    const group = key(record.body.entry);
    counts.set(group, (counts.get(group) ?? 0) + 1);
  }
  return [...counts].map(([name, count]) => `${name} ${count}`).join(' · ') || 'None in shown records';
}

function totalCounts(records: Dict[]) {
  return records.reduce((total, record) => {
    const count = record.body.entry.count;
    return Number.isSafeInteger(count) || (typeof count === 'string' && /^\d+$/.test(count)) ? total + BigInt(count) : total;
  }, 0n).toString();
}

export function V2Evidence({ profile, controls, decisions, verdict, caseId }: {
  profile?: Dict; controls: Dict[]; decisions: Dict[]; verdict?: Verify; caseId: string;
}) {
  const [selected, setSelected] = useState<Reference>();
  const byControl = new Map(controls.map(record => [record.body.sequence, record]));
  const byDecision = new Map(decisions.map(record => [record.body.decision_id, record]));
  const entry = (record: Dict) => record.body.entry;
  const kinds = (...names: string[]) => controls.filter(record => names.includes(entry(record).kind));
  const admissions = kinds('launch_admission');
  const artifacts = kinds('artifact_set_admitted');
  const releases = kinds('admission_released');
  const events = kinds('boundary_violation', 'tripwire_presented');
  const trips = kinds('tripped');
  const windows = kinds('security_events_suppressed');
  const hardening = profile?.hardening;
  const trust = recordedVerdict(verdict);
  const authenticated = trust.trusted && verdict?.summary?.sealed === true && verdict?.summary?.checkpoints > 0;
  const totals = (trust.trusted ? verdict?.stdout?.split(/\r?\n/) : [])?.filter(line =>
    /^(model requests observed|boundary violations |tripwire presentations |kills: |admissions |security counts complete: |incomplete: )/.test(line)) ?? [];
  function link(record?: Dict, source: Reference['source'] = 'Control') {
    if (!record) return <span className="muted">UNKNOWN</span>;
    return <button type="button" className="record-ref" onClick={() => setSelected({ source, record })}>
      {source === 'Control' ? 'C' : 'D'}:{record.body.sequence}
    </button>;
  }
  const steps = [
    ['Dry run', admissions[0]], ['Normal work', admissions[1]], ['Deliberate quota trip', trips.find(record => entry(record).trigger === 'quota_exhausted:issue_write')],
    ['Relaunch refused while quarantined', admissions[3]], ['Operator reset', kinds('reset').find(record => entry(record).applied === true)],
    ['Normal work resumed', admissions[4]],
  ] as const;
  return <>
    <section className="panel wide"><h2>Run profile · format v2</h2>
      <p className="muted">{authenticated ? 'Authenticated by the checkpoint chain.' : 'AS STORED · profile authentication UNKNOWN.'}</p>
      <Fields items={[
        ['Run ID', <Value value={profile?.run_id} />], ['Subject / session', <><Value value={profile?.subject_id} /> / <Value value={profile?.session_id} /></>],
        ['Hardening increment · recorded', <Value value={hardening?.increment} />], ['Model mode', <Value value={hardening?.model_mode} />],
        ['Gateway observed', <Value value={hardening?.gateway_observed} />], ['Trip on unlisted model endpoint', <Value value={hardening?.trip_on_model_endpoint_not_allowlisted} />],
        ['Package mode', <Value value={hardening?.package_mode} />], ['Artifact manifest digest', hardening?.artifact_manifest_sha256 ? <HashCell value={hardening.artifact_manifest_sha256} /> : <Value value={hardening?.artifact_manifest_sha256} empty={hardening ? 'No artifact set recorded' : 'UNKNOWN'} />],
        ['Tripwire IDs', <Value value={Array.isArray(hardening?.tripwire_ids) ? hardening.tripwire_ids.filter((id: unknown) => typeof id === 'string' && /^tw-(0[1-9]|1[0-6])$/.test(id)).join(', ') || 'None recorded' : null} />],
      ]} />
    </section>
    {caseId.startsWith('agent-') && <section className="panel wide"><h2>Published agent run · November 5</h2>
      <ol className="run-steps">{steps.map(([label, record]) => <li key={label}>{label} {link(record)}</li>)}</ol>
    </section>}
    {selected && <aside className="panel wide" aria-label="Linked evidence record"><h2>{selected.source} record #{selected.record.body.sequence} · AS STORED</h2>
      <Fields items={[
        ['Event', <Value value={selected.record.body.entry?.kind ?? selected.record.body.payload?.event} />],
        ['Recorded outcome', <Value value={selected.record.body.entry?.outcome ?? selected.record.body.payload?.outcome} />],
        ['Entry hash', <HashCell value={selected.record.sha256} />],
      ]} /><button type="button" onClick={() => setSelected(undefined)}>Close linked record</button></aside>}
    <section className="panel wide"><h2>Admissions and releases · recorded</h2>
      <div className="table-scroll"><table><thead><tr><th>Execution ID</th><th>Launch admission</th><th>Registry check</th><th>Artifact admission</th><th>Scope end / release</th></tr></thead>
        <tbody>{admissions.map(record => { const e = entry(record); const matching = releases.filter(item => entry(item).execution_id === e.execution_id);
          const artifact = artifacts.find(item => entry(item).execution_id === e.execution_id);
          return <tr key={record.body.sequence}><td className="mono">{e.execution_id}</td><td>{link(record)}</td>
            <td>{e.registry_checked === false ? 'local launch check, not a host-wide registry' : e.registry_checked === true ? 'Host-wide registry checked' : 'UNKNOWN'}</td>
            <td>{artifact ? <>{link(artifact)} · {entry(artifact).artifact_count} artifacts · {entry(artifact).total_bytes} bytes</> : hardening?.artifact_manifest_sha256 ? 'UNKNOWN' : 'No artifact set declared'}</td>
            <td>{matching.length ? matching.map(item => <div key={item.body.sequence}>{link(item)} <StatusPill value={entry(item).scope_end} /> · registry released: <Value value={entry(item).registry_released} /></div>) : 'UNKNOWN'}</td></tr>;
        })}</tbody></table></div>
      {!admissions.length && <p className="muted">No launch admission recorded in these rows.</p>}
    </section>
    <section className="panel wide"><h2>Security events · recorded</h2>
      <div className="table-scroll"><table><thead><tr><th>Event</th><th>Reason / marker ID</th><th>Action</th><th>Model use</th><th>RiskApplied</th><th>Bound trip</th></tr></thead>
        <tbody>{events.map(record => { const e = entry(record); const trip = trips.find(item => entry(item).security_event_sequence === record.body.sequence);
          const marker = typeof e.marker_id === 'string' && /^tw-(0[1-9]|1[0-6])$/.test(e.marker_id) ? e.marker_id : null;
          return <tr key={record.body.sequence}><td>{link(record)} · {e.kind}</td><td><Value value={e.kind === 'tripwire_presented' ? marker : e.reason} /></td>
            <td>{e.action}</td><td>{link(byControl.get(e.model_use_sequence))}</td><td>{e.action === 'deny' ? 'Not applicable' : link(byDecision.get(e.restriction_decision_id), 'Decision')}</td>
            <td>{e.action === 'deny' ? 'Not applicable' : link(trip)}</td></tr>;
        })}</tbody></table></div>
      {!events.length && <p className="muted">No security events recorded in these rows.</p>}
      <h3>Suppression windows · recorded monotonic time</h3>
      {windows.length ? <ol className="run-steps">{windows.map(record => { const e = entry(record); const first = byControl.get(e.first_sequence);
        return <li key={record.body.sequence}>{link(first)} → {link(record)} · <Value value={first && entry(first).window_start_ms} />–{e.window_end_ms} ms · {e.count} additional · complete: <Value value={e.complete} /></li>;
      })}</ol> : <p className="muted">No suppression windows recorded in these rows.</p>}
    </section>
    <section className="panel wide"><h2>Verifier totals · lower bound</h2>
      {totals.length ? <ul>{totals.map(line => <li key={line}>{line}</li>)}</ul> : <p>UNKNOWN (the verifier did not report totals for this result).</p>}
      <h3>Additional counts · derived lower bounds from shown records</h3>
      <Fields items={[
        ['Model use by outcome', countBy(kinds('model_use'), item => item.outcome ?? 'UNKNOWN')],
        ['Already-closed model refusals', totalCounts(kinds('model_uses_suppressed'))],
        ['Additional security requests in closed windows', totalCounts(windows)],
        ['Trips recorded', trips.length], ['Kill outcomes', countBy(kinds('kill'), item => item.outcome ?? 'UNKNOWN')],
        ['Alarm outcomes', countBy(kinds('alarm'), item => item.outcome ?? 'UNKNOWN')],
        ['Reset outcomes', countBy(kinds('reset'), item => item.applied === true ? 'applied' : item.applied === false ? 'refused' : 'UNKNOWN')],
      ]} />
    </section>
  </>;
}
