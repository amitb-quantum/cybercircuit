import { useEffect, useState } from 'react';
import { Fields, Raw, time, Value } from '../components/Fields';
import { HashCell, copyText } from '../components/HashCell';
import { Icon } from '../components/Icon';
import { JournalChain } from '../components/JournalChain';
import { EvidenceCoverage } from '../components/EvidenceCoverage';
import { V2Evidence } from '../components/V2Evidence';
import { RecordTrust } from '../components/RecordTrust';
import { recordedVerdict } from '../data/verdict';
import { StatusPill } from '../components/StatusPill';
import { UnknownBanner } from '../components/UnknownBanner';
import type { Adapter, Dict, Evidence as EvidenceData, Row, Verify } from '../data/types';

function JournalTable({ rows, title }: { rows: Dict[]; title: string }) {
  return <details className="panel"><summary>{title} · {rows.length} rows</summary><div className="table-scroll journal-scroll"><table><thead><tr>
    <th>Sequence</th><th>Previous hash</th><th>Hash</th><th>Recorded event</th></tr></thead><tbody>{rows.map(row => <tr key={row.body.sequence}>
      <td>{row.body.sequence}</td><td><HashCell value={row.body.previous_sha256} /></td><td><HashCell value={row.sha256} /></td>
      <td>{row.body.entry?.kind ?? row.body.payload?.event ?? 'Record'}</td>
    </tr>)}</tbody></table>{!rows.length && <p>No available rows.</p>}</div></details>;
}

export function Evidence({ adapter, id, revision, activity, onVerdict, receipts = true }: { adapter: Adapter; id: string; revision: string; activity: Row[]; onVerdict?: (result: Verify) => void; receipts?: boolean }) {
  const demo = adapter.demo;
  const [base, setBase] = useState<EvidenceData>(), [selected, setSelected] = useState(''), [data, setData] = useState<EvidenceData>(),
    [offset, setOffset] = useState(0), [error, setError] = useState(''),
    [result, setResult] = useState<{ key: string; value: Verify }>(), [busy, setBusy] = useState(false), [fresh, setFresh] = useState(false);
  const name = demo ? id : selected;
  const resultKey = `${id}:${name}:${receipts}`;
  useEffect(() => {
    let active = true;
    void adapter.evidence(id).then(v => { if (active) { setBase(v); setError(''); } }, e => { if (active) { setBase(undefined); setError(e.message); } });
    return () => { active = false; };
  }, [adapter, id, revision]);
  useEffect(() => {
    let active = true;
    if (demo || name || offset) void adapter.evidence(id, name || undefined, offset).then(v => { if (active) { setData(v); setError(''); } }, e => { if (active) { setData(undefined); setError(e.message); } });
    return () => { active = false; };
  }, [adapter, demo, id, name, offset, revision]);
  useEffect(() => {
    if (!demo) return;
    let active = true;
    void adapter.verify(id, id, receipts).then(v => { if (active) setResult({ key: resultKey, value: v }); }, e => { if (active) setError(e.message); });
    return () => { active = false; };
  }, [adapter, demo, id, receipts, resultKey]);
  useEffect(() => {
    if (!fresh) return;
    const timer = setTimeout(() => setFresh(false), 5000);
    return () => clearTimeout(timer);
  }, [fresh, result]);
  const current = data && (demo || (name ? data.selected === name : offset > 0 && !data.selected)) ? data : base;
  const verdict = result?.key === resultKey ? result.value : undefined;
  const d = current?.decision ?? (name ? [] : activity.filter(r => r.source === 'decision').map(r => r.raw));
  const c = current?.control ?? (name ? [] : activity.filter(r => r.source === 'control').map(r => r.raw));
  const checkpoints: Dict[] = current?.checkpoint ?? [];
  const anchors: Dict[] = current?.anchors ?? [];
  const v2 = current?.version === 2 || current?.profile?.schema_version === 'circuitbreaker.bundle.v2' || verdict?.version === 2;
  const trust = recordedVerdict(verdict);
  const exactTrust = (demo || fresh) && !!verdict?.trusted_key && verdict?.log_key !== 'bundle copy';
  return <section aria-label="Evidence" className={`evidence-screen ${trust.trusted ? '' : 'untrusted-records'}`}><div className="screen-heading"><span className="eyebrow"><Icon name="shield" /> Verification workspace</span><h1>Evidence <small>{demo ? 'recorded verifier output' : 'existing exports'}</small></h1></div>
    <RecordTrust verdict={trust} />
    <UnknownBanner errors={{ evidence: error, ...current?.errors }} />
    <div className="panels evidence-panels">
      <details className="panel wide bundle-files" open={!demo}><summary>{demo ? 'Published bundle files' : 'Bundles'} {demo && <span className="mono muted">{name}</span>}</summary>
        <div className="table-scroll"><table><thead><tr><th>Bundle</th><th>Created</th><th>Files</th></tr></thead><tbody>
          {base?.bundles.map(b => <tr key={b.name}><td><button type="button" aria-pressed={name === b.name} disabled={demo}
            onClick={() => { setSelected(b.name); setOffset(0); setResult(undefined); }}>{b.name}</button></td>
            <td>{b.created_ms != null ? time(b.created_ms) : demo ? 'not recorded' : 'UNKNOWN'}</td>
            <td className="file-list">{b.error ? `UNKNOWN: ${b.error}` : Object.entries(b.files).map(([k, v]) => <span key={k} title={v}>{k}: {v}</span>)}</td></tr>)}
        </tbody></table>{base && !base.bundles.length && <p className="muted">{base.errors.bundles ? 'UNKNOWN (bundle listing failed)' : 'No bundles exported.'}</p>}</div>
        {!demo && <><p>The engine refuses to export while the gateway is live.</p>{base?.export_command && <div className="toolbar"><code>{base.export_command}</code>
          <button type="button" onClick={() => void copyText(base.export_command)}>Copy export command</button></div>}</>}
      </details>
      <section className="panel verifier-panel"><div className="verifier-heading"><span className="icon-tile purple"><Icon name="shield" size={19} /></span><div><h2>Independent verifier</h2><p>Bundle format {v2 ? 'v2' : 'v1'}</p></div>
        <StatusPill value={trust.label} fresh={exactTrust} /></div><div className="toolbar verifier-controls">
        {demo ? <span>{receipts ? 'With published receipts' : 'Without published receipts'}</span> : <>
          <button type="button" disabled={!name || busy} onClick={() => {
            setBusy(true); setError(''); setResult(undefined); setFresh(false);
            void adapter.verify(id, name, true).then(value => { setResult({ key: resultKey, value }); setFresh(true); onVerdict?.(value); }, e => setError(e.message)).finally(() => setBusy(false));
          }}>{busy ? 'Running verifier…' : 'Verify selected bundle'}</button>
          <StatusPill value="same-host receipts" />
        </>}
      </div>
      <ol className="checks">{(verdict?.checks ?? ['Trusted keys', 'Decision journal', 'Control journal', 'Checkpoints', 'Chain and heads', 'Rekor anchors', 'Receipts']
        .map(name => ({ name, status: 'UNKNOWN' }))).map(check => {
          const shade = check.status === 'failed' ? 'red' : check.status === 'passed' && (demo || fresh) ? 'green' : 'unknown';
          return <li key={check.name}><span className={`check-icon ${shade}`}><Icon name={check.status === 'failed' ? 'cross' : check.status === 'passed' ? 'check' : 'minus'} size={14} /></span>
            <span>{check.name}</span><StatusPill value={check.status} fresh={demo || fresh} /></li>;
        })}</ol>
      {verdict && <div className={`verifier-message ${trust.label === 'INVALID' ? 'invalid' : ''}`}>
        <Icon name={trust.label === 'VALID' ? 'check' : 'warn'} size={16} /><span>{trust.detail}</span></div>}
      {!verdict ? <p className="muted">{demo ? 'Reading recorded result…' : 'Select a bundle to run the verifier.'}</p> : <>
        {demo && <p>Recorded output of cybercircuit-verify {verdict.provenance?.version ?? 'UNKNOWN'} on these exact files.</p>}
        {!demo && !fresh && <p className="muted">Last verifier result. Run again to check the current files.</p>}
        {demo && !receipts && verdict.verdict === 'VALID' && <p className="muted">This result does not check any receipts. Removing complete records can leave a bundle that still verifies by itself. A receipt can expose the removal.</p>}
        <details className="verifier-details"><summary>Verifier output and inputs</summary><Fields items={[
          ['Exit code', verdict.exit_code], ['Verifier version', verdict.provenance?.version], ['Verifier commit', <HashCell value={verdict.provenance?.commit} />],
          ['Gateway key (trusted)', <HashCell value={verdict.trusted_key} />], ['Log key', <StatusPill value={verdict.log_key} />],
          ['Seal', verdict.summary ? <StatusPill value={verdict.summary.sealed ? 'sealed' : 'unsealed'} /> : null], ['Receipts checked', verdict.summary?.receipts],
          ['Result detail', verdict.message ?? '—'],
        ]} />
        {verdict.command && <Raw label="Command" value={verdict.command} />}
        {verdict.stdout != null && <Raw label="Verifier stdout" value={verdict.stdout} />}
        {verdict.inputs && <details><summary>Input SHA-256 values</summary><div className="table-scroll"><table><tbody>
          {verdict.inputs.map((f: Dict) => <tr key={f.path}><td>{f.path}</td><td><HashCell value={f.sha256} /></td></tr>)}
        </tbody></table></div></details>}</details>
      </>}
        <details className="verifier-details"><summary>Trust and receipts</summary><p className="muted">A valid bundle shows what was recorded and signed. Receipts or anchors detect removal through checkpoints they hold.</p><Fields items={[
          ['Public key ID', <HashCell value={base?.key_id} />], ['Receipt lines', <Value value={base?.receipt_lines} />],
          ['Receipt locality', <StatusPill value={demo ? 'published receipts' : 'same-host'} />],
        ]} /></details>
      </section>
      <JournalChain decisions={d} controls={c} checkpoints={checkpoints} verdict={verdict} />
      <EvidenceCoverage decisions={d} controls={c} checkpoints={checkpoints} trusted={trust.trusted} receipts={receipts} more={current?.more || offset > 0} />
      {v2 && <V2Evidence key={name} profile={current?.profile} controls={c} decisions={d} verdict={verdict} caseId={id} />}
      <section className="panel wide"><h2>Journal viewers <small>as stored; verified only by the verifier run above on the selected bundle</small></h2>
        {!demo && name && <button type="button" onClick={() => { setSelected(''); setOffset(0); }}>View run journals</button>}
        <JournalTable rows={d} title="Decision journal" /><JournalTable rows={c} title="Control journal" />
        <details className="panel"><summary>Checkpoints · {checkpoints.length} rows</summary><div className="table-scroll journal-scroll"><table><thead><tr>
          {['Seq', 'Reason', 'Wall time (UTC)', 'Decision seq / head', 'Control seq / head', 'Previous', 'Hash', 'SLH / ECDSA bytes', 'Receipt lookup'].map(t => <th key={t}>{t}</th>)}
        </tr></thead><tbody>{checkpoints.map(cp => <tr key={cp.statement.sequence}>
          <td>{cp.statement.sequence}</td><td>{cp.statement.reason}</td><td>{time(cp.statement.wall_time_unix_ms)}</td>
          <td>{cp.statement.decision.sequence} <HashCell value={cp.statement.decision.head_sha256} /></td>
          <td>{cp.statement.control.sequence} <HashCell value={cp.statement.control.head_sha256} /></td>
          <td><HashCell value={cp.statement.previous_checkpoint_sha256} /></td><td><HashCell value={cp.hash} /></td>
          <td>{cp.slh_bytes} / {cp.ecdsa_bytes}</td><td><Value value={cp.receipt == null ? null : cp.receipt ? 'matching' : 'not found'} /></td>
        </tr>)}</tbody></table></div></details>
        <details className="panel"><summary>Rekor anchors · {anchors.length} rows</summary><p className="muted">Optional live comparison with the log is not performed.</p>
          <div className="table-scroll"><table><thead><tr><th>Checkpoint</th><th>Log index</th><th>UUID</th><th>Integrated time</th><th>Statement</th></tr></thead><tbody>
            {anchors.map(a => <tr key={a.checkpoint_sequence}><td>{a.checkpoint_sequence}</td><td>{a.logIndex}</td><td><HashCell value={a.uuid} /></td><td>{time(a.integratedTime * 1000)}</td><td><HashCell value={a.statement_sha256} /></td></tr>)}
          </tbody></table></div></details>
        {!demo && (offset > 0 || current?.more) && <div className="toolbar"><button type="button" disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 200))}>Previous 200</button>
          <button type="button" disabled={!current?.more} onClick={() => setOffset(offset + 200)}>Next 200</button></div>}
      </section>
    </div>
  </section>;
}
