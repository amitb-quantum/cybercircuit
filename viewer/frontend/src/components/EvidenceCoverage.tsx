import type { Dict } from '../data/types';

export function EvidenceCoverage({ decisions, controls, checkpoints, trusted, receipts, more }: {
  decisions: Dict[]; controls: Dict[]; checkpoints: Dict[]; trusted: boolean; receipts: boolean; more?: boolean;
}) {
  const lastSequence = (rows: Dict[]) => rows.reduce((maximum, row) => Math.max(maximum, row.body.sequence), 0);
  const ends = { decision: lastSequence(decisions), control: lastSequence(controls) };
  const heads = { decision: 0, control: 0 };
  function range(source: 'decision' | 'control', checkpoint: Dict) {
    const end = checkpoint.statement[source]?.sequence;
    if (!Number.isSafeInteger(end) || end < heads[source]) return 'UNKNOWN';
    if (end === heads[source]) return 'No new records';
    const start = heads[source] + 1;
    heads[source] = end;
    return start === end ? `#${end}` : `#${start}–${end}`;
  }
  return <section className="panel wide coverage-panel"><h2>Checkpoint coverage map</h2>
    <p className="muted">Derived ranges from recorded journal heads. {trusted ? 'The active verifier result is valid.' : 'Treat stored checkpoint heads as claims.'}</p>
    <div className="table-scroll"><table><thead><tr><th>Checkpoint</th><th>Decision range</th><th>Control range</th><th>Receipt lookup</th></tr></thead>
      <tbody>{checkpoints.map(cp => <tr key={cp.statement.sequence}><td>#{cp.statement.sequence} · {cp.statement.reason}</td>
        <td>{range('decision', cp)}</td><td>{range('control', cp)}</td><td>{cp.receipt == null ? 'UNKNOWN' : cp.receipt ? 'Matching receipt' : 'No match'}</td></tr>)}</tbody>
    </table></div>
    {!receipts && <p className="muted">Receipts were not supplied for the active verdict.</p>}
    {more ? <p>UNKNOWN (only a page of records is shown)</p> : (['decision', 'control'] as const).map(source => ends[source] > heads[source] &&
      <div className="coverage-tail" key={source}><span className="pill amber">Uncovered tail</span> <span>{source} #{heads[source] + 1}–{ends[source]} · not covered by a signature</span></div>)}
  </section>;
}
