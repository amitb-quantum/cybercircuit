import { useEffect, useRef, useState } from 'react';
import { HashCell } from './HashCell';
import { Icon } from './Icon';
import type { Dict, Verify } from '../data/types';

function hasBrokenPrevious(row: Dict, previous?: Dict) {
  return !!previous && Number(previous.body.sequence) + 1 === Number(row.body.sequence) &&
    !!previous.sha256 && !!row.body.previous_sha256 && previous.sha256 !== row.body.previous_sha256;
}

export function JournalChain({ decisions, controls, checkpoints, verdict }: { decisions: Dict[]; controls: Dict[]; checkpoints: Dict[]; verdict?: Verify }) {
  const [stream, setStream] = useState<'decision' | 'control'>('control');
  const listRef = useRef<HTMLOListElement>(null);
  const rows = stream === 'decision' ? decisions : controls;
  const failure = verdict?.verdict === 'INVALID' ? String(verdict.failure ?? verdict.message ?? '') : '';
  // Locate a link only when the existing verifier names the checkpoint and journal head.
  const reported = /checkpoint\s+(\d+):\s*(decision|control) head is not in/i.exec(failure);
  const reportedStream = reported?.[2].toLowerCase();
  const reportedCheckpoint = reportedStream === stream ? Number(reported?.[1]) : null;
  const firstBrokenEntry = rows.find((row, index) => hasBrokenPrevious(row, rows[index - 1]))?.body.sequence;
  const brokenCheckpoint = reportedCheckpoint != null && checkpoints.some(cp => cp.statement.sequence === reportedCheckpoint);
  const canJump = firstBrokenEntry != null || brokenCheckpoint;

  function jumpToBreak() {
    const list = listRef.current;
    const broken = list?.querySelector<HTMLElement>('.chain-step.broken');
    if (list && broken) list.scrollTop = Math.max(0, broken.offsetTop - 72);
  }

  useEffect(() => {
    if (reportedStream === 'decision' || reportedStream === 'control') setStream(reportedStream);
  }, [reportedStream]);
  useEffect(() => {
    if (canJump) jumpToBreak();
    else if (listRef.current) listRef.current.scrollTop = 0;
  }, [stream, canJump, firstBrokenEntry, reportedCheckpoint]);
  const points = new Map<number, Dict[]>();
  for (const cp of checkpoints) {
    const seq = cp.statement?.[stream]?.sequence;
    if (typeof seq !== 'number') continue;
    points.set(seq, [...(points.get(seq) ?? []), cp]);
  }
  function checkpoint(cp: Dict) {
    const broken = cp.statement.sequence === reportedCheckpoint;
    return <li className={`chain-step checkpoint-step ${broken ? 'broken' : ''}`} key={`checkpoint:${cp.statement.sequence}`}>
      <span className="chain-node"><Icon name={broken ? 'warn' : 'stack'} size={14} /></span><div className="chain-card">
        <div className="chain-title"><strong>Checkpoint {cp.statement.sequence}</strong><span className="pill chain-kind">{cp.statement.reason}</span></div>
        <div className="chain-hashes"><span>Journal head <HashCell value={cp.statement[stream].head_sha256} /></span><span>Statement <HashCell value={cp.hash} /></span></div>
        {broken && <span className="chain-failure"><Icon name="warn" size={14} /> Verifier: checkpoint head is missing from this journal</span>}
      </div></li>;
  }
  const shown = new Set([0, ...rows.map(r => Number(r.body.sequence))]);
  return <section className="panel chain-panel" aria-label="Journal chain"><div className="chain-header"><div><span className="eyebrow"><Icon name="chain" /> Evidence trail</span>
    <h2>Journal chain</h2></div><div className="chain-tabs" role="group" aria-label="Journal chain source">
      <button type="button" aria-pressed={stream === 'control'} onClick={() => setStream('control')}>Control</button>
      <button type="button" aria-pressed={stream === 'decision'} onClick={() => setStream('decision')}>Decisions</button></div></div>
    <div className="chain-tools"><div className="chain-legend"><span><i /> Entry</span><span><i /> Checkpoint</span><span><i /> Broken link</span></div>
      <button className="jump-break" type="button" disabled={!canJump} onClick={jumpToBreak}><Icon name="warn" size={14} /> Jump to break</button></div>
    <ol className="chain-list" ref={listRef}>{(points.get(0) ?? []).map(checkpoint)}{rows.flatMap((row, i) => {
      const seq = Number(row.body.sequence);
      const broken = hasBrokenPrevious(row, rows[i - 1]);
      return [<li className={`chain-step ${broken ? 'broken' : ''}`} key={`${stream}:${seq}`}><span className="chain-node">{broken && <Icon name="warn" size={13} />}</span>
        <div className="chain-card"><div className="chain-title"><span className="chain-sequence">{stream === 'control' ? 'C' : 'D'}:{seq}</span>
          <strong>{row.body.entry?.kind ?? row.body.payload?.event ?? 'Record'}</strong></div>
          <div className="chain-hashes"><span>Previous <HashCell value={row.body.previous_sha256} /></span><span>Entry <HashCell value={row.sha256} /></span></div>
          {broken && <span className="chain-failure">Previous hash differs from the preceding stored entry</span>}
        </div></li>, ...(points.get(seq) ?? []).map(checkpoint)];
    })}{[...points.entries()].flatMap(([seq, list]) => shown.has(seq) ? [] : list.map(checkpoint))}</ol>
    {!rows.length && !checkpoints.length && <p className="muted">No available rows.</p>}
    <p className="chain-caption">Stored hashes and reported failures. This view does not independently verify the chain.</p>
  </section>;
}
