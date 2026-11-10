import { Icon } from '../components/Icon';
import type { Verify } from '../data/types';
import { recordedVerdict } from '../data/verdict';
import { StatusPill } from '../components/StatusPill';

export function Demo({ cases, selected, select, verdicts, receipts, setReceipts }: {
  cases: { id: string; label: string }[]; selected: string; select: (id: string) => void;
  verdicts: Record<string, { with: Verify; without: Verify }>; receipts: boolean; setReceipts: (enabled: boolean) => void;
}) {
  return <div className="demo-picker" aria-label="Recorded public evidence">
    <div className="challenge-title"><span className="icon-tile purple"><Icon name="chain" size={19} /></span><div><strong>Evidence challenge 1</strong>
      <span>Published bundles · independent verifier</span></div></div>
    <div className="bundle-picker" role="group" aria-label="Bundle">
      {cases.filter(c => c.id.startsWith('bundle-')).map((c, i, challenge) => {
        const verdict = recordedVerdict(verdicts[c.id]?.[receipts ? 'with' : 'without']);
        return <button type="button" key={c.id} aria-label={`Bundle ${c.label}`} aria-pressed={selected === c.id}
        aria-description={verdict.label} title={verdict.label} onClick={() => select(c.id)}
        onKeyDown={e => {
          if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
          e.preventDefault(); const next = (i + (e.key === 'ArrowLeft' ? -1 : 1) + challenge.length) % challenge.length;
          select(challenge[next].id); e.currentTarget.parentElement?.querySelectorAll('button')[next]?.focus();
        }}><span>{c.label}</span>{verdict.label === 'INVALID' && <span className="bundle-warning"><Icon name="warn" size={13} /></span>}</button>;
      })}
    </div>
    {cases.some(c => c.id.startsWith('agent-')) && <label className="v2-picker">Recorded v2 bundle <select
      value={selected.startsWith('bundle-') ? '' : selected} onChange={e => { if (e.target.value) select(e.target.value); }}>
      <option value="" disabled>Choose a recording</option>
      <optgroup label="Published agent runs">{cases.filter(c => c.id.startsWith('agent-')).map(c => <option key={c.id} value={c.id}>{c.label}</option>)}</optgroup>
      <optgroup label="Published lab bundles">{cases.filter(c => c.id.startsWith('lab-')).map(c => <option key={c.id} value={c.id}>{c.label}</option>)}</optgroup>
    </select></label>}
    <div className="receipt-picker" role="group" aria-label="Recorded verification results">
      {[false, true].map(enabled => {
        const verdict = recordedVerdict(verdicts[selected]?.[enabled ? 'with' : 'without']);
        return <button type="button" key={String(enabled)} aria-pressed={receipts === enabled} onClick={() => setReceipts(enabled)}>
          <span>{enabled ? 'With receipts' : 'Without receipts'}</span><StatusPill value={verdict.label} fresh={verdict.trusted} />
        </button>;
      })}
    </div>
  </div>;
}
