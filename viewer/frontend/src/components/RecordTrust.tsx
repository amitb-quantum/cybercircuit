import { Icon } from './Icon';
import type { recordedVerdict } from '../data/verdict';

export function RecordTrust({ verdict }: { verdict: ReturnType<typeof recordedVerdict> }) {
  if (verdict.label === 'VALID') return null;
  if (verdict.label === 'VALID, INCOMPLETE') {
    return <div className="record-trust amber" role="note">
      <Icon name="warn" /><div><strong>Verification is incomplete.</strong><p>{verdict.detail}</p></div>
    </div>;
  }
  return <div className={`record-trust ${verdict.label === 'INVALID' ? 'red' : 'amber'}`} role="note">
    <Icon name="warn" /><div><strong>{verdict.label === 'INVALID' ? 'These records failed verification.' : verdict.label === 'NOT VERIFIED' ? 'These records were not verified.' : 'Verification status is UNKNOWN.'}</strong>
      {' '}Treat them as claims, not facts.{verdict.label === 'UNKNOWN' && <p>{verdict.detail}</p>}</div>
  </div>;
}
