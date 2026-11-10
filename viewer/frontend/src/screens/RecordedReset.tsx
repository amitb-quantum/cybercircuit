import type { Adapter, Overview } from '../data/types';

export function Reset(_: { adapter: Adapter; data: Overview; connected: boolean }) {
  return <section aria-label="Reset"><h1>Reset</h1><div className="panel">
    <p>Reset is an operator action on the gateway host: <code>circuitbreaker reset --project DIR "reason"</code></p>
  </div></section>;
}
