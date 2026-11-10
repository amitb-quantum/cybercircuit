import data from '../../../demo/results/data.json';
import type { Adapter, Evidence, Overview, Row, Trip, Verify } from './types';

type Case = { label: string; overview: Overview; decision: Row[]; control: Row[]; trips: Record<string, Trip>;
  evidence: Evidence; results: Record<string, Verify> };
const cases = data as unknown as Record<string, Case>;
function bundle(id: string) {
  const value = cases[id];
  if (!value) throw new Error('Recorded public bundle unavailable');
  return value;
}

export const adapter: Adapter = {
  demo: true,
  cases: Object.entries(cases).map(([id, c]) => ({ id, label: c.label })),
  overview: async (id) => bundle(id).overview,
  rows: async (id, source, after) => {
    const rows = bundle(id)[source].filter(row => row.sequence > after);
    return { run: id, phase: 'recorded', rows: rows.slice(0, 500), more: rows.length > 500 };
  },
  trip: async (id, seq) => {
    const trip = bundle(id).trips[String(seq)];
    if (!trip) throw new Error('Trip was not recorded in this bundle');
    return trip;
  },
  evidence: async (id) => bundle(id).evidence,
  verify: async (id, _, receipts) => bundle(id).results[receipts ? 'with' : 'without'],
};
