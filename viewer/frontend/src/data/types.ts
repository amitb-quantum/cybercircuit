export type Dict = Record<string, any>;
export type Source = 'decision' | 'control';
export type Label = 'PROVISIONAL' | 'VERIFIED' | 'MISMATCH' | 'AS STORED';
export interface Row {
  source: Source; sequence: number; hash: string; previous: string; label: Label;
  wall_ms: number | null; wall_source: string | null; raw: Dict;
  event: string; reason?: string | null; outcome?: string | null;
  tick?: number | null; epoch?: number | null; state?: string | null; tool?: string | null; resource_digest?: string | null;
}
export interface Page { run: string | null; phase: string | null; rows: Row[]; more: boolean; error?: string | null }
export interface Overview extends Dict {
  run: string | null; phase: string | null; project: string | null; process: string; state: string | null;
  epoch: number | null; read_age: number; healthy_read: boolean; errors: Record<string, string>; reset_reasons: string[];
}
export interface Trip extends Dict { trip: Row; risk: Row | null; effects: Row[]; leading: Row[]; resets: Dict[]; errors: Record<string, string> }
export interface Verify extends Dict { verdict: string; stdout?: string; exit_code?: number; checks: { name: string; status: string }[] }
export interface Evidence extends Dict { bundles: { name: string; created_ms?: number; files: Record<string, string>; error?: string }[]; errors: Record<string, string>; more?: boolean }
export type Event = 'decision' | 'control' | 'status' | 'stale';
export interface Adapter {
  demo: boolean;
  cases: { id: string; label: string }[];
  overview(id: string): Promise<Overview>;
  rows(id: string, source: Source, after: number): Promise<Page>;
  trip(id: string, sequence: number): Promise<Trip>;
  evidence(id: string, name?: string, after?: number): Promise<Evidence>;
  verify(id: string, name: string, receipts: boolean): Promise<Verify>;
  reset?: (reason: string) => Promise<Dict>;
  stream?: (event: (type: Event, data: Dict) => void, signal: AbortSignal) => Promise<void>;
}
