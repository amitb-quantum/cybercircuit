export function UnknownBanner({ errors }: { errors?: Record<string, string | null | undefined> }) {
  const entries = Object.entries(errors ?? {}).filter(([, v]) => v);
  if (!entries.length) return null;
  return <div className="unknown-banner" role="status"><strong>UNKNOWN</strong>{entries.map(([key, value]) => <span key={key}>{key}: {value}</span>)}</div>;
}
