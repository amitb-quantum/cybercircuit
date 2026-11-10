import type { ReactNode } from 'react';

const glyphs: Record<string, ReactNode> = {
  grid: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
  activity: <path d="M2 12h5l3-8 4 16 3-8h5"/>,
  bolt: <path d="m13 2-9 12h7l-1 8 10-12h-7l1-8z"/>,
  chain: <><path d="m10 13 4-4m-7 7-2 2a3 3 0 0 0 4 4l5-5a3 3 0 0 0 0-4m3-5 2-2a3 3 0 0 0-4-4l-5 5a3 3 0 0 0 0 4" transform="translate(0 -1)"/></>,
  reset: <path d="M4 11a8 8 0 1 1 1.5 6.5M4 4v7h7"/>,
  shield: <path d="M12 22S4 18 4 11V5l8-3 8 3v6c0 7-8 11-8 11Z"/>,
  stack: <path d="m12 3 9 5-9 5-9-5 9-5Zm-9 9 9 5 9-5M3 16l9 5 9-5"/>,
  receipt: <path d="M5 3h14v18l-3-2-4 2-4-2-3 2V3Zm3 5h8m-8 4h8m-8 4h4"/>,
  bell: <><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9m-8 12a2 2 0 0 0 4 0"/></>,
  check: <path d="m5 12 5 5L20 7"/>,
  cross: <path d="m6 6 12 12M18 6 6 18"/>,
  minus: <path d="M5 12h14"/>,
  warn: <><path d="M10.2 4.8 2.7 18a1.5 1.5 0 0 0 1.3 2.2h16a1.5 1.5 0 0 0 1.3-2.2L13.8 4.8a2.1 2.1 0 0 0-3.6 0Z"/><path d="M12 9v4m0 3h.01"/></>,
  search: <><circle cx="10.5" cy="10.5" r="5.5"/><path d="m15 15 5 5"/></>,
  arrow: <path d="M4 12h15m-6-6 6 6-6 6"/>,
  clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
};

export function Icon({ name, size = 16 }: { name: string; size?: number }) {
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75"
    strokeLinecap="round" strokeLinejoin="round" focusable="false">{glyphs[name] ?? glyphs.minus}</svg>;
}
