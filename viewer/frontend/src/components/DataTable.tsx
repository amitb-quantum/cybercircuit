import { useLayoutEffect, useRef, type ReactNode } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';

export interface Column<T> { id: string; title: string; width: number; render: (row: T) => ReactNode }

export function DataTable<T>({ rows, columns, rowKey, selected, focused, onSelect, onTrip, trip, rowTone, label }: {
  rows: T[]; columns: Column<T>[]; rowKey: (row: T) => string; selected?: string; focused?: string;
  onSelect?: (row: T) => void; onTrip?: (row: T) => void; trip?: (row: T) => ReactNode; rowTone?: (row: T) => string; label: string;
}) {
  const parent = useRef<HTMLDivElement>(null);
  const index = focused ? rows.findIndex(row => rowKey(row) === focused) : -1;
  const virtual = useVirtualizer({ count: rows.length, getScrollElement: () => parent.current,
    estimateSize: () => 24, overscan: 12, getItemKey: i => rowKey(rows[i]) });
  const height = virtual.getTotalSize();
  const first = useRef(rows[0] ? rowKey(rows[0]) : '');
  useLayoutEffect(() => {
    const node = parent.current;
    const newFirst = rows[0] ? rowKey(rows[0]) : '';
    if (node && node.scrollTop > 24 && first.current && first.current !== newFirst) {
      const inserted = rows.findIndex(row => rowKey(row) === first.current);
      if (inserted > 0) node.scrollTop += inserted * 24;
    }
    first.current = newFirst;
  }, [rows, rowKey]);
  useLayoutEffect(() => { if (index >= 0) virtual.scrollToIndex(index, { align: 'auto' }); }, [focused]); // keyboard focus only
  const grid = columns.map(c => `${c.width}px`).join(' ');
  return <div className="table-scroll virtual-scroll" ref={parent} tabIndex={0} aria-label={label}>
    <div className="vtable" role="table" aria-label={label} aria-rowcount={rows.length + 1} style={{ minWidth: columns.reduce((a, c) => a + c.width, 0) }}>
      <div className="vhead vrow" role="row" style={{ gridTemplateColumns: grid }}>
        {columns.map(c => <span role="columnheader" key={c.id}>{c.title}</span>)}
      </div>
      <div className="vbody" role="rowgroup" style={{ height }}>
        {virtual.getVirtualItems().map(item => {
          const row = rows[item.index], key = rowKey(row), tripLabel = trip?.(row);
          return <div key={item.key} className={`vrow ${rowTone?.(row) ?? ''} ${selected === key || focused === key ? 'selected' : ''} ${tripLabel ? 'trip-row' : ''}`}
            role="row" aria-rowindex={item.index + 2} aria-selected={onSelect ? selected === key : undefined} data-row={key}
            style={{ gridTemplateColumns: grid, transform: `translateY(${item.start}px)` }} onClick={() => onSelect?.(row)}>
            {tripLabel ? <div role="cell" className="trip-cell"><button type="button" onClick={e => { e.stopPropagation(); onTrip?.(row); }}>{tripLabel}</button></div> :
              columns.map((c, i) => <span role="cell" key={c.id}>
                {i === 0 && onSelect ? <button type="button" className="bare" onClick={e => { e.stopPropagation(); onSelect(row); }}>{c.render(row)}</button> : c.render(row)}
              </span>)}
          </div>;
        })}
      </div>
      {!rows.length && <div className="empty">No matching rows.</div>}
    </div>
  </div>;
}
