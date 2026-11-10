export function KeyHelp({ close }: { close: () => void }) {
  return <div className="key-help" role="dialog" aria-modal="true" aria-label="Keyboard shortcuts">
    <div className="panel"><h2>Keyboard shortcuts</h2>
      <dl>{[['g o', 'Overview'], ['g a', 'Activity'], ['g t', 'Trip detail'], ['g e', 'Evidence'], ['g r', 'Reset screen'],
        ['j / k', 'Move between rows'], ['Enter', 'Open selected row'], ['Esc', 'Close detail or help'], ['/', 'Focus filter'], ['p', 'Pause activity'],
        ['c', 'Copy selected redacted record'], ['Ctrl+K', 'Open command palette'], ['?', 'Show shortcuts']].map(([key, text]) => <div key={key}><dt><kbd>{key}</kbd></dt><dd>{text}</dd></div>)}</dl>
      <button autoFocus type="button" onClick={close}>Close</button>
    </div>
  </div>;
}
