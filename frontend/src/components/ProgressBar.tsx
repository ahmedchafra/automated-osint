interface ProgressBarProps {
  value: number; // 0..100
  indeterminate?: boolean;
  label?: string;
}

export function ProgressBar({ value, indeterminate, label }: ProgressBarProps) {
  const safeValue = Math.max(0, Math.min(100, value));
  return (
    <div>
      {label && (
        <div className="flex items-center justify-between mb-2 text-sm">
          <span className="text-gray">{label}</span>
          <span className="text-muted font-mono">{indeterminate ? '...' : `${Math.round(safeValue)}%`}</span>
       </div>
      )}
      <div className="progress" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(safeValue)}>
        <div
          className={`progress-bar${indeterminate ? ' indeterminate' : ''}`}
          style={indeterminate ? undefined : { width: `${safeValue}%` }}
        />
     </div>
   </div>
  );
}
