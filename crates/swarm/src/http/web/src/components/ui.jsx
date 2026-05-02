import React from 'react';

export function EmptyState({ glyph = '∅', title, children, actions = null, className = '' }) {
  return (
    <div className={`ui-empty ${className}`.trim()}>
      <div className="ui-empty-glyph" aria-hidden="true">{glyph}</div>
      <div className="ui-empty-title">{title}</div>
      {children ? <div className="ui-empty-body muted small">{children}</div> : null}
      {actions ? <div className="ui-empty-actions">{actions}</div> : null}
    </div>
  );
}

export function Pager({
  label,
  canPrev,
  canNext,
  onPrev,
  onNext,
  disabled = false,
  prevLabel = '‹ prev',
  nextLabel = 'next ›',
  className = '',
}) {
  return (
    <div className={`ui-pager ${className}`.trim()}>
      <button
        type="button"
        className="btn btn-ghost btn-sm"
        onClick={onPrev}
        disabled={disabled || !canPrev}
      >
        {prevLabel}
      </button>
      <span className="muted small">{label}</span>
      <button
        type="button"
        className="btn btn-ghost btn-sm"
        onClick={onNext}
        disabled={disabled || !canNext}
      >
        {nextLabel}
      </button>
    </div>
  );
}
