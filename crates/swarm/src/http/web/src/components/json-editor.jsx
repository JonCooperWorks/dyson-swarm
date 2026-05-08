import React from 'react';

/**
 * Reusable JSON textarea with parse-on-blur, pretty-print, and inline status.
 *
 * Props:
 *   value          string, raw textarea contents (parent owns state)
 *   onChange       (next: string) => void
 *   rows           number of textarea rows (default 16)
 *   placeholder    string
 *   disabled       boolean
 *   ariaLabel      string for screen readers
 *   prettyOnBlur   bool, auto JSON.stringify(parsed, null, 2) on blur (default true)
 *   validate       optional (parsed) => { ok: boolean, message?: string }
 *
 * Imperative ref API:
 *   ref.current.parse() => { ok: true, value } | { ok: false, error }
 */
export const JsonEditor = React.forwardRef(function JsonEditor(
  { value, onChange, rows = 16, placeholder, disabled, ariaLabel, prettyOnBlur = true, validate },
  ref,
) {
  const [status, setStatus] = React.useState({ kind: 'idle' });

  const evaluate = React.useCallback((raw) => {
    const trimmed = (raw || '').trim();
    if (!trimmed) return { kind: 'idle' };
    try {
      const parsed = JSON.parse(trimmed);
      if (validate) {
        const result = validate(parsed);
        return result.ok
          ? { kind: 'ok', message: result.message || 'valid JSON', parsed }
          : { kind: 'invalid', message: result.message || 'invalid' };
      }
      return { kind: 'ok', message: 'valid JSON', parsed };
    } catch (err) {
      return { kind: 'parse_error', message: err?.message || 'parse error' };
    }
  }, [validate]);

  React.useImperativeHandle(ref, () => ({
    parse: () => {
      const next = evaluate(value);
      if (next.kind === 'ok') return { ok: true, value: next.parsed };
      return { ok: false, error: next.message || 'invalid JSON' };
    },
  }), [evaluate, value]);

  const handleBlur = () => {
    const next = evaluate(value);
    setStatus(next);
    if (prettyOnBlur && next.kind === 'ok') {
      const pretty = JSON.stringify(next.parsed, null, 2);
      if (pretty !== value) onChange(pretty);
    }
  };

  return (
    <div className="json-editor">
      <textarea
        className="json-editor-textarea"
        value={value}
        rows={rows}
        spellCheck={false}
        placeholder={placeholder}
        disabled={disabled}
        aria-label={ariaLabel}
        onChange={event => onChange(event.target.value)}
        onBlur={handleBlur}
      />
      {status.kind === 'parse_error' ? (
        <div className="json-editor-status json-editor-status-error">
          parse error: {status.message}
        </div>
      ) : status.kind === 'invalid' ? (
        <div className="json-editor-status json-editor-status-error">
          {status.message}
        </div>
      ) : status.kind === 'ok' ? (
        <div className="json-editor-status json-editor-status-ok">
          {status.message}
        </div>
      ) : null}
    </div>
  );
});
