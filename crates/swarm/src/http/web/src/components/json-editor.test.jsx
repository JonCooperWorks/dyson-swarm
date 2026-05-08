import { afterEach, describe, expect, test, vi } from 'vitest';
import React from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';

import { JsonEditor } from './json-editor.jsx';

afterEach(() => cleanup());

function ControlledEditor(props) {
  const [value, setValue] = React.useState(props.value || '');
  React.useImperativeHandle(props.captureRef, () => ({ value }));
  return <JsonEditor {...props} value={value} onChange={setValue}/>;
}

describe('JsonEditor', () => {
  test('renders the textarea with the given value', () => {
    render(<JsonEditor value='{"ok":true}' onChange={() => {}} ariaLabel="json"/>);

    expect(screen.getByLabelText('json')).toHaveValue('{"ok":true}');
  });

  test('prettyOnBlur rewrites valid JSON to canonical formatting', () => {
    const captureRef = React.createRef();
    render(<ControlledEditor value='{"a":1,"b":[2]}' ariaLabel="json" captureRef={captureRef}/>);

    fireEvent.blur(screen.getByLabelText('json'));

    expect(screen.getByLabelText('json')).toHaveValue('{\n  "a": 1,\n  "b": [\n    2\n  ]\n}');
    expect(captureRef.current.value).toContain('\n  "a": 1');
    expect(screen.getByText('valid JSON')).toHaveClass('json-editor-status-ok');
  });

  test('malformed JSON shows a parse error and does not pretty-print', () => {
    render(<ControlledEditor value='{ broken' ariaLabel="json"/>);

    fireEvent.blur(screen.getByLabelText('json'));

    expect(screen.getByLabelText('json')).toHaveValue('{ broken');
    expect(screen.getByText(/^parse error:/)).toHaveClass('json-editor-status-error');
  });

  test('validate returning false shows the red message', () => {
    render(
      <ControlledEditor
        value='{"skills":{}}'
        ariaLabel="json"
        validate={() => ({ ok: false, message: 'missing skills[] array' })}
      />,
    );

    fireEvent.blur(screen.getByLabelText('json'));

    expect(screen.getByText('missing skills[] array')).toHaveClass('json-editor-status-error');
  });

  test('validate returning true shows the green message', () => {
    render(
      <ControlledEditor
        value='{"skills":[]}'
        ariaLabel="json"
        validate={() => ({ ok: true, message: 'valid (0 skills)' })}
      />,
    );

    fireEvent.blur(screen.getByLabelText('json'));

    expect(screen.getByText('valid (0 skills)')).toHaveClass('json-editor-status-ok');
  });

  test('imperative parse returns parsed value for valid JSON', () => {
    const ref = React.createRef();
    render(<JsonEditor ref={ref} value='{"a":1}' onChange={() => {}} ariaLabel="json"/>);

    expect(ref.current.parse()).toEqual({ ok: true, value: { a: 1 } });
  });

  test('imperative parse returns an error for invalid JSON', () => {
    const ref = React.createRef();
    render(<JsonEditor ref={ref} value='{ broken' onChange={() => {}} ariaLabel="json"/>);

    const result = ref.current.parse();
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/Expected|JSON|property|parse/i);
  });

  test('calls onChange as the textarea changes', () => {
    const onChange = vi.fn();
    render(<JsonEditor value="" onChange={onChange} ariaLabel="json"/>);

    fireEvent.change(screen.getByLabelText('json'), { target: { value: '{"a":1}' } });

    expect(onChange).toHaveBeenCalledWith('{"a":1}');
  });
});
