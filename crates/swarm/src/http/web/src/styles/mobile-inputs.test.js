import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const layoutCss = readFileSync(join(process.cwd(), 'src/styles/layout.css'), 'utf8');
const panelsCss = readFileSync(join(process.cwd(), 'src/styles/panels.css'), 'utf8');

describe('mobile form controls', () => {
  test('keeps mobile inputs at 16px or larger so iOS does not zoom on focus', () => {
    expect(layoutCss).toMatch(/@media \(max-width: 700px\)[\s\S]*font-size:\s*16px/);
    expect(panelsCss).toMatch(/@media \(max-width: 700px\)[\s\S]*\.mcp-json-textarea[\s\S]*font-size:\s*16px/);
  });
});
