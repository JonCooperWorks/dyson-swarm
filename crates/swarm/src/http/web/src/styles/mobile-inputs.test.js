import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const layoutCss = readFileSync(join(process.cwd(), 'src/styles/layout.css'), 'utf8');
const panelsCss = readFileSync(join(process.cwd(), 'src/styles/panels.css'), 'utf8');

describe('mobile form controls', () => {
  test('keeps mobile inputs at 16px or larger so iOS does not zoom on focus', () => {
    expect(layoutCss).toMatch(/@media \(max-width: 760px\)[\s\S]*input:not\(\[type\]\)[\s\S]*textarea\s*\{[\s\S]*font-size:\s*16px\s*!important/);
    expect(mobileBlock(layoutCss)).not.toContain(':where(');
    expect(panelsCss).toMatch(/@media \(max-width: 760px\)[\s\S]*\.mcp-json-textarea[\s\S]*font-size:\s*16px\s*!important/);
    expect(panelsCss).toMatch(/@media \(max-width: 760px\)[\s\S]*\.task-verification-input[\s\S]*font-size:\s*16px\s*!important/);
  });
});

describe('section tab highlights', () => {
  test('keeps active detail section borders square', () => {
    expect(panelsCss).toMatch(/\.detail-section-chip\s*\{[\s\S]*border-radius:\s*0;/);
  });
});

describe('activity controls', () => {
  test('use the app control radius rather than pill styling', () => {
    const start = panelsCss.indexOf('/* LLM tool-call activity. */');
    const end = panelsCss.indexOf('/* Detail page metadata + body view. */');
    const activityCss = panelsCss.slice(start, end);

    expect(activityCss).toContain('border-radius: var(--radius)');
    expect(activityCss).not.toMatch(/border-radius:\s*999px/);
  });
});

describe('admin KMS audit layout', () => {
  test('keeps audit rows compact by scrolling horizontally instead of wrapping IDs', () => {
    expect(panelsCss).toMatch(/\.admin-kms-audit-table\s*\{[\s\S]*width:\s*max-content;[\s\S]*min-width:\s*1600px/);
    expect(panelsCss).toMatch(/\.admin-kms-audit-table\s+:is\(th,\s*td\)\s*\{[\s\S]*white-space:\s*nowrap;/);
  });

  test('keeps the wide audit table from expanding the admin page chrome', () => {
    const tabsRule = ruleBody(panelsCss, '.admin-section-tabs');
    const panelRule = ruleBody(panelsCss, '.admin-kms-audit-panel');
    const scrollRule = ruleBody(panelsCss, '.table-scroll');

    expect(tabsRule).toContain('min-width: 0');
    expect(tabsRule).toContain('max-width: 100%');
    expect(panelRule).toContain('min-width: 0');
    expect(panelRule).toContain('max-width: 100%');
    expect(scrollRule).toContain('max-width: 100%');
    expect(scrollRule).toContain('overflow-x: auto');
  });
});

function mobileBlock(css) {
  const match = css.match(/@media \(max-width: 760px\)\s*\{([\s\S]*?)\n\}/);
  return match?.[1] || '';
}

function ruleBody(css, selector) {
  const start = css.indexOf(`${selector} {`);
  if (start < 0) return '';
  const bodyStart = css.indexOf('{', start) + 1;
  const bodyEnd = css.indexOf('}', bodyStart);
  return css.slice(bodyStart, bodyEnd);
}
