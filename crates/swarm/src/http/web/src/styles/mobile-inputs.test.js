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
  test('admin overview uses a bounded dashboard grid', () => {
    const summaryRule = ruleBody(panelsCss, '.admin-overview-summary');
    const gridRule = ruleBody(panelsCss, '.admin-overview-grid');
    const linksRule = ruleBody(panelsCss, '.admin-section-links');

    expect(summaryRule).toContain('width: min(100%, 1180px)');
    expect(gridRule).toContain('grid-template-columns: minmax(0, 1fr) minmax(280px, 340px)');
    expect(gridRule).toContain('width: min(100%, 1180px)');
    expect(linksRule).toContain('grid-template-columns: repeat(3, minmax(0, 1fr))');
  });

  test('caps normal admin section panels so forms do not stretch across wide screens', () => {
    const sectionPageRule = ruleBody(panelsCss, '.admin-section-page');
    const sectionPanelRule = ruleBody(panelsCss, '.admin-section-page > .panel');
    const kmsSectionRule = ruleBody(panelsCss, '.admin-section-page-kms-audit > .admin-kms-audit-panel');

    expect(sectionPageRule).toContain('align-items: flex-start');
    expect(sectionPanelRule).toContain('width: min(100%, 1180px)');
    expect(kmsSectionRule).toContain('width: min(100%, 1320px)');
  });

  test('does not vertically clip admin section tabs', () => {
    const tabsRule = ruleBody(panelsCss, '.admin-section-tabs');
    const linkRule = ruleBody(panelsCss, '.admin-section-tabs a');

    expect(tabsRule).toContain('overflow-y: visible');
    expect(tabsRule).toContain('min-height: calc(var(--control-height) + 4px)');
    expect(linkRule).toContain('display: inline-flex');
    expect(linkRule).toContain('min-height: var(--control-height)');
  });

  test('renders audit events as a labelled list instead of a crowded spreadsheet', () => {
    const tableRule = ruleBody(panelsCss, '.admin-kms-audit-table');
    const cellRule = ruleBody(panelsCss, '.admin-kms-audit-table :is(th, td)');
    const rowRule = ruleBody(panelsCss, '.admin-kms-audit-table tr');

    expect(tableRule).toContain('width: 100%');
    expect(tableRule).toContain('display: block');
    expect(rowRule).toContain('grid-template-columns: repeat(4, minmax(0, 1fr))');
    expect(cellRule).toContain('white-space: normal');
    expect(cellRule).toContain('overflow-wrap: anywhere');
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

  test('uses record tables with grouped actions on admin section pages', () => {
    const tableRule = ruleBody(panelsCss, '.admin-record-table');
    const actionRule = ruleBody(panelsCss, '.admin-row-action-group');
    const mobileRule = mediaRuleBody(panelsCss, '@media (max-width: 640px)', '.admin-record-table');

    expect(tableRule).toContain('table-layout: fixed');
    expect(tableRule).toContain('border-radius: var(--radius)');
    expect(actionRule).toContain('display: flex');
    expect(actionRule).toContain('flex-wrap: wrap');
    expect(mobileRule).toContain('border: 0');
    expect(mobileRule).toContain('background: transparent');
  });
});

function mobileBlock(css) {
  const match = css.match(/@media \(max-width: 760px\)\s*\{([\s\S]*?)\n\}/);
  return match?.[1] || '';
}

function ruleBody(css, selector) {
  const match = new RegExp(`(?:^|\\n)${escapeRegExp(selector)}\\s*\\{`).exec(css);
  if (!match) return '';
  const bodyStart = css.indexOf('{', match.index) + 1;
  const bodyEnd = css.indexOf('}', bodyStart);
  return css.slice(bodyStart, bodyEnd);
}

function mediaRuleBody(css, mediaSelector, selector) {
  const mediaStart = css.indexOf(mediaSelector);
  if (mediaStart === -1) return '';
  const ruleStart = css.indexOf(selector, mediaStart);
  if (ruleStart === -1) return '';
  const bodyStart = css.indexOf('{', ruleStart) + 1;
  const bodyEnd = css.indexOf('}', bodyStart);
  return css.slice(bodyStart, bodyEnd);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
