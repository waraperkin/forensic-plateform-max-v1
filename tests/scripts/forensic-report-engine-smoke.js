'use strict';

const assert = require('assert');
const {
  buildReportDraft,
  renderReportHtml,
  markdownToHtml,
  dedupeEvents,
} = require('../../portal-cert/lib/forensic-report-engine');

const sampleEvidence = {
  case_id: 'CASE-UC06-CLOUD',
  incident: {
    id: 'inc-1',
    title: '[CERT-E2E] CloudTrail AWS - clé IAM compromise',
    severity: 'high',
    status: 'investigating',
    assignee: 'admin',
  },
  stats: {
    events_total: 499,
    uploads_count: 13,
    iocs_count: 2,
    alerts_count: 1,
    hosts: [{ name: 'aws-cloudtrail', count: 120 }],
    source_ips: [{ ip: '198.51.100.201', count: 45 }],
    top_actions: [
      { action: 'CreateAccessKey', count: 30 },
      { action: 'GetObject', count: 12 },
    ],
  },
  uploads: [
    { timestamp: '2026-07-12T13:00:00Z', file: 'cloudtrail.json', portal: 'cert', os_type: 'cloud', analyst: 'admin' },
  ],
  events: dedupeEvents([
    { timestamp: '2026-07-12T13:00:00Z', host: 'aws', source_ip: '198.51.100.201', action: 'CreateAccessKey', message: 'Suspicious IAM access key creation' },
    { timestamp: '2026-07-12T13:00:00Z', host: 'aws', source_ip: '198.51.100.201', action: 'CreateAccessKey', message: 'Suspicious IAM access key creation' },
    { timestamp: '2026-07-12T13:05:00Z', host: 'aws', source_ip: '198.51.100.201', action: 'GetObject', message: 'S3 object access' },
  ]),
  iocs: [{ type: 'ip', value: '198.51.100.201', feed: 'misp', timestamp: '2026-07-12T13:00:00Z' }],
  alerts: [{ rule: 'fp-sigma-cloud-iam', severity: 'high', timestamp: '2026-07-12T13:00:00Z', message: 'IAM key created from suspicious IP' }],
};

const report = buildReportDraft(sampleEvidence, { incident: sampleEvidence.incident, templateId: 'standard-ir' });
assert.ok(report.sections.executive_summary.content.includes('direction'), 'exec summary director-ready');
assert.ok(!report.sections.technical_findings.content.includes('undefined'), 'no undefined counts');
assert.ok(report.sections.timeline.content.includes('| Date/heure'), 'timeline as table');

const html = renderReportHtml(report);
assert.ok(html.includes('<table class="fp-report-table">'), 'HTML tables rendered');
assert.ok(!html.includes('|------|'), 'no raw markdown separators');
assert.ok(html.includes('fp-report-cover'), 'professional cover');
assert.ok(html.indexOf('Synthèse exécutive') < html.indexOf('Chronologie'), 'executive before timeline');

const mdTable = markdownToHtml('| A | B |\n|---|---|\n| 1 | 2 |');
assert.ok(mdTable.includes('<thead>'), 'markdown table thead');
assert.ok(!mdTable.includes('<p>|'), 'no broken table in p tag');

console.log('forensic-report-engine-smoke: OK');
