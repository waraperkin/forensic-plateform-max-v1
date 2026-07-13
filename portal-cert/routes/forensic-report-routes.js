'use strict';

const express = require('express');
const {
  REPORTS_INDEX,
  DEFAULT_TEMPLATES,
  collectEvidence,
  buildReportDraft,
  renderReportHtml,
  renderReportMarkdown,
} = require('../lib/forensic-report-engine');
const {
  checkLlmHealth,
  enrichSection,
  enrichFullReport,
  llmConfigured,
} = require('../lib/forensic-report-llm');

function createForensicReportRoutes({ os, logger }) {
  const router = express.Router();
  const INCIDENTS_INDEX = 'forensic-portal-incidents';

  async function osGetIncident(id) {
    try {
      const r = await os.get({ index: `${INCIDENTS_INDEX}*`, id });
      return { id: r.body._id, ...r.body._source };
    } catch {
      const sr = await os.search({
        index: `${INCIDENTS_INDEX}*`,
        body: { size: 1, query: { ids: { values: [id] } } },
      });
      const hit = sr.body.hits?.hits?.[0];
      return hit ? { id: hit._id, ...hit._source } : null;
    }
  }

  async function saveReport(report) {
    const id = report.id;
    await os.index({
      index: REPORTS_INDEX,
      id,
      body: {
        ...report,
        '@timestamp': report.generated_at || new Date().toISOString(),
        tags: ['fp-master', 'forensic-report', 'portal-cert'],
      },
      refresh: true,
    });
    return report;
  }

  async function getReport(id) {
    try {
      const r = await os.get({ index: REPORTS_INDEX, id });
      return { id: r.body._id, ...r.body._source };
    } catch {
      return null;
    }
  }

  async function listReports(caseId) {
    const q = caseId
      ? { term: { 'case_id.keyword': caseId } }
      : { match_all: {} };
    const r = await os.search({
      index: REPORTS_INDEX,
      ignore_unavailable: true,
      body: {
        size: 50,
        sort: [{ generated_at: { order: 'desc', unmapped_type: 'date' } }, { '@timestamp': { order: 'desc' } }],
        query: q,
      },
    }).catch(() => ({ body: { hits: { hits: [] } } }));
    return (r.body.hits?.hits || []).map((h) => {
      const s = h._source || {};
      return {
        id: h._id,
        title: s.title,
        case_id: s.case_id,
        incident_id: s.incident_id,
        status: s.status,
        generated_at: s.generated_at,
        generated_by: s.generated_by,
        template_id: s.template_id,
        metadata: s.metadata,
      };
    });
  }

  router.get('/reports/templates', (_req, res) => {
    res.json({ templates: DEFAULT_TEMPLATES });
  });

  router.get('/reports/llm/status', async (_req, res) => {
    const status = await checkLlmHealth();
    res.json({ ...status, configured: llmConfigured() });
  });

  router.get('/reports', async (req, res) => {
    try {
      const reports = await listReports(req.query.case_id);
      res.json(reports);
    } catch (e) {
      logger.warn('reports list:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  router.get('/reports/:id', async (req, res) => {
    const report = await getReport(req.params.id);
    if (!report) return res.status(404).json({ error: 'Rapport introuvable' });
    res.json(report);
  });

  router.post('/reports/collect', async (req, res) => {
    try {
      const { case_id: caseId, incident_id: incidentId } = req.body || {};
      let incident = null;
      if (incidentId) incident = await osGetIncident(incidentId);
      const cid = caseId || incident?.case_id;
      if (!cid) return res.status(400).json({ error: 'case_id ou incident_id requis' });
      const evidence = await collectEvidence(os, { caseId: cid, incident });
      res.json({ ok: true, evidence });
    } catch (e) {
      logger.warn('reports collect:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  router.post('/reports/generate', async (req, res) => {
    try {
      const body = req.body || {};
      const {
        case_id: caseId,
        incident_id: incidentId,
        template_id: templateId,
        title,
        custom_sections: customSections,
        custom_blocks: customBlocks,
        enrich_ai: enrichAi,
        enrich_sections: enrichSections,
        language,
      } = body;

      let incident = null;
      if (incidentId) incident = await osGetIncident(incidentId);
      const cid = caseId || incident?.case_id;
      if (!cid) return res.status(400).json({ error: 'case_id ou incident_id requis' });

      const evidence = await collectEvidence(os, { caseId: cid, incident });
      evidence.incident = incident;

      let report = buildReportDraft(evidence, {
        incident,
        templateId,
        customSections,
        customBlocks,
        analyst: req.user?.username || body.analyst || 'cert-analyst',
        title,
      });

      if (enrichAi) {
        report = await enrichFullReport(report, {
          sections: enrichSections,
          language: language || 'fr',
        });
      }

      await saveReport(report);
      res.json({ ok: true, report });
    } catch (e) {
      logger.error('reports generate:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  router.put('/reports/:id', async (req, res) => {
    try {
      const existing = await getReport(req.params.id);
      if (!existing) return res.status(404).json({ error: 'Rapport introuvable' });
      const {
        title, status, sections, custom_blocks: customBlocks,
      } = req.body || {};
      const updated = {
        ...existing,
        title: title ?? existing.title,
        status: status ?? existing.status,
        sections: sections ? { ...existing.sections, ...sections } : existing.sections,
        custom_blocks: customBlocks ?? existing.custom_blocks,
        updated_at: new Date().toISOString(),
        updated_by: req.user?.username || 'cert-analyst',
      };
      await saveReport(updated);
      res.json({ ok: true, report: updated });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  router.post('/reports/:id/enrich', async (req, res) => {
    try {
      const report = await getReport(req.params.id);
      if (!report) return res.status(404).json({ error: 'Rapport introuvable' });
      const { section_key: sectionKey, language } = req.body || {};
      if (!sectionKey || !report.sections?.[sectionKey]) {
        return res.status(400).json({ error: 'section_key invalide' });
      }
      const r = await enrichSection(sectionKey, {
        evidence: report.evidence_snapshot,
        incident: report.evidence_snapshot?.incident,
        section: report.sections[sectionKey],
        language: language || 'fr',
      });
      report.sections[sectionKey] = {
        ...report.sections[sectionKey],
        content: r.content,
        source: r.source,
      };
      report.metadata = {
        ...(report.metadata || {}),
        llm_used: r.source === 'ollama' || report.metadata?.llm_used,
        last_enrich: sectionKey,
      };
      await saveReport(report);
      res.json({ ok: true, section: report.sections[sectionKey], llm: r });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  router.get('/reports/:id/export', async (req, res) => {
    const report = await getReport(req.params.id);
    if (!report) return res.status(404).json({ error: 'Rapport introuvable' });
    const fmt = String(req.query.format || 'html').toLowerCase();
    const safeName = String(report.case_id || report.id).replace(/[^\w.-]+/g, '_');

    if (fmt === 'md' || fmt === 'markdown') {
      res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="rapport-${safeName}.md"`);
      return res.send(renderReportMarkdown(report));
    }
    if (fmt === 'json') {
      return res.json(report);
    }
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="rapport-${safeName}.html"`);
    res.send(renderReportHtml(report));
  });

  router.delete('/reports/:id', async (req, res) => {
    try {
      await os.delete({ index: REPORTS_INDEX, id: req.params.id, refresh: true });
      res.json({ ok: true, deleted: req.params.id });
    } catch (e) {
      if (e.meta?.statusCode === 404) return res.status(404).json({ error: 'Rapport introuvable' });
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = { createForensicReportRoutes };
