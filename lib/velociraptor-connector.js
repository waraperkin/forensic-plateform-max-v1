'use strict';

const axios = require('axios');

const VR_BRIDGE_URL = (process.env.VR_BRIDGE_URL || 'http://velociraptor-bridge:8097').replace(/\/$/, '');
const VR_UI_URL = process.env.VELOCIRAPTOR_UI_URL || '/velociraptor/';
const ENABLED = process.env.VELOCIRAPTOR_ENABLED !== 'false';

async function velociraptorHealth() {
  if (!ENABLED) return { ok: false, enabled: false };
  try {
    const r = await axios.get(`${VR_BRIDGE_URL}/health`, { timeout: 5000, validateStatus: () => true });
    return { ok: r.status === 200 && r.data?.velociraptor?.ok !== false, enabled: true, ...r.data };
  } catch (e) {
    return { ok: false, enabled: true, error: e.message };
  }
}

function isVelociraptorSource(meta = {}) {
  const tags = meta.tags || [];
  return meta.source === 'velociraptor'
    || meta.portal === 'velociraptor'
    || tags.includes('velociraptor')
    || meta.velociraptor === true
    || meta.velociraptor === 'true';
}

module.exports = { velociraptorHealth, isVelociraptorSource, VR_UI_URL, ENABLED };
