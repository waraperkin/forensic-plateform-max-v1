'use strict';

const axios = require('axios');

const VR_BRIDGE_URL = (process.env.VR_BRIDGE_URL || 'http://velociraptor-bridge:8097').replace(/\/$/, '');
const VR_UI_URL = process.env.VELOCIRAPTOR_UI_URL || '/velociraptor/';
const ENABLED = process.env.VELOCIRAPTOR_ENABLED !== 'false';

async function velociraptorHealth() {
  if (!ENABLED) return { ok: false, enabled: false };
  try {
    // Bridge health peut dépasser 5s sous charge (GUI probe) — timeout trop bas → faux DOWN.
    const r = await axios.get(`${VR_BRIDGE_URL}/health`, { timeout: 15000, validateStatus: () => true });
    const bridgeOk = r.status === 200 && r.data?.ok !== false;
    // GUI peut répondre 401 (auth requise) : considéré sain si bridge ok
    const gui = r.data?.velociraptor || {};
    const guiOk = gui.ok !== false || [200, 401, 403].includes(Number(gui.status));
    return { ok: bridgeOk && guiOk, enabled: true, ...r.data };
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
