/* global window, ForensicUtils */
'use strict';

class FileValidator {
  constructor(config = {}) {
    this.maxFiles = config.maxFiles ?? 100;
    this.maxSizeBytes = config.maxSizeBytes ?? 5 * 1024 * 1024 * 1024;
    this.allowedExtensions = new Set(
      (config.allowedExtensions || []).map((e) => e.toLowerCase().replace(/^\./, '')),
    );
  }

  static async loadFromAPI(api, path = 'api/config') {
    try {
      const cfg = await api.get(path);
      return new FileValidator(cfg);
    } catch {
      return new FileValidator();
    }
  }

  ext(name) {
    const p = (name || '').split('.');
    return p.length > 1 ? p.pop().toLowerCase() : '';
  }

  validateFile(file) {
    const errors = [];
    const ext = this.ext(file.name);
    if (this.allowedExtensions.size && ext && !this.allowedExtensions.has(ext)) {
      errors.push(`Extension « .${ext} » non autorisée`);
    }
    if (file.size > this.maxSizeBytes) {
      errors.push(`Taille max ${ForensicUtils.sz(this.maxSizeBytes)} dépassée`);
    }
    if (file.size === 0) errors.push(i18n.t('msg.fichier_vide'));
    return { valid: errors.length === 0, errors, ext };
  }

  validateQueue(files) {
    const results = files.map((f) => ({ file: f, ...this.validateFile(f) }));
    const invalid = results.filter((r) => !r.valid);
    if (files.length > this.maxFiles) {
      return {
        valid: false,
        results,
        globalError: `Maximum ${this.maxFiles} fichiers par envoi`,
      };
    }
    return {
      valid: invalid.length === 0,
      results,
      globalError: invalid.length
        ? `${invalid.length} fichier(s) invalide(s)`
        : null,
    };
  }
}

window.FileValidator = FileValidator;
