'use strict';

const MAX_FILES = parseInt(process.env.UPLOAD_MAX_FILES || '100', 10);
const MAX_SIZE_BYTES = parseInt(
  process.env.UPLOAD_MAX_SIZE_BYTES || process.env.CERT_PORTAL_UPLOAD_MAX_SIZE || String(5 * 1024 * 1024 * 1024),
  10,
);

const ALLOWED_EXTENSIONS = [
  'evtx', 'evt', 'log', 'syslog', 'plaso', 'csv', 'jsonl', 'tsv', 'json',
  'pcap', 'pcapng', 'cap', 'pdf', 'docx', 'xlsx', 'gz', 'zip', 'txt', 'xml',
  'stix', 'bin', 'e01', 'dump', 'db', 'out',
];

function getUploadConfig() {
  return {
    maxFiles: MAX_FILES,
    maxSizeBytes: MAX_SIZE_BYTES,
    maxSizeLabel: formatBytes(MAX_SIZE_BYTES),
    allowedExtensions: ALLOWED_EXTENSIONS,
  };
}

function formatBytes(b) {
  if (b >= 1e9) return `${(b / 1e9).toFixed(1)} GB`;
  if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB`;
  if (b >= 1e3) return `${(b / 1e3).toFixed(1)} KB`;
  return `${b} B`;
}

module.exports = { MAX_FILES, MAX_SIZE_BYTES, ALLOWED_EXTENSIONS, getUploadConfig };
