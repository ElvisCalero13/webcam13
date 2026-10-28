'use strict';

const fs = require('node:fs');
const path = require('node:path');

const ENV_FILE = path.join(__dirname, '.env');

function loadLocalEnv() {
  if (!fs.existsSync(ENV_FILE)) return;
  const text = fs.readFileSync(ENV_FILE, 'utf8');
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!match || match[1].startsWith('#') || process.env[match[1]] !== undefined) continue;
    let value = match[2];
    if (value.length >= 2 && ((value[0] === '"' && value.at(-1) === '"')
        || (value[0] === "'" && value.at(-1) === "'"))) {
      value = value.slice(1, -1);
    }
    process.env[match[1]] = value;
  }
}

loadLocalEnv();

function getCameraCredentials() {
  return { account: process.env.HDCAMERA_ACCOUNT || 'admin',
    password: process.env.HDCAMERA_PASSWORD || '' };
}

module.exports = { getCameraCredentials };
