import { getSettings, saveSettings, normaliseDomain } from '../lib/settings.js';

const fields = ['highlightLinks', 'warnOnDangerous', 'domainAgeLookup'];
const allowlistEl = document.getElementById('allowlist');
const statusEl = document.getElementById('status');

async function load() {
  const settings = await getSettings();
  for (const f of fields) document.getElementById(f).checked = Boolean(settings[f]);
  allowlistEl.value = settings.allowlist.join('\n');
}

document.getElementById('save').addEventListener('click', async () => {
  const patch = Object.fromEntries(fields.map((f) => [f, document.getElementById(f).checked]));
  patch.allowlist = [...new Set(allowlistEl.value.split(/\s+/).map(normaliseDomain).filter(Boolean))];
  await saveSettings(patch);
  allowlistEl.value = patch.allowlist.join('\n');
  statusEl.textContent = 'Saved.';
  setTimeout(() => (statusEl.textContent = ''), 2000);
});

load();
