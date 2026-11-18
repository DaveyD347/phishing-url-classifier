import { getSettings, saveSettings } from '../lib/settings.js';
import { renderAnalysis } from './render.js';

const api = globalThis.browser ?? globalThis.chrome;

const currentEl = document.getElementById('current-result');
const trustBtn = document.getElementById('trust');
const form = document.getElementById('check-form');
const input = document.getElementById('check-input');
const checkEl = document.getElementById('check-result');

document.getElementById('options').addEventListener('click', (e) => {
  e.preventDefault();
  api.runtime.openOptionsPage();
});

async function showCurrentTab() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) {
    currentEl.innerHTML = '<p class="muted">No page to check.</p>';
    return;
  }
  const analysis = await api.runtime.sendMessage({ type: 'get-tab-analysis', tabId: tab.id, url: tab.url });
  renderAnalysis(currentEl, analysis);

  if (analysis && (analysis.verdict === 'suspicious' || analysis.verdict === 'dangerous') && analysis.registrable) {
    trustBtn.hidden = false;
    trustBtn.textContent = `Trust ${analysis.registrable}`;
    trustBtn.onclick = async () => {
      const settings = await getSettings();
      await saveSettings({ allowlist: [...new Set([...settings.allowlist, analysis.registrable])] });
      trustBtn.hidden = true;
      renderAnalysis(currentEl, await api.runtime.sendMessage({ type: 'rescore-tab', tabId: tab.id, url: tab.url }));
    };
  }
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  let value = input.value.trim();
  if (!value) return;
  if (!/^[a-z][a-z0-9+.-]*:/i.test(value)) value = `https://${value}`;
  checkEl.innerHTML = '<p class="muted">Checking…</p>';
  renderAnalysis(checkEl, await api.runtime.sendMessage({ type: 'analyze-url', url: value }));
});

(async () => {
  const settings = await getSettings();
  document.getElementById('age-note').textContent = settings.domainAgeLookup
    ? 'Domain-age lookup is on (only the domain name is sent to rdap.org).'
    : 'Everything is scored on your device. Domain-age lookup is off; turn it on in Settings.';
  await showCurrentTab();
})();
