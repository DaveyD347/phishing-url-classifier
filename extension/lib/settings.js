// User settings, stored in storage.sync so they follow the browser profile.

const api = globalThis.browser ?? globalThis.chrome;

export const DEFAULT_SETTINGS = Object.freeze({
  // Off by default: looking up a domain's age means sending that domain name
  // to rdap.org, and this extension sends nothing anywhere unless you opt in.
  domainAgeLookup: false,
  highlightLinks: true,
  warnOnDangerous: true,
  allowlist: [],
});

export async function getSettings() {
  const stored = await api.storage.sync.get(DEFAULT_SETTINGS);
  return { ...DEFAULT_SETTINGS, ...stored };
}

export async function saveSettings(patch) {
  await api.storage.sync.set(patch);
}

/** Normalises user input like "https://Example.com/path" to "example.com". */
export function normaliseDomain(input) {
  const trimmed = String(input).trim().toLowerCase();
  if (!trimmed) return '';
  try {
    return new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`).hostname.replace(/^www\./, '');
  } catch {
    return '';
  }
}
