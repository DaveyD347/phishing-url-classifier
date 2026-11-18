// Domain-age lookup over RDAP (the JSON successor to WHOIS).
//
// Only used when the user turns on "Look up domain age" in the options. The
// only thing sent is the registrable domain name (e.g. "example.com"), never
// the full URL, path or query string. Results are cached for 7 days.

const api = globalThis.browser ?? globalThis.chrome;

const RDAP_BOOTSTRAP = 'https://rdap.org/domain/';
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const TIMEOUT_MS = 4000;
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Extracts the registration date from an RDAP domain response.
 * @param {object} rdap Parsed RDAP JSON.
 * @returns {Date|null}
 */
export function parseRegistrationDate(rdap) {
  const events = Array.isArray(rdap?.events) ? rdap.events : [];
  const reg = events.find((e) => e?.eventAction === 'registration');
  if (!reg?.eventDate) return null;
  const date = new Date(reg.eventDate);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** Whole days between `date` and `now`. */
export function ageInDays(date, now = new Date()) {
  return Math.max(0, Math.floor((now.getTime() - date.getTime()) / DAY_MS));
}

/**
 * Returns the age of `domain` in days, or null if it cannot be determined.
 * @param {string} domain Registrable domain, e.g. "example.com".
 */
export async function lookupDomainAgeDays(domain) {
  const cacheKey = `rdap:${domain}`;
  const cached = (await api.storage.local.get(cacheKey))[cacheKey];
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
    return cached.registered ? ageInDays(new Date(cached.registered)) : null;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let registered = null;
  try {
    const res = await fetch(RDAP_BOOTSTRAP + encodeURIComponent(domain), {
      signal: controller.signal,
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      headers: { Accept: 'application/rdap+json, application/json' },
    });
    if (res.ok) registered = parseRegistrationDate(await res.json());
  } catch {
    return null; // network error or timeout: don't cache, try again next time
  } finally {
    clearTimeout(timer);
  }

  await api.storage.local.set({
    [cacheKey]: { registered: registered?.toISOString() ?? null, fetchedAt: Date.now() },
  });
  return registered ? ageInDays(registered) : null;
}
