// Heuristic phishing URL classifier.
//
// Every heuristic returns zero or more "signals". Each signal carries a weight;
// the final score is the capped sum of weights (0-100). The engine is pure and
// synchronous: anything that needs the network (domain age, TLS state) is
// gathered elsewhere and passed in through `context`.

import { BRANDS, OFFICIAL_DOMAINS, MIN_FUZZY_LABEL_LENGTH } from './brands.js';
import {
  splitHost,
  isIpAddress,
  hasObfuscatedIp,
  toUnicode,
  FREE_HOSTING_SUFFIXES,
} from './domain.js';
import { shannonEntropy, editDistance, skeleton, sequenceSkeleton, scriptsUsed } from './text.js';

export const THRESHOLDS = Object.freeze({ suspicious: 25, dangerous: 60 });

// TLDs with consistently high abuse rates in public phishing feeds
// (Spamhaus / Interisle reports). Being on this list is weak evidence on its own.
const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'icu', 'cyou', 'rest',
  'click', 'country', 'kim', 'work', 'support', 'live', 'fit', 'loan', 'men', 'date',
  'review', 'party', 'cam', 'quest', 'sbs', 'cfd', 'bond', 'monster', 'lol', 'today',
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
  'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'bl.ink', 'lnkd.in', 'qrco.de', 's.id',
]);

const PHISHING_KEYWORDS = [
  'login', 'log-in', 'signin', 'sign-in', 'verify', 'verification', 'account', 'secure',
  'security', 'update', 'confirm', 'banking', 'wallet', 'password', 'unlock', 'suspend',
  'suspended', 'billing', 'invoice', 'webscr', 'authenticate', 'recover', 'restore',
  'validate', 'credential', 'support', 'helpdesk', 'reactivate', 'seed', 'airdrop',
];

const RISKY_FILE_EXT = /\.(exe|scr|msi|bat|cmd|js|jse|vbs|vbe|wsf|hta|ps1|jar|apk|iso|img|lnk|zip|rar|7z)$/i;

const NON_WEB_SCHEMES = new Set(['chrome:', 'chrome-extension:', 'moz-extension:', 'about:', 'edge:', 'mailto:', 'tel:', 'view-source:', 'devtools:']);
const DANGEROUS_SCHEMES = new Set(['data:', 'javascript:', 'vbscript:', 'blob:']);

/**
 * @typedef {Object} Signal
 * @property {string} id      Stable identifier, e.g. "typosquat".
 * @property {string} title   Short human-readable label.
 * @property {string} detail  Explanation specific to this URL.
 * @property {number} weight  Contribution to the score.
 *
 * @typedef {Object} Context
 * @property {number|null} [domainAgeDays]  Age of the registrable domain, if known.
 * @property {'secure'|'insecure'|'broken'} [tlsState]  From the browser, if known.
 * @property {boolean} [hasPasswordField]   Page contains a password input.
 * @property {string[]} [allowlist]         User-trusted registrable domains.
 * @property {string} [linkText]            Visible text of the link pointing at this URL.
 *
 * @typedef {Object} Analysis
 * @property {string} url
 * @property {string} host
 * @property {string} displayHost  Unicode form of the host.
 * @property {string} registrable
 * @property {number} score        0-100
 * @property {'safe'|'suspicious'|'dangerous'|'trusted'|'not_applicable'|'invalid'} verdict
 * @property {Signal[]} signals
 */

/** Maps a numeric score to a verdict. */
export function verdictFor(score) {
  if (score >= THRESHOLDS.dangerous) return 'dangerous';
  if (score >= THRESHOLDS.suspicious) return 'suspicious';
  return 'safe';
}

/**
 * Scores a URL for phishing risk.
 * @param {string} rawUrl
 * @param {Context} [context]
 * @returns {Analysis}
 */
export function analyzeUrl(rawUrl, context = {}) {
  const input = String(rawUrl ?? '').trim();
  let url;
  try {
    url = new URL(input);
  } catch {
    return result(input, '', '', 0, 'invalid', []);
  }

  if (NON_WEB_SCHEMES.has(url.protocol)) {
    return result(input, url.hostname, '', 0, 'not_applicable', []);
  }

  if (DANGEROUS_SCHEMES.has(url.protocol)) {
    const signals = [signal('dangerous_scheme', 'Script or inline-document URL',
      `"${url.protocol}" URLs can render a fake login page without any real website behind it.`, 60)];
    return result(input, '', '', 60, 'dangerous', signals);
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return result(input, url.hostname, '', 0, 'not_applicable', []);
  }

  const host = url.hostname.toLowerCase();
  const parts = splitHost(host);
  const allowed = (context.allowlist ?? [])
    .map((d) => String(d).toLowerCase())
    .find((d) => d && (host === d || host.endsWith(`.${d}`)));

  if (allowed || OFFICIAL_DOMAINS.has(parts.registrable)) {
    const why = allowed ? `${allowed} is on your allowlist` : `${parts.registrable} is a known official brand domain`;
    const signals = [signal('trusted', 'Trusted domain', `${why}.`, 0)];
    return result(input, host, parts.registrable, 0, 'trusted', signals);
  }

  const signals = [
    ...checkTransport(input, url, context),
    ...checkHostForm(input, url, host),
    ...checkLookalikes(parts),
    ...checkDomainShape(parts),
    ...checkUrlShape(url, parts),
    ...checkDomainAge(context),
    ...checkLinkText(context.linkText, parts),
  ];

  const score = Math.min(100, signals.reduce((sum, s) => sum + s.weight, 0));
  return result(input, host, parts.registrable, score, verdictFor(score), signals);
}

// ---------------------------------------------------------------------------
// Heuristic groups
// ---------------------------------------------------------------------------

function checkTransport(input, url, context) {
  const out = [];
  if (url.protocol === 'http:') {
    // Routers and home-lab devices on private IPs rarely have certificates.
    const local = isIpAddress(url.hostname) && isPrivateIp(url.hostname) && !hasObfuscatedIp(input);
    out.push(signal('no_https', 'Unencrypted connection',
      'The page is served over plain HTTP, so anything typed into it can be read in transit.', local ? 5 : 15));
    if (context.hasPasswordField) {
      out.push(signal('password_over_http', 'Password form over HTTP',
        'This page asks for a password without encryption. Legitimate login pages never do this.', 25));
    }
  }
  if (context.tlsState === 'broken') {
    out.push(signal('tls_broken', 'Certificate problem',
      'The browser reported an invalid, expired or untrusted TLS certificate for this site.', 40));
  } else if (context.tlsState === 'insecure' && url.protocol === 'https:') {
    out.push(signal('tls_weak', 'Weak TLS', 'The connection uses an outdated or weak TLS configuration.', 10));
  }
  if (url.port && !['80', '443'].includes(url.port)) {
    out.push(signal('nonstandard_port', 'Unusual port',
      `The URL points at port ${url.port}, which normal websites rarely use.`, 10));
  }
  return out;
}

function checkHostForm(input, url, host) {
  const out = [];
  if (hasObfuscatedIp(input)) {
    out.push(signal('obfuscated_ip', 'Disguised IP address',
      'The host is an IP address written in decimal, hex or octal to hide what it is.', 45));
  } else if (isIpAddress(host)) {
    if (isPrivateIp(host)) {
      out.push(signal('local_ip', 'Local network address',
        `${host} is on your local network (a router or home device, for example).`, 5));
    } else {
      out.push(signal('ip_host', 'Raw IP address',
        `The link goes to ${host} instead of a domain name. Real brands use named domains.`, 35));
    }
  }

  if (url.username || url.password) {
    out.push(signal('userinfo', 'Text before "@" in the address',
      `Browsers ignore "${decodeURIComponent(url.username)}@". The real destination is ${host}.`, 30));
  }

  if (host.split('.').some((l) => l.startsWith('xn--'))) {
    const unicodeHost = toUnicode(host);
    const mixed = unicodeHost.split('.').some((l) => scriptsUsed(l).size > 1);
    if (mixed) {
      out.push(signal('mixed_script', 'Mixed alphabets in domain',
        `"${unicodeHost}" (really "${host}") mixes characters from different alphabets, a classic homograph trick.`, 35));
    } else {
      out.push(signal('punycode', 'Internationalised domain',
        `The domain displays as "${unicodeHost}". Check that it is the site you expect.`, 10));
    }
  }
  return out;
}

function checkLookalikes(parts) {
  const out = [];
  const label = toUnicode(parts.label);
  if (!label || isIpAddress(parts.registrable)) return out;

  const labelSkel = skeleton(label);
  const labelSeqSkel = sequenceSkeleton(label);
  const tokens = label.split('-').filter(Boolean);
  const subLabels = parts.subdomain ? toUnicode(parts.subdomain).split('.') : [];

  let typosquatFound = false;
  for (const brand of BRANDS) {
    if (brand.domains.includes(parts.registrable)) continue;
    const b = brand.label;

    // 1. Exact homoglyph match: "paypa1", "pаypal" (Cyrillic а), "arnazon".
    if (!typosquatFound && label !== b && (labelSkel === b || labelSeqSkel === b)) {
      out.push(signal('homoglyph', `Look-alike of ${b}`,
        `"${label}"${label !== parts.label ? ` (really "${parts.label}")` : ''} is visually almost identical to "${b}" but is not an official ${b} domain.`, 60));
      typosquatFound = true;
      continue;
    }

    // 2. Small edit distance: "paypla", "gooogle", "micosoft".
    if (!typosquatFound && b.length >= MIN_FUZZY_LABEL_LENGTH && label !== b) {
      const maxDist = b.length >= 8 ? 2 : 1;
      const d = Math.min(editDistance(label, b), editDistance(labelSkel, b));
      if (d > 0 && d <= maxDist) {
        out.push(signal('typosquat', `Typo-squat of ${b}`,
          `"${parts.registrable}" is ${d} character${d > 1 ? 's' : ''} away from "${b}".`, 40));
        typosquatFound = true;
        continue;
      }
    }

    // 3. Brand combined with other words: "paypal-verify.com", "secure-paypal-login.net".
    if (label !== b && tokens.length > 1 && tokens.some((t) => tokenImitates(t, b))) {
      out.push(signal('brand_combo', `Uses the ${b} name`,
        `"${parts.registrable}" combines "${b}" with other words but is not owned by ${b}.`, 30));
      continue;
    }

    // 4. Brand glued to other text: "paypalsecure.com", "myappleid.net".
    if (label !== b && b.length >= 6 && labelSkel.includes(b)) {
      out.push(signal('brand_embedded', `Contains ${b}`,
        `"${parts.registrable}" embeds "${b}" in a domain ${b} does not own.`, 20));
      continue;
    }

    // 5. Brand in a subdomain: "paypal.com.account-check.xyz".
    if (subLabels.some((s) => skeleton(s) === b || s.split('-').some((t) => skeleton(t) === b))) {
      out.push(signal('brand_subdomain', `${b} in subdomain`,
        `The real domain is "${parts.registrable}". "${b}" only appears in the subdomain to look official.`, 35));
    }
  }
  return out;
}

function checkDomainShape(parts) {
  const out = [];
  if (isIpAddress(parts.registrable)) return out;

  const tld = parts.suffix.split('.').pop();
  if (SUSPICIOUS_TLDS.has(tld)) {
    out.push(signal('suspicious_tld', 'High-abuse TLD',
      `".${tld}" domains are cheap and disproportionately used for phishing.`, 15));
  }

  if (FREE_HOSTING_SUFFIXES.has(parts.suffix)) {
    out.push(signal('free_hosting', 'Free hosting platform',
      `Anyone can publish a page on ${parts.suffix} in minutes. It is often abused for throwaway phishing pages.`, 10));
  }

  if (URL_SHORTENERS.has(parts.registrable)) {
    out.push(signal('shortener', 'Link shortener', 'The real destination is hidden behind a URL shortener.', 10));
  }

  const subCount = parts.subdomain ? parts.subdomain.split('.').length : 0;
  if (subCount >= 4) {
    out.push(signal('deep_subdomains', 'Many subdomains',
      `${subCount} levels of subdomain push the real domain out of view in the address bar.`, 20));
  } else if (subCount === 3) {
    out.push(signal('deep_subdomains', 'Many subdomains',
      '3 levels of subdomain can hide the real domain in the address bar.', 10));
  }

  const unicodeLabel = toUnicode(parts.label);
  const hyphens = (unicodeLabel.match(/-/g) ?? []).length;
  if (hyphens >= 3) {
    out.push(signal('many_hyphens', 'Many hyphens',
      `The domain name contains ${hyphens} hyphens, typical of keyword-stuffed phishing domains.`, 10));
  }

  // Random-looking labels (domain generation algorithms, throwaway domains).
  // Plain English compounds ("appleidverifyaccount") also have high entropy,
  // so we additionally require digits mixed in, long consonant runs, or few vowels.
  const plain = unicodeLabel.replace(/-/g, '');
  const entropy = shannonEntropy(plain);
  const len = Math.max(plain.length, 1);
  const digitRatio = (plain.match(/\d/g) ?? []).length / len;
  const vowelRatio = (plain.match(/[aeiouy]/g) ?? []).length / len;
  const longestConsonantRun = Math.max(0, ...(plain.match(/[bcdfghjklmnpqrstvwxz]+/g) ?? []).map((r) => r.length));
  if (plain.length >= 10 && entropy >= 3.2 && (digitRatio >= 0.25 || longestConsonantRun >= 5 || vowelRatio < 0.2)) {
    out.push(signal('high_entropy', 'Random-looking domain',
      `"${parts.label}" looks machine-generated (entropy ${entropy.toFixed(2)} bits/char).`, 15));
  }

  const hostKeywords = matchKeywords(`${parts.subdomain}.${parts.label}`);
  if (hostKeywords.length) {
    out.push(signal('host_keywords', 'Bait words in domain',
      `The domain contains ${quoteList(hostKeywords)}, words phishing domains use to look urgent or official.`,
      Math.min(20, hostKeywords.length * 10)));
  }
  return out;
}

function checkUrlShape(url, parts) {
  const out = [];
  const href = url.href;

  if (href.length > 200) {
    out.push(signal('long_url', 'Very long URL', `The URL is ${href.length} characters long, which can hide its real target.`, 10));
  } else if (href.length > 100) {
    out.push(signal('long_url', 'Long URL', `The URL is ${href.length} characters long.`, 5));
  }

  const pathAndQuery = decodeSafe(url.pathname + url.search).toLowerCase();
  const pathKeywords = matchKeywords(pathAndQuery);
  if (pathKeywords.length) {
    out.push(signal('path_keywords', 'Bait words in path',
      `The path contains ${quoteList(pathKeywords)}.`, Math.min(10, pathKeywords.length * 5)));
  }

  const brandInPath = BRANDS.find(
    (b) => b.label.length >= 4 && !b.domains.includes(parts.registrable) && new RegExp(`\\b${b.label}\\b`).test(pathAndQuery),
  );
  if (brandInPath) {
    out.push(signal('brand_path', `${brandInPath.label} named in path`,
      `The path mentions "${brandInPath.label}" but the site is ${parts.registrable}.`, 10));
  }

  if (/(^|[?&=/])(https?:\/\/|https?%3a%2f%2f)/i.test(url.search + url.pathname.slice(1))) {
    out.push(signal('embedded_url', 'Redirect to another URL',
      'The link carries another URL inside it, a common way to bounce through open redirects.', 10));
  }

  if (RISKY_FILE_EXT.test(url.pathname)) {
    out.push(signal('risky_file', 'Downloads a risky file type',
      `The link points at "${url.pathname.split('/').pop()}", a file type often used to deliver malware.`, 15));
  }

  const encoded = (url.pathname.match(/%[0-9a-f]{2}/gi) ?? []).length;
  if (encoded >= 10) {
    out.push(signal('heavy_encoding', 'Heavily encoded path', `The path has ${encoded} percent-encoded characters.`, 5));
  }
  return out;
}

function checkDomainAge(context) {
  const age = context.domainAgeDays;
  if (typeof age !== 'number' || Number.isNaN(age)) return [];
  if (age < 7) return [signal('new_domain', 'Brand-new domain', `Registered ${plural(age, 'day')} ago.`, 40)];
  if (age < 30) return [signal('new_domain', 'Very new domain', `Registered ${plural(age, 'day')} ago.`, 30)];
  if (age < 180) return [signal('young_domain', 'Young domain', `Registered about ${plural(Math.round(age / 30), 'month')} ago.`, 15)];
  return [];
}

// Link text that shows one domain while the href goes somewhere else, e.g.
// <a href="https://evil.example">https://www.paypal.com</a>.
const DOMAIN_IN_TEXT = /(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?=[\/:\s]|$)/i;

function checkLinkText(linkText, parts) {
  if (!linkText || !parts.registrable) return [];
  const m = DOMAIN_IN_TEXT.exec(linkText.trim().toLowerCase());
  if (!m) return [];
  const shown = splitHost(m[1]).registrable;
  if (!shown || shown === parts.registrable) return [];
  // "Visit example.com" linking to a shortener or tracking redirect is common but still worth flagging.
  return [signal('deceptive_link_text', 'Link text shows a different site',
    `The link reads "${m[1]}" but actually goes to ${parts.registrable}.`, 35)];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function signal(id, title, detail, weight) {
  return { id, title, detail, weight };
}

function result(url, host, registrable, score, verdict, signals) {
  return {
    url,
    host,
    displayHost: host ? toUnicode(host) : '',
    registrable,
    score,
    verdict,
    signals: [...signals].sort((a, b) => b.weight - a.weight),
  };
}

/** A hyphen-separated token imitates a brand if it equals, misspells or prefixes it ("appleid"). */
function tokenImitates(token, brand) {
  const t = skeleton(token);
  if (t === brand || sequenceSkeleton(token) === brand) return true;
  if (brand.length < MIN_FUZZY_LABEL_LENGTH) return false;
  if (t.length <= brand.length + 3 && (t.startsWith(brand) || t.endsWith(brand))) return true;
  return editDistance(t, brand) <= (brand.length >= 8 ? 2 : 1);
}

function isPrivateIp(host) {
  if (host.startsWith('[')) return /^\[(::1|f[cd][0-9a-f]{2}:|fe80:)/i.test(host);
  const [a, b] = host.split('.').map(Number);
  return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254);
}

function matchKeywords(text) {
  const found = new Set();
  for (const kw of PHISHING_KEYWORDS) {
    if (new RegExp(`(^|[^a-z])${kw}`).test(text)) found.add(kw);
  }
  return [...found];
}

function quoteList(words) {
  return words.slice(0, 4).map((w) => `"${w}"`).join(', ');
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

function decodeSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
