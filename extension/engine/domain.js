// Host parsing helpers: registrable-domain extraction, IP detection, punycode.
//
// A full Public Suffix List is ~200 KB. To keep the extension small we ship the
// multi-label suffixes that account for the overwhelming majority of real-world
// traffic. Any single-label TLD (".com", ".xyz", ...) works without a list.

const MULTI_LABEL_SUFFIXES = new Set([
  // United Kingdom
  'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'ac.uk', 'gov.uk', 'nhs.uk',
  // Australia / New Zealand
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'org.nz', 'net.nz', 'govt.nz',
  // Asia
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'co.kr', 'or.kr', 'com.cn', 'net.cn', 'org.cn',
  'gov.cn', 'com.hk', 'com.tw', 'com.sg', 'com.my', 'co.in', 'net.in', 'org.in', 'gov.in',
  'co.id', 'or.id', 'com.ph', 'com.vn', 'co.th', 'in.th', 'com.pk',
  // Americas
  'com.br', 'net.br', 'org.br', 'gov.br', 'com.mx', 'org.mx', 'gob.mx', 'com.ar', 'gob.ar',
  'com.co', 'com.pe', 'com.ve', 'com.uy', 'com.ec',
  // Europe / Middle East / Africa
  'com.tr', 'gov.tr', 'co.il', 'org.il', 'com.sa', 'com.eg', 'co.za', 'org.za', 'gov.za',
  'com.ng', 'co.ke', 'com.ua', 'com.pl', 'com.gr', 'co.at', 'or.at',
  // Common hosted-platform suffixes (each customer gets a subdomain)
  'github.io', 'gitlab.io', 'herokuapp.com', 'netlify.app', 'vercel.app', 'pages.dev',
  'workers.dev', 'web.app', 'firebaseapp.com', 'appspot.com', 'azurewebsites.net',
  'cloudfront.net', 'blogspot.com', 'wordpress.com', 'wixsite.com', 'weebly.com',
  '000webhostapp.com', 'glitch.me', 'repl.co', 'ngrok.io', 'ngrok-free.app', 'r2.dev',
  'onrender.com', 'fly.dev', 'surge.sh', 'translate.goog',
]);

// Free hosting / tunnelling platforms that phishing kits commonly abuse.
export const FREE_HOSTING_SUFFIXES = new Set([
  '000webhostapp.com', 'weebly.com', 'wixsite.com', 'glitch.me', 'repl.co', 'ngrok.io',
  'ngrok-free.app', 'r2.dev', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com',
  'netlify.app', 'vercel.app', 'github.io', 'herokuapp.com', 'onrender.com', 'fly.dev',
  'surge.sh', 'blogspot.com',
]);

const IPV4_DOTTED = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** True if the host is an IPv4/IPv6 literal (including the bracketed form). */
export function isIpAddress(host) {
  if (!host) return false;
  if (host.startsWith('[') && host.endsWith(']')) return true; // IPv6 literal
  const m = IPV4_DOTTED.exec(host);
  return Boolean(m && m.slice(1).every((o) => Number(o) <= 255));
}

/**
 * Detects hosts that were written as obfuscated IPs in the raw URL, e.g.
 * "http://3232235777/" (decimal) or "http://0xC0A80101/" (hex). WHATWG URL
 * parsing normalises these to dotted form, so we check the original string.
 */
export function hasObfuscatedIp(rawUrl) {
  const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/?#]*@)?([^/:?#]+)/i.exec(rawUrl.trim());
  if (!m) return false;
  const host = m[1];
  if (/^\d{8,10}$/.test(host)) return true; // single decimal integer
  if (/^0x[0-9a-f]{1,8}$/i.test(host)) return true; // single hex integer
  // dotted form with hex or octal-looking octets
  const parts = host.split('.');
  if (parts.length === 4 && parts.every((p) => /^(0x[0-9a-f]+|0[0-7]+|\d+)$/i.test(p))) {
    return parts.some((p) => /^0x/i.test(p) || /^0\d/.test(p));
  }
  return false;
}

/** Returns the public suffix of a hostname (best effort, see note above). */
export function publicSuffix(host) {
  const labels = host.split('.');
  for (let i = 0; i < labels.length - 1; i++) {
    const candidate = labels.slice(i).join('.');
    if (MULTI_LABEL_SUFFIXES.has(candidate)) return candidate;
  }
  return labels[labels.length - 1];
}

/**
 * Splits a hostname into { subdomain, label, suffix, registrable }.
 * "login.paypal.co.uk" -> { subdomain: "login", label: "paypal",
 *                           suffix: "co.uk", registrable: "paypal.co.uk" }
 */
export function splitHost(host) {
  const clean = host.replace(/\.$/, '').toLowerCase();
  if (isIpAddress(clean)) {
    return { subdomain: '', label: clean, suffix: '', registrable: clean };
  }
  const suffix = publicSuffix(clean);
  const rest = clean === suffix ? '' : clean.slice(0, -(suffix.length + 1));
  const restLabels = rest ? rest.split('.') : [];
  const label = restLabels.pop() ?? '';
  return {
    subdomain: restLabels.join('.'),
    label,
    suffix,
    registrable: label ? `${label}.${suffix}` : suffix,
  };
}

// --- Punycode (RFC 3492) decoder, enough to display IDN hosts --------------

const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;

function adapt(delta, numPoints, firstTime) {
  let k = 0;
  delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  for (; delta > ((BASE - TMIN) * TMAX) >> 1; k += BASE) {
    delta = Math.floor(delta / (BASE - TMIN));
  }
  return Math.floor(k + ((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

function decodeLabel(input) {
  const output = [];
  const basicEnd = input.lastIndexOf('-');
  for (let j = 0; j < Math.max(basicEnd, 0); j++) output.push(input.charCodeAt(j));
  let n = INITIAL_N, bias = INITIAL_BIAS, i = 0;
  for (let idx = basicEnd > 0 ? basicEnd + 1 : 0; idx < input.length;) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (idx >= input.length) throw new RangeError('invalid punycode');
      const cp = input.charCodeAt(idx++);
      const digit = cp - 48 < 10 ? cp - 22 : cp - 65 < 26 ? cp - 65 : cp - 97 < 26 ? cp - 97 : BASE;
      if (digit >= BASE) throw new RangeError('invalid punycode');
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    bias = adapt(i - oldi, output.length + 1, oldi === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

/** Converts "xn--pypal-4ve.com" to its Unicode form. Invalid labels are kept as-is. */
export function toUnicode(host) {
  return host
    .split('.')
    .map((label) => {
      if (!label.startsWith('xn--')) return label;
      try {
        return decodeLabel(label.slice(4));
      } catch {
        return label;
      }
    })
    .join('.');
}
