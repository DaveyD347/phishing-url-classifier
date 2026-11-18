import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrl, verdictFor, THRESHOLDS } from '../extension/engine/classifier.js';

const ids = (r) => r.signals.map((s) => s.id);
const atLeast = (verdict) => (verdict === 'dangerous' ? ['dangerous'] : ['suspicious', 'dangerous']);

// --- False-positive guard: ordinary sites must not be flagged ---------------

const LEGITIMATE = [
  'https://www.paypal.com/signin',
  'https://accounts.google.com/ServiceLogin',
  'https://login.microsoftonline.com/common/oauth2/authorize',
  'https://github.com/DaveyD347',
  'https://en.wikipedia.org/wiki/Phishing',
  'https://news.ycombinator.com/item?id=1',
  'https://stackoverflow.com/questions/111102',
  'https://www.bbc.co.uk/news',
  'https://www.nytimes.com/section/technology',
  'https://developer.mozilla.org/en-US/docs/Web/API/URL',
  'https://docs.python.org/3/library/urllib.parse.html',
  'https://www.reddit.com/r/netsec/',
  'https://www.applebees.com/en/menu',
  'https://openai.com/research',
  'https://mail.yahoo.co.jp/',
  'https://www.amazon.co.uk/gp/cart/view.html',
  'https://shop.example.com/products/shoes?color=red',
  'http://192.168.1.1/login.html',
];

for (const url of LEGITIMATE) {
  test(`not flagged: ${url}`, () => {
    const r = analyzeUrl(url);
    assert.ok(['safe', 'trusted'].includes(r.verdict), `${url} scored ${r.score} (${ids(r).join(', ')})`);
  });
}

// --- Phishing-style URLs must be flagged -----------------------------------

const PHISHING = [
  ['https://paypa1.com/login', 'dangerous', 'homoglyph'],
  ['https://xn--pypal-4ve.com/', 'dangerous', 'mixed_script'],
  ['https://arnazon.com/account', 'dangerous', 'homoglyph'],
  ['http://paypal.com.account-verify.xyz/webscr', 'dangerous', 'brand_subdomain'],
  ['https://micosoft-support.net/', 'suspicious', 'brand_combo'],
  ['https://appleid-verify-account.com/', 'suspicious', 'brand_combo'],
  ['https://secure-paypal-login.top/update', 'dangerous', 'brand_combo'],
  ['https://netfliix.com/billing', 'suspicious', 'typosquat'],
  ['http://3232235777/', 'dangerous', 'obfuscated_ip'],
  ['http://45.33.32.156/paypal/login.php', 'dangerous', 'ip_host'],
  ['https://www.google.com@evil.example/', 'suspicious', 'userinfo'],
  ['data:text/html;base64,PGgxPkxvZ2luPC9oMT4=', 'dangerous', 'dangerous_scheme'],
  ['https://x7kq9zpl2vmw3r.top/a', 'suspicious', 'high_entropy'],
  ['https://login.microsoft.verify.account.update.example.net/', 'suspicious', 'brand_subdomain'],
];

for (const [url, minVerdict, expectedSignal] of PHISHING) {
  test(`flagged as ${minVerdict}: ${url}`, () => {
    const r = analyzeUrl(url);
    assert.ok(atLeast(minVerdict).includes(r.verdict), `${url} scored ${r.score} (${ids(r).join(', ')})`);
    assert.ok(ids(r).includes(expectedSignal), `expected ${expectedSignal}, got ${ids(r).join(', ')}`);
  });
}

// --- Individual behaviours ---------------------------------------------------

test('verdict thresholds', () => {
  assert.equal(verdictFor(0), 'safe');
  assert.equal(verdictFor(THRESHOLDS.suspicious - 1), 'safe');
  assert.equal(verdictFor(THRESHOLDS.suspicious), 'suspicious');
  assert.equal(verdictFor(THRESHOLDS.dangerous), 'dangerous');
});

test('score is capped at 100', () => {
  const r = analyzeUrl('http://secure-paypa1-login-verify.xyz:8080/paypal/webscr?cmd=login&next=https://paypal.com', {
    domainAgeDays: 1,
    hasPasswordField: true,
  });
  assert.equal(r.score, 100);
});

test('invalid and non-web URLs are not scored', () => {
  assert.equal(analyzeUrl('not a url').verdict, 'invalid');
  assert.equal(analyzeUrl('').verdict, 'invalid');
  assert.equal(analyzeUrl('chrome://settings').verdict, 'not_applicable');
  assert.equal(analyzeUrl('mailto:someone@example.com').verdict, 'not_applicable');
});

test('javascript: URLs are dangerous', () => {
  assert.equal(analyzeUrl('javascript:alert(1)').verdict, 'dangerous');
});

test('allowlist trusts a domain and its subdomains', () => {
  const r = analyzeUrl('https://sso.paypa1-corp.example/login', { allowlist: ['paypa1-corp.example'] });
  assert.equal(r.verdict, 'trusted');
  assert.equal(analyzeUrl('https://paypa1-corp.example.evil.com', { allowlist: ['paypa1-corp.example'] }).verdict === 'trusted', false);
});

test('domain age adds risk for young domains only', () => {
  const url = 'https://example-shop.com/';
  assert.ok(ids(analyzeUrl(url, { domainAgeDays: 3 })).includes('new_domain'));
  assert.ok(ids(analyzeUrl(url, { domainAgeDays: 90 })).includes('young_domain'));
  assert.deepEqual(ids(analyzeUrl(url, { domainAgeDays: 4000 })), []);
  assert.deepEqual(ids(analyzeUrl(url, { domainAgeDays: null })), []);
});

test('password field over HTTP is flagged', () => {
  const r = analyzeUrl('http://shop.example.com/login', { hasPasswordField: true });
  assert.ok(ids(r).includes('password_over_http'));
});

test('broken TLS reported by the browser is flagged', () => {
  assert.ok(ids(analyzeUrl('https://example.com/', { tlsState: 'broken' })).includes('tls_broken'));
});

test('deceptive link text', () => {
  const r = analyzeUrl('https://evil.example/login', { linkText: 'https://www.paypal.com/account' });
  assert.ok(ids(r).includes('deceptive_link_text'));
  assert.ok(!ids(analyzeUrl('https://example.com/a', { linkText: 'example.com' })).includes('deceptive_link_text'));
  assert.ok(!ids(analyzeUrl('https://example.com/a', { linkText: 'Read more' })).includes('deceptive_link_text'));
});

test('signals are sorted by weight and explain themselves', () => {
  const r = analyzeUrl('http://paypal.com.account-verify.xyz/webscr');
  for (let i = 1; i < r.signals.length; i++) assert.ok(r.signals[i - 1].weight >= r.signals[i].weight);
  for (const s of r.signals) assert.ok(s.title && s.detail);
});

test('short brand names are not fuzzy-matched', () => {
  // "ups" -> "cups", "irs" -> "airs" would be false positives
  assert.equal(analyzeUrl('https://cups.org/').verdict, 'safe');
  assert.equal(analyzeUrl('https://airs.com/').verdict, 'safe');
});
