import { test } from 'node:test';
import assert from 'node:assert/strict';
import { splitHost, isIpAddress, hasObfuscatedIp, toUnicode } from '../extension/engine/domain.js';

test('splitHost handles single-label suffixes', () => {
  assert.deepEqual(splitHost('login.secure.example.com'), {
    subdomain: 'login.secure', label: 'example', suffix: 'com', registrable: 'example.com',
  });
});

test('splitHost handles multi-label suffixes', () => {
  assert.equal(splitHost('www.bbc.co.uk').registrable, 'bbc.co.uk');
  assert.equal(splitHost('shop.amazon.com.au').registrable, 'amazon.com.au');
  assert.equal(splitHost('evil-login.github.io').registrable, 'evil-login.github.io');
});

test('splitHost leaves IP addresses intact', () => {
  assert.equal(splitHost('10.0.0.1').registrable, '10.0.0.1');
});

test('isIpAddress', () => {
  assert.ok(isIpAddress('8.8.8.8'));
  assert.ok(isIpAddress('[::1]'));
  assert.ok(!isIpAddress('999.1.1.1'));
  assert.ok(!isIpAddress('example.com'));
});

test('hasObfuscatedIp detects decimal, hex and octal hosts', () => {
  assert.ok(hasObfuscatedIp('http://3232235777/'));
  assert.ok(hasObfuscatedIp('http://0xC0A80101/login'));
  assert.ok(hasObfuscatedIp('http://0300.0250.0001.0001/'));
  assert.ok(hasObfuscatedIp('http://user@0x7f000001/'));
  assert.ok(!hasObfuscatedIp('http://192.168.1.1/'));
  assert.ok(!hasObfuscatedIp('https://example.com/'));
});

test('toUnicode decodes punycode labels', () => {
  assert.equal(toUnicode('xn--pypal-4ve.com'), 'pаypal.com'); // Cyrillic а
  assert.equal(toUnicode('xn--mnchen-3ya.de'), 'münchen.de');
  assert.equal(toUnicode('example.com'), 'example.com');
  assert.equal(toUnicode('xn--!!.com'), 'xn--!!.com'); // invalid stays as-is
});
