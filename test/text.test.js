import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shannonEntropy, editDistance, skeleton, sequenceSkeleton, scriptsUsed } from '../extension/engine/text.js';

test('shannonEntropy', () => {
  assert.equal(shannonEntropy(''), 0);
  assert.equal(shannonEntropy('aaaa'), 0);
  assert.equal(shannonEntropy('ab'), 1);
  assert.ok(shannonEntropy('x7kq9zpl2vmw') > 3.4);
});

test('editDistance counts adjacent transpositions as one edit', () => {
  assert.equal(editDistance('paypal', 'paypal'), 0);
  assert.equal(editDistance('paypla', 'paypal'), 1);
  assert.equal(editDistance('gooogle', 'google'), 1);
  assert.equal(editDistance('micosoft', 'microsoft'), 1);
  assert.equal(editDistance('kitten', 'sitting'), 3);
});

test('skeleton folds digits, accents and Cyrillic/Greek look-alikes', () => {
  assert.equal(skeleton('paypa1'), 'paypal');
  assert.equal(skeleton('pаypal'), 'paypal'); // Cyrillic а
  assert.equal(skeleton('pàypal'), 'paypal');
  assert.equal(skeleton('g00gle'), 'google');
  assert.equal(skeleton('αpple'), 'apple');
});

test('sequenceSkeleton folds multi-letter look-alikes', () => {
  assert.equal(sequenceSkeleton('arnazon'), 'amazon');
  assert.equal(sequenceSkeleton('vvhatsapp'), 'whatsapp');
});

test('scriptsUsed', () => {
  assert.deepEqual([...scriptsUsed('paypal')], ['Latin']);
  assert.deepEqual([...scriptsUsed('pаypal')].sort(), ['Cyrillic', 'Latin']);
});
