import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRegistrationDate, ageInDays } from '../extension/lib/rdap.js';

test('parseRegistrationDate reads the registration event', () => {
  const rdap = {
    events: [
      { eventAction: 'last changed', eventDate: '2025-01-01T00:00:00Z' },
      { eventAction: 'registration', eventDate: '1997-09-15T04:00:00Z' },
    ],
  };
  assert.equal(parseRegistrationDate(rdap).toISOString(), '1997-09-15T04:00:00.000Z');
});

test('parseRegistrationDate tolerates missing or malformed data', () => {
  assert.equal(parseRegistrationDate(null), null);
  assert.equal(parseRegistrationDate({}), null);
  assert.equal(parseRegistrationDate({ events: [{ eventAction: 'registration', eventDate: 'nope' }] }), null);
});

test('ageInDays', () => {
  const now = new Date('2026-01-31T12:00:00Z');
  assert.equal(ageInDays(new Date('2026-01-01T12:00:00Z'), now), 30);
  assert.equal(ageInDays(new Date('2027-01-01T00:00:00Z'), now), 0); // future dates clamp to 0
});
