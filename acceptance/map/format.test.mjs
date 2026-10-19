// Map phase 3: new pure helpers of the public page.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { countryLabel, countryList } from '../../csrmon/web/format.mjs';

test('countryLabel', () => {
  assert.equal(countryLabel('DE'), 'DE');
  assert.equal(countryLabel('??'), 'unknown');
  assert.equal(countryLabel(''), 'unknown');
  assert.equal(countryLabel(null), 'unknown');
  assert.equal(countryLabel(undefined), 'unknown');
  assert.equal(countryLabel('de'), 'unknown');
  assert.equal(countryLabel('DEU'), 'unknown');
});

test('countryList', () => {
  assert.equal(countryList({ US: 3, DE: 3, '??': 2, FR: 1, JP: 0 }), 'DE 3 · US 3 · FR 1 · unknown 2');
  assert.equal(countryList({ '??': 1, '': 2 }), 'unknown 3');
  assert.equal(countryList({ NL: 1 }), 'NL 1');
  assert.equal(countryList({}), '');
  assert.equal(countryList(null), '');
});
