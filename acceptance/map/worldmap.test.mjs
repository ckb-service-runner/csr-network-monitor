// Shared world map module: the copy must equal the fixture, and its pure functions must behave.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const FIXTURE = 'acceptance/map/worldmap.js';
const COPY = 'csrmon/web/worldmap.js';

// Values from the vm context have other prototypes; compare plain JSON copies.
const plain = (v) => JSON.parse(JSON.stringify(v));

function load(file) {
  const ctx = {};
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(file, 'utf8'), ctx);
  return ctx.CSRWorldMap;
}

test('copy is identical to the fixture', () => {
  assert.ok(fs.existsSync(COPY), `${COPY} missing`);
  assert.equal(fs.readFileSync(COPY, 'utf8'), fs.readFileSync(FIXTURE, 'utf8'));
});

test('country data', () => {
  const M = load(COPY);
  assert.equal(M.WIDTH, 360);
  assert.equal(M.HEIGHT, 154);
  assert.equal(M.COUNTRIES.length, 177);
  const codes = new Set(M.COUNTRIES.map((c) => c[0]));
  for (const cc of ['DE', 'US', 'BR', 'JP', 'AU', 'ZA', 'FR', 'NO']) assert.ok(codes.has(cc), cc);
  for (const c of M.COUNTRIES) assert.match(c[2], /^M[-0-9.]+ [-0-9.]+l/);
});

test('project', () => {
  const M = load(COPY);
  assert.deepEqual(plain(M.project(84, -180)), { x: 0, y: 0 });
  assert.deepEqual(plain(M.project(-70, 180)), { x: 360, y: 154 });
  assert.deepEqual(plain(M.project(53, 13)), { x: 193, y: 31 });
  assert.deepEqual(plain(M.project(-33, 151)), { x: 331, y: 117 });
});

test('radius', () => {
  const M = load(COPY);
  assert.equal(M.radius(1, 1), 6);
  assert.equal(M.radius(4, 4), 6);
  assert.equal(M.radius(1, 4), 4.3);
  assert.equal(M.radius(0, 4), 0);
  assert.equal(M.radius(5, 0), 6);
});

test('label', () => {
  const M = load(COPY);
  assert.equal(M.label({ lat: 53, lon: 13, count: 2 }), '53°N 13°E · 2 runners');
  assert.equal(M.label({ lat: -33, lon: -71, count: 1 }), '33°S 71°W · 1 runner');
  assert.equal(M.label({ lat: 0, lon: 0, count: 1 }), '0° 0° · 1 runner');
});

test('dots: validation, merging, order', () => {
  const M = load(COPY);
  const d = M.dots([
    { lat: 53, lon: 13, count: 1 }, { lat: 41, lon: -75, count: 4 }, { lat: 53, lon: 13, count: 1 },
    { lat: 95, lon: 0, count: 1 }, { lat: 0, lon: 0, count: 0 }, { lat: 'x', lon: 0, count: 1 },
    { lat: 1, lon: 1, count: 1.5 }, null, { lat: -33, lon: 151, count: 1 },
  ]);
  assert.deepEqual(plain(d.map((x) => [x.lat, x.lon, x.count, x.r])), [[41, -75, 4, 6], [53, 13, 2, 5], [-33, 151, 1, 4.3]]);
  assert.equal(d[1].label, '53°N 13°E · 2 runners');
  assert.equal(d[1].x, 193);
  assert.equal(d[1].y, 31);
  assert.deepEqual(plain(M.dots(undefined)), []);
});

test('svg markup', () => {
  const M = load(COPY);
  const s = M.svg([{ lat: 53, lon: 13, count: 2 }, { lat: 41, lon: -75, count: 1 }], { label: 'a<b' });
  assert.match(s, /^<svg class="wm" viewBox="0 0 360 154" role="img" aria-label="a&lt;b">/);
  assert.ok(s.endsWith('</svg>'));
  assert.equal((s.match(/<circle class="wm-dot"/g) || []).length, 2);
  assert.match(s, /<circle class="wm-dot" cx="193" cy="31" r="6" data-index="0"><title>53°N 13°E · 2 runners<\/title><\/circle>/);
  assert.equal((s.match(/<path class="wm-c"/g) || []).length, 177);
  assert.match(s, /<g class="wm-shadow"/);
  assert.doesNotMatch(s, /style=|https?:|<script|xmlns/);
  assert.equal((M.svg([]).match(/<circle/g) || []).length, 0);
});
