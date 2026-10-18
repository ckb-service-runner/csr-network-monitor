// Phase 9 acceptance (Node part): pure helpers used by the page.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  formatPercent, formatScore, statusLabel, countryTiles, gateText, TILE_POSITIONS,
} from "../csrmon/web/format.mjs";

test("formatPercent", () => {
  assert.equal(formatPercent(0.9951), "99.5%");
  assert.equal(formatPercent(1), "100.0%");
  assert.equal(formatPercent(0), "0.0%");
  assert.equal(formatPercent(null), "–");
  assert.equal(formatPercent(undefined), "–");
});

test("formatScore", () => {
  assert.equal(formatScore(87.456), "87.5");
  assert.equal(formatScore(0), "0.0");
  assert.equal(formatScore(null), "–");
});

test("statusLabel", () => {
  assert.equal(statusLabel({ provisional: true, rank: null, flags: [], status: "active" }), "provisional");
  assert.equal(statusLabel({ provisional: false, rank: null, flags: ["identity_mismatch"], status: "active" }), "excluded");
  assert.equal(statusLabel({ provisional: false, rank: null, flags: ["bad_binding"], status: "active" }), "excluded");
  assert.equal(statusLabel({ provisional: false, rank: 3, flags: [], status: "active" }), "ranked");
  assert.equal(statusLabel({ provisional: false, rank: null, flags: [], status: "active" }), "active");
});

test("TILE_POSITIONS", () => {
  const codes = Object.keys(TILE_POSITIONS);
  assert.ok(codes.length >= 40);
  for (const cc of ["DE", "US", "FR", "GB", "NL", "JP", "CN", "IN", "BR", "AU", "CA", "NG", "ZA", "SG", "KR", "RU"]) {
    assert.ok(cc in TILE_POSITIONS, cc);
  }
  const seen = new Set();
  for (const [cc, pos] of Object.entries(TILE_POSITIONS)) {
    assert.match(cc, /^[A-Z]{2}$/);
    assert.ok(Array.isArray(pos) && pos.length === 2 && Number.isInteger(pos[0]) && Number.isInteger(pos[1]), cc);
    const key = pos.join(",");
    assert.ok(!seen.has(key), `duplicate position ${key}`);
    seen.add(key);
  }
});

test("countryTiles", () => {
  const { tiles, other } = countryTiles({ DE: 3, US: 2, XX: 1, QQ: 4, "??": 2 });
  assert.equal(tiles.length, Object.keys(TILE_POSITIONS).length);
  const de = tiles.find((t) => t.cc === "DE");
  assert.deepEqual(de, { cc: "DE", x: TILE_POSITIONS.DE[0], y: TILE_POSITIONS.DE[1], count: 3 });
  assert.equal(tiles.find((t) => t.cc === "FR").count, 0);
  assert.deepEqual(other, [{ cc: "QQ", count: 4 }, { cc: "??", count: 2 }, { cc: "XX", count: 1 }]);
  assert.deepEqual(countryTiles({}).other, []);
});

test("gateText", () => {
  const g = { history_days: 120, min_days: 365, runners: 12, min_runners: 60, met: false };
  assert.equal(gateText(g), "120/365 days · 12/60 runners · not met");
  assert.equal(gateText({ ...g, met: true }), "120/365 days · 12/60 runners · met");
});
