// Pure helpers for the public page (no DOM access).
const DASH = "–";

export function formatPercent(x) {
  return x === null || x === undefined ? DASH : (x * 100).toFixed(1) + "%";
}

export function formatScore(s) {
  return s === null || s === undefined ? DASH : s.toFixed(1);
}

export function statusLabel(item) {
  if (item.provisional) return "provisional";
  const flags = item.flags || [];
  if (flags.includes("identity_mismatch") || flags.includes("bad_binding")) return "excluded";
  if (item.rank !== null && item.rank !== undefined) return "ranked";
  return item.status;
}

// Tile-grid map: [x, y], roughly geographic (x = west to east, y = north to south).
export const TILE_POSITIONS = {
  IS: [4, 0], NO: [8, 0], SE: [9, 0], FI: [10, 0],
  CA: [1, 1], IE: [4, 1], GB: [5, 1], DK: [8, 1], EE: [10, 1], RU: [12, 1],
  US: [1, 2], NL: [6, 2], DE: [7, 2], PL: [8, 2], LV: [9, 2], UA: [10, 2], KZ: [13, 2], MN: [15, 2],
  MX: [1, 3], FR: [5, 3], BE: [6, 3], CH: [7, 3], CZ: [8, 3], AT: [9, 3], RO: [10, 3], CN: [14, 3], KR: [16, 3], JP: [17, 3],
  PT: [4, 4], ES: [5, 4], IT: [8, 4], HU: [9, 4], BG: [10, 4], TR: [11, 4], IR: [12, 4], IN: [13, 4], HK: [15, 4], TW: [16, 4],
  CO: [2, 5], MA: [4, 5], DZ: [5, 5], GR: [10, 5], IL: [11, 5], AE: [12, 5], PK: [13, 5], TH: [14, 5], VN: [15, 5], PH: [16, 5],
  VE: [3, 6], NG: [6, 6], EG: [11, 6], SA: [12, 6], ID: [15, 6], MY: [14, 6], SG: [14, 7],
  BR: [4, 7], KE: [11, 7], ET: [12, 7],
  PE: [3, 8], CL: [3, 9], AR: [4, 9], ZA: [9, 9], AU: [16, 9], NZ: [18, 10],
};

export function countryTiles(byCountry) {
  const counts = byCountry || {};
  const tiles = Object.entries(TILE_POSITIONS).map(([cc, [x, y]]) => ({
    cc, x, y, count: counts[cc] || 0,
  }));
  const other = Object.entries(counts)
    .filter(([cc, n]) => !(cc in TILE_POSITIONS) && n > 0)
    .map(([cc, count]) => ({ cc, count }))
    .sort((a, b) => b.count - a.count || (a.cc < b.cc ? -1 : a.cc > b.cc ? 1 : 0));
  return { tiles, other };
}

export function gateText(g) {
  return `${g.history_days}/${g.min_days} days · ${g.runners}/${g.min_runners} runners · ${g.met ? "met" : "not met"}`;
}

export function countryLabel(cc) {
  return typeof cc === "string" && /^[A-Z]{2}$/.test(cc) ? cc : "unknown";
}

export function countryList(byCountry) {
  const known = [];
  let unknown = 0;
  for (const [cc, n] of Object.entries(byCountry || {})) {
    if (!(n > 0)) continue;
    if (countryLabel(cc) === "unknown") unknown += n;
    else known.push([cc, n]);
  }
  known.sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const parts = known.map(([cc, n]) => `${cc} ${n}`);
  if (unknown > 0) parts.push(`unknown ${unknown}`);
  return parts.join(" · ");
}
