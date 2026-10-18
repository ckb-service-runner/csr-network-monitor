import { formatPercent, formatScore, statusLabel, countryTiles, gateText } from "./format.mjs";

const $ = (id) => document.getElementById(id);

async function getJson(path) {
  const r = await fetch(path, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
}

function cell(tr, text) {
  const td = document.createElement("td");
  td.textContent = text;
  tr.appendChild(td);
  return td;
}

function shortId(id) {
  return id.length > 14 ? id.slice(0, 8) + "…" + id.slice(-6) : id;
}

function renderSummary(s) {
  const div = s.diversity_index === null || s.diversity_index === undefined
    ? "–" : Number(s.diversity_index).toFixed(2);
  $("summary").textContent =
    `${s.runner_count} ranked · ${s.provisional_count} provisional · ASN diversity ${div}`;
  $("gate").textContent = "Gate: " + gateText(s.gate);
}

function renderMap(byCountry) {
  const { tiles, other } = countryTiles(byCountry);
  const map = $("map");
  map.textContent = "";
  const maxCount = Math.max(1, ...tiles.map((t) => t.count));
  for (const t of tiles) {
    const d = document.createElement("div");
    d.className = "tile" + (t.count > 0 ? " on" : "");
    d.style.gridColumn = String(t.x + 1);
    d.style.gridRow = String(t.y + 1);
    d.style.setProperty("--level", String(t.count / maxCount));
    d.title = `${t.cc}: ${t.count}`;
    d.textContent = t.count > 0 ? `${t.cc} ${t.count}` : t.cc;
    map.appendChild(d);
  }
  $("other").textContent = other.length
    ? "Other: " + other.map((o) => `${o.cc} ${o.count}`).join(", ") : "";
}

function renderRanking(items) {
  const body = $("ranking").tBodies[0];
  body.textContent = "";
  for (const it of items) {
    const tr = document.createElement("tr");
    cell(tr, it.rank === null || it.rank === undefined ? "–" : String(it.rank));
    cell(tr, shortId(it.runner_id)).title = it.runner_id;
    cell(tr, formatScore(it.score));
    cell(tr, formatPercent(it.a30));
    cell(tr, formatPercent(it.a365));
    cell(tr, it.country || "–");
    cell(tr, it.asn === null || it.asn === undefined ? "–" : String(it.asn));
    cell(tr, statusLabel(it));
    body.appendChild(tr);
  }
}

async function main() {
  try {
    const mon = await getJson("/v1/monitor");
    const net = mon.network;
    $("network-name").textContent = net;
    const [summary, runners] = await Promise.all([
      getJson(`/v1/${net}/summary`),
      getJson(`/v1/${net}/runners?limit=500`),
    ]);
    renderSummary(summary);
    renderMap(summary.by_country);
    renderRanking(runners.items);
  } catch (e) {
    const el = $("error");
    el.hidden = false;
    el.textContent = "Could not load data: " + e.message;
    $("summary").textContent = "";
  }
}

main();
