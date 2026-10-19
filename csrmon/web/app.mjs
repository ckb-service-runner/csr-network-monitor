import { formatPercent, formatScore, statusLabel, countryLabel, countryList, gateText } from "./format.mjs";

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

let mapLocations = [];

function renderMap(locations, byCountry) {
  const wm = globalThis.CSRWorldMap;
  mapLocations = locations ? locations.locations || [] : [];
  $("map").innerHTML = wm.svg(mapLocations, { label: "Runners on a world map" });
  if (!locations) $("map-info").textContent = "Location data is not available.";
  $("other").textContent = countryList(byCountry);
}

$("map").addEventListener("click", (ev) => {
  const c = ev.target.closest ? ev.target.closest("circle[data-index]") : null;
  if (!c) return;
  const d = globalThis.CSRWorldMap.dots(mapLocations)[Number(c.getAttribute("data-index"))];
  if (d) $("map-info").textContent = d.label;
});

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
    cell(tr, countryLabel(it.country));
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
    const [summary, runners, locations] = await Promise.all([
      getJson(`/v1/${net}/summary`),
      getJson(`/v1/${net}/runners?limit=500`),
      getJson("/v1/locations").catch(() => null),
    ]);
    renderSummary(summary);
    renderMap(locations, summary.by_country);
    renderRanking(runners.items);
  } catch (e) {
    const el = $("error");
    el.hidden = false;
    el.textContent = "Could not load data: " + e.message;
    $("summary").textContent = "";
  }
}

main();
