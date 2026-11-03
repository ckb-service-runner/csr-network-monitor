import { formatPercent, formatScore, statusLabel, countryLabel, countryList, gateText } from "./format.mjs";

// API base: "" on the monitor itself (relative paths); a preview page sets data-api on <html>.
const API = document.documentElement.dataset.api || "";
const SNAPSHOT = globalThis.CSR_SNAPSHOT || null;
const $ = (id) => document.getElementById(id);
let usedSnapshot = false;

async function getJson(path) {
  try {
    const r = await fetch(API + path, { headers: { Accept: "application/json" } });
    if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
    return await r.json();
  } catch (e) {
    if (SNAPSHOT && path in SNAPSHOT) { usedSnapshot = true; return SNAPSHOT[path]; }
    throw e;
  }
}

function cell(tr, text, cls) {
  const td = document.createElement("td");
  td.textContent = text;
  if (cls) td.className = cls;
  tr.appendChild(td);
  return td;
}

function shortId(id) {
  return id.length > 14 ? id.slice(0, 8) + "…" + id.slice(-6) : id;
}

const pct = (x) => (x === null || x === undefined ? "–" : Math.round(x * 100) + "%");
const clamp01 = (x) => Math.max(0, Math.min(1, Number(x) || 0));

function setMeter(fillId, valId, value, text, limitId, limit) {
  const f = $(fillId);
  f.style.width = (clamp01(value) * 100).toFixed(1) + "%";
  if (limitId) {
    $(limitId).style.left = `calc(${(clamp01(limit) * 100).toFixed(1)}% - 1px)`;
    f.classList.toggle("over", value > limit);
  }
  $(valId).textContent = text;
}

function renderGate(s) {
  const g = s.gate;
  const ranked = g.runners || 0;
  const prov = s.provisional_count || 0;
  const total = Math.max(g.min_runners, ranked + prov);
  const box = $("cells");
  box.textContent = "";
  for (let i = 0; i < total; i++) {
    const c = document.createElement("span");
    c.className = "cell " + (i < ranked ? "on" : i < ranked + prov ? "prov" : "open");
    box.appendChild(c);
  }
  box.setAttribute("aria-label", `${ranked} of ${g.min_runners} runners ranked, ${prov} provisional`);
  $("gate-min").textContent = g.min_runners;
  $("n-ranked").textContent = ranked;
  $("n-prov").textContent = prov;
  $("n-open").textContent = Math.max(0, g.min_runners - ranked - prov);
  setMeter("m-days", "v-days", g.history_days / g.min_days, `${g.history_days} / ${g.min_days} days`);
  setMeter("m-asn", "v-asn", g.largest_asn_share, `${pct(g.largest_asn_share)} · max ${pct(g.max_asn_share)}`, "l-asn", g.max_asn_share);
  setMeter("m-cc", "v-cc", g.largest_country_share, `${pct(g.largest_country_share)} · max ${pct(g.max_country_share)}`, "l-cc", g.max_country_share);
  const chip = $("gate-chip");
  chip.textContent = g.met ? "open" : "not met";
  chip.classList.toggle("met", !!g.met);
  $("gate").textContent = "Gate: " + gateText(g);
}

function renderSummary(s) {
  const div = s.diversity_index === null || s.diversity_index === undefined
    ? "–" : Number(s.diversity_index).toFixed(2);
  $("summary").textContent =
    `${s.runner_count} ranked · ${s.provisional_count} provisional` +
    (s.inactive_count ? ` · ${s.inactive_count} inactive` : "") + ` · ASN diversity ${div} · ${s.date}`;
  $("s-ranked").textContent = s.runner_count;
  $("s-prov").textContent = s.provisional_count;
  $("s-cc").textContent = Object.values(s.by_country || {}).filter((n) => n > 0).length;
  $("s-div").textContent = div;
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

let rankingItems = [];

function renderRanking(items) {
  const body = $("ranking").tBodies[0];
  body.textContent = "";
  if (!rankingItems.length) {
    const tr = document.createElement("tr");
    tr.className = "empty";
    const td = cell(tr, "No runners yet. Install CSR and yours is the first row.");
    td.colSpan = 8;
    body.appendChild(tr);
    return;
  }
  for (const it of items) {
    const tr = document.createElement("tr");
    if (it.unranked_reason === "inactive") {
      tr.className = "inactive";
      tr.title = "No successful check for several days";
    }
    cell(tr, it.rank === null || it.rank === undefined ? "–" : String(it.rank));
    cell(tr, shortId(it.runner_id), "id").title = it.runner_id;
    const sc = cell(tr, "", "score");
    const bar = document.createElement("span");
    bar.className = "sbar";
    const fill = document.createElement("i");
    fill.style.width = (clamp01((it.score || 0) / 100) * 100).toFixed(0) + "%";
    bar.appendChild(fill);
    const num = document.createElement("span");
    num.textContent = formatScore(it.score);
    sc.append(num, bar);
    cell(tr, formatPercent(it.a30));
    cell(tr, formatPercent(it.a365));
    cell(tr, countryLabel(it.country));
    cell(tr, it.asn === null || it.asn === undefined ? "–" : String(it.asn));
    const st = statusLabel(it);
    const stTd = cell(tr, "");
    const pill = document.createElement("span");
    pill.className = "st " + st;
    pill.textContent = st;
    stTd.appendChild(pill);
    body.appendChild(tr);
  }
}

$("runner-filter").addEventListener("input", (ev) => {
  const q = ev.target.value.trim().toLowerCase();
  const items = q ? rankingItems.filter((it) => it.runner_id.toLowerCase().includes(q)) : rankingItems;
  renderRanking(items);
  $("rank-empty").hidden = !(q && rankingItems.length && !items.length);
});

function renderMonitor(mon) {
  $("mon-version").textContent = mon.version ? "v" + mon.version : "";
  if (mon.pubkey) {
    $("mon-key").textContent = mon.pubkey.slice(0, 10) + "…" + mon.pubkey.slice(-8);
    $("mon-key").title = mon.pubkey;
  }
  if (mon.tip && mon.tip.number !== undefined) $("tip").textContent = "#" + Number(mon.tip.number).toLocaleString("en-US");
}

function setNetwork(net) {
  document.documentElement.dataset.net = net;
  $("network-name").textContent = net;
  const other = net === "mainnet" ? "testnet" : "mainnet";
  const sw = $("netswitch");
  sw.textContent = other[0].toUpperCase() + other.slice(1);
  sw.href = `../${other}/`;
}

for (const b of document.querySelectorAll(".copy")) {
  b.addEventListener("click", async () => {
    const el = $(b.dataset.copy);
    try {
      await navigator.clipboard.writeText(el.textContent);
      b.textContent = "Copied";
    } catch {
      const range = document.createRange();
      range.selectNodeContents(el);
      const sel = getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      b.textContent = "Selected";
    }
    setTimeout(() => { b.textContent = "Copy"; }, 1600);
  });
}

async function main() {
  try {
    const mon = await getJson("v1/monitor");
    const net = mon.network;
    setNetwork(net);
    renderMonitor(mon);
    const [summary, runners, locations] = await Promise.all([
      getJson(`v1/${net}/summary`),
      getJson(`v1/${net}/runners?limit=500`),
      getJson("v1/locations").catch(() => null),
    ]);
    renderGate(summary);
    renderSummary(summary);
    renderMap(locations, summary.by_country);
    rankingItems = runners.items || [];
    renderRanking(rankingItems);
    if (usedSnapshot && SNAPSHOT.__taken) {
      const n = $("snapshot-note");
      n.hidden = false;
      n.textContent = `Preview: live data could not load here, showing a snapshot from ${SNAPSHOT.__taken}.`;
    }
  } catch (e) {
    const el = $("error");
    el.hidden = false;
    el.textContent = "Could not load data: " + e.message;
    $("summary").textContent = "";
  }
}

main();
