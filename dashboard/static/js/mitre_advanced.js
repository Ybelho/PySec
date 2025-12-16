let FULL = {};
let currentFilter = { search: "", severity: "" };

function severityScore(sev) {
  return sev === "HIGH" ? 3 : sev === "MEDIUM" ? 2 : sev === "LOW" ? 1 : 0;
}

function colorCell(cell) {
  const s = cell.severity;
  const score =
    severityScore("HIGH") * (s.HIGH || 0) +
    severityScore("MEDIUM") * (s.MEDIUM || 0) +
    severityScore("LOW") * (s.LOW || 0);

  if (score > 6) return "rgba(239,68,68,.4)";
  if (score > 3) return "rgba(245,158,11,.35)";
  if (score > 0) return "rgba(34,197,94,.3)";
  return "rgba(255,255,255,.05)";
}

function renderHeatmap() {
  const root = document.getElementById("heatmap");
  root.innerHTML = "";

  Object.entries(FULL).forEach(([tactic, techniques]) => {
    const row = document.createElement("div");
    row.className = "hm-row";

    const tdiv = document.createElement("div");
    tdiv.className = "hm-tactic";
    tdiv.textContent = tactic;
    row.appendChild(tdiv);

    Object.entries(techniques).forEach(([tid, cell]) => {
      if (currentFilter.search && !tid.includes(currentFilter.search)) return;
      if (currentFilter.severity && !cell.severity[currentFilter.severity]) return;

      const d = document.createElement("div");
      d.className = "hm-cell";
      d.style.background = colorCell(cell);
      d.textContent = tid;
      d.title = `Count: ${cell.count}`;

      d.onclick = () => drillDown(tid, cell.alerts);
      row.appendChild(d);
    });

    root.appendChild(row);
  });
}

function drillDown(tid, alerts) {
  const box = document.getElementById("drilldown");
  const body = document.getElementById("drillBody");
  body.innerHTML = "";

  alerts.forEach(a => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${a.timestamp || "—"}</td>
      <td>${a.type || "—"}</td>
      <td>${a.severity}</td>
      <td>${a.src_ip || "—"}</td>
      <td style="max-width:400px">${a.command || "—"}</td>`;
    body.appendChild(tr);
  });

  box.classList.remove("hidden");
}

async function load() {
  const res = await fetch("/api/mitre/full");
  FULL = await res.json();
  renderHeatmap();
}

document.getElementById("search").oninput = e => {
  currentFilter.search = e.target.value.trim();
  renderHeatmap();
};
document.getElementById("severity").onchange = e => {
  currentFilter.severity = e.target.value;
  renderHeatmap();
};

load();

