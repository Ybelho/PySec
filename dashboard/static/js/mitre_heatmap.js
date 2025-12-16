function colorFor(value, max) {
  if (!max || max <= 0) return "rgba(255,255,255,0.05)";
  const r = value / max; // 0..1
  // Gradient: green -> amber -> red
  if (r < 0.34) return `rgba(34,197,94,${0.10 + r * 0.45})`;
  if (r < 0.67) return `rgba(245,158,11,${0.10 + r * 0.45})`;
  return `rgba(239,68,68,${0.10 + r * 0.55})`;
}

async function fetchHeatmap() {
  const res = await fetch("/api/mitre/heatmap");
  return await res.json();
}

function renderHeatmap(hm) {
  const root = document.getElementById("heatmap");
  if (!root) return;

  const tactics = hm.tactics || [];
  const techs = hm.techniques || [];
  const matrix = hm.matrix || [];
  const maxv = hm.max || 0;

  root.innerHTML = "";

  if (!tactics.length || !techs.length) {
    root.innerHTML = `<div class="muted">No MITRE data yet. Generate alerts with "mitre" field first.</div>`;
    return;
  }

  // Header row
  const header = document.createElement("div");
  header.className = "hm-row hm-header";
  header.style.gridTemplateColumns = `220px repeat(${techs.length}, minmax(80px, 1fr))`;
  header.innerHTML = `<div></div>` + techs.map(t => `<div>${t}</div>`).join("");
  root.appendChild(header);

  // Data rows
  tactics.forEach((tactic, i) => {
    const row = document.createElement("div");
    row.className = "hm-row";
    row.style.gridTemplateColumns = `220px repeat(${techs.length}, minmax(80px, 1fr))`;

    const left = document.createElement("div");
    left.className = "hm-tactic";
    left.textContent = tactic;
    row.appendChild(left);

    techs.forEach((tid, j) => {
      const val = (matrix[i] && matrix[i][j]) ? matrix[i][j] : 0;
      const cell = document.createElement("div");
      cell.className = "hm-cell";
      cell.style.background = colorFor(val, maxv);
      cell.title = `${tactic} / ${tid} = ${val}`;
      cell.textContent = val ? String(val) : "·";
      row.appendChild(cell);
    });

    root.appendChild(row);
  });
}

async function loop() {
  try {
    const hm = await fetchHeatmap();
    renderHeatmap(hm);
  } catch (e) {
    // ignore
  } finally {
    setTimeout(loop, 4000);
  }
}

document.addEventListener("DOMContentLoaded", loop);

