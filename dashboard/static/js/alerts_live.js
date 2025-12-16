function sevBadge(sev) {
  const s = (sev || "UNKNOWN").toUpperCase();
  const cls = s === "HIGH" ? "high" : s === "MEDIUM" ? "medium" : s === "LOW" ? "low" : "unknown";
  return `<span class="badge ${cls}">${s}</span>`;
}

function mitreBadge(mitre) {
  if (!mitre) return "—";
  const id = mitre.id || "N/A";
  const tactic = mitre.tactic || "Unknown";
  return `<span class="badge unknown">${id}</span><div class="muted" style="font-size:11px;margin-top:4px">${tactic}</div>`;
}

function renderRows(alerts, flashNew=false) {
  const tbody = document.querySelector("#alertsTable tbody");
  if (!tbody) return;

  tbody.innerHTML = "";
  for (const a of alerts.slice().reverse()) {
    const tr = document.createElement("tr");
    if (flashNew) tr.classList.add("flash-new");

    const ts = a.timestamp ? a.timestamp.replace("T"," ").slice(0,19) : "—";
    tr.innerHTML = `
      <td>${ts}</td>
      <td><b>${a.type || "—"}</b></td>
      <td>${sevBadge(a.severity)}</td>
      <td><code>${a.src_ip || "—"}</code></td>
      <td style="max-width:420px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
        ${a.command ? a.command.replaceAll("<","&lt;").replaceAll(">","&gt;") : "—"}
      </td>
      <td>${mitreBadge(a.mitre)}</td>
    `;
    tbody.appendChild(tr);
  }
}

async function fetchLive() {
  const since = window.PYSEC?.lastTimestamp || "";
  const res = await fetch(`/api/live?since=${encodeURIComponent(since)}`);
  return await res.json();
}

async function loop() {
  try {
    const live = await fetchLive();
    const alerts = live.alerts || [];

    if (alerts.length) {
      const last = alerts[alerts.length - 1];
      const newTs = last.timestamp || "";
      const isNew = newTs && newTs !== window.PYSEC.lastTimestamp;

      renderRows(alerts, isNew);

      if (isNew) {
        window.PYSEC.toast(`New alert: ${last.type} (${last.severity})`);
        window.PYSEC.lastTimestamp = newTs;
      }
    }
  } catch (e) {
    // ignore
  } finally {
    setTimeout(loop, 2500);
  }
}

document.addEventListener("DOMContentLoaded", loop);

