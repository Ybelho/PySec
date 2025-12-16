let miniTimeline;

function buildMiniTimeline(stats) {
  const labels = Object.keys(stats.timeline || {});
  const values = Object.values(stats.timeline || {});
  return { labels, values };
}

async function fetchStats() {
  const res = await fetch("/api/stats");
  return await res.json();
}

async function loop() {
  try {
    const stats = await fetchStats();

    const total = stats.total || 0;
    const high = (stats.severity && stats.severity.HIGH) ? stats.severity.HIGH : 0;
    const topMitre = stats.mitre_top ? Object.keys(stats.mitre_top)[0] : "—";

    const k1 = document.getElementById("kpiTotal");
    const k2 = document.getElementById("kpiHigh");
    const k3 = document.getElementById("kpiTopMitre");
    if (k1) k1.textContent = total;
    if (k2) k2.textContent = high;
    if (k3) k3.textContent = topMitre;

    const canvas = document.getElementById("miniTimeline");
    if (canvas) {
      const { labels, values } = buildMiniTimeline(stats);
      const data = {
        labels,
        datasets: [{
          label: "Alerts",
          data: values,
          borderColor: "#38bdf8",
          backgroundColor: "rgba(56,189,248,0.12)",
          tension: 0.35,
          fill: true
        }]
      };

      if (!miniTimeline) {
        miniTimeline = new Chart(canvas, {
          type: "line",
          data,
          options: { responsive: true, animation: { duration: 1200 } }
        });
      } else {
        miniTimeline.data = data;
        miniTimeline.update();
      }
    }
  } catch (e) {
    // ignore
  } finally {
    setTimeout(loop, 3500);
  }
}

document.addEventListener("DOMContentLoaded", loop);

