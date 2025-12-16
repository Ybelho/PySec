async function loadStats() {
  const res = await fetch("/api/stats");
  return await res.json();
}

async function renderCharts() {
  const stats = await loadStats();

  /* ---------- SEVERITY DONUT ---------- */
  const severityCtx = document.getElementById("severityChart");
  if (severityCtx) {
    new Chart(severityCtx, {
      type: "doughnut",
      data: {
        labels: Object.keys(stats.severity),
        datasets: [{
          data: Object.values(stats.severity),
          backgroundColor: [
            "#ef4444",
            "#f59e0b",
            "#22c55e",
            "#38bdf8"
          ]
        }]
      },
      options: {
        responsive: true,
        animation: {
          animateScale: true
        },
        plugins: {
          legend: {
            position: "bottom"
          }
        }
      }
    });
  }

  /* ---------- TIMELINE ---------- */
  const timelineCtx = document.getElementById("timelineChart");
  if (timelineCtx) {
    new Chart(timelineCtx, {
      type: "line",
      data: {
        labels: Object.keys(stats.timeline),
        datasets: [{
          label: "Attacks / hour",
          data: Object.values(stats.timeline),
          borderColor: "#38bdf8",
          backgroundColor: "rgba(56,189,248,0.2)",
          tension: 0.4,
          fill: true
        }]
      },
      options: {
        responsive: true,
        animation: {
          duration: 1500
        }
      }
    });
  }

  /* ---------- MITRE BAR ---------- */
  const mitreCtx = document.getElementById("mitreChart");
  if (mitreCtx) {
    new Chart(mitreCtx, {
      type: "bar",
      data: {
        labels: Object.keys(stats.mitre),
        datasets: [{
          label: "MITRE Techniques",
          data: Object.values(stats.mitre),
          backgroundColor: "#22c55e"
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        animation: {
          delay: 300
        }
      }
    });
  }
}

document.addEventListener("DOMContentLoaded", renderCharts);

