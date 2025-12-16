let severityChart, timelineChart, mitreChart;

function ensureChart(ctx, type, data, options) {
  return new Chart(ctx, { type, data, options });
}

function buildSeverityData(stats) {
  const labels = Object.keys(stats.severity || {});
  const values = Object.values(stats.severity || {});
  return {
    labels,
    datasets: [{
      data: values,
      backgroundColor: ["#ef4444", "#f59e0b", "#22c55e", "#38bdf8"]
    }]
  };
}

function buildTimelineData(stats) {
  const labels = Object.keys(stats.timeline || {});
  const values = Object.values(stats.timeline || {});
  return {
    labels,
    datasets: [{
      label: "Alerts / minute",
      data: values,
      borderColor: "#38bdf8",
      backgroundColor: "rgba(56,189,248,0.15)",
      tension: 0.4,
      fill: true
    }]
  };
}

function buildMitreData(stats) {
  const labels = Object.keys(stats.mitre_top || {});
  const values = Object.values(stats.mitre_top || {});
  return {
    labels,
    datasets: [{
      label: "MITRE Techniques",
      data: values,
      backgroundColor: "#22c55e"
    }]
  };
}

async function fetchLive() {
  const since = window.PYSEC?.lastTimestamp || "";
  const res = await fetch(`/api/live?since=${encodeURIComponent(since)}`);
  return await res.json();
}

async function initChartsOnce(stats) {
  const sev = document.getElementById("severityChart");
  if (sev && !severityChart) {
    severityChart = ensureChart(sev, "doughnut", buildSeverityData(stats), {
      responsive: true,
      animation: { animateScale: true },
      plugins: { legend: { position: "bottom" } }
    });
  }

  const tl = document.getElementById("timelineChart");
  if (tl && !timelineChart) {
    timelineChart = ensureChart(tl, "line", buildTimelineData(stats), {
      responsive: true,
      animation: { duration: 1400 }
    });
  }

  const mt = document.getElementById("mitreChart");
  if (mt && !mitreChart) {
    mitreChart = ensureChart(mt, "bar", buildMitreData(stats), {
      indexAxis: "y",
      responsive: true,
      animation: { delay: 250 }
    });
  }
}

function updateCharts(stats) {
  if (severityChart) {
    severityChart.data = buildSeverityData(stats);
    severityChart.update();
  }
  if (timelineChart) {
    timelineChart.data = buildTimelineData(stats);
    timelineChart.update();
  }
  if (mitreChart) {
    mitreChart.data = buildMitreData(stats);
    mitreChart.update();
  }
}

async function loop() {
  try {
    const live = await fetchLive();
    const stats = live.stats;

    await initChartsOnce(stats);
    updateCharts(stats);

    // Update "lastTimestamp" for incremental polling
    const alerts = live.alerts || [];
    if (alerts.length) {
      const last = alerts[alerts.length - 1];
      window.PYSEC.lastTimestamp = last.timestamp || window.PYSEC.lastTimestamp;
    }
  } catch (e) {
    // ignore
  } finally {
    setTimeout(loop, 3500); // refresh smooth
  }
}

document.addEventListener("DOMContentLoaded", loop);

