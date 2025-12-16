#!/usr/bin/env python3
from flask import Flask, render_template, jsonify, request, send_file

from services.alerts_service import latest_alerts
from services.stats_service import (
    global_stats,
    risk_score_by_ip,
    mitre_heatmap,
    mitre_full_matrix
)
from services.timeline_service import mitre_killchain
from services.pdf_export import build_dashboard_pdf

app = Flask(__name__)

# ==================== ROUTES UI ====================

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html")

@app.route("/stats")
def stats_page():
    return render_template("stats.html")

@app.route("/mitre")
def mitre_page():
    return render_template("mitre.html")

@app.route("/timeline")
def timeline_page():
    return render_template("timeline.html")

# ==================== API ====================

@app.route("/api/live")
def api_live():
    since = request.args.get("since")
    alerts = latest_alerts(since_iso=since, limit=30)
    stats = global_stats()
    return jsonify({
        "alerts": alerts,
        "stats": stats
    })

@app.route("/api/stats")
def api_stats():
    return jsonify(global_stats())

@app.route("/api/risk")
def api_risk():
    return jsonify(risk_score_by_ip())

@app.route("/api/mitre/heatmap")
def api_mitre_heatmap():
    return jsonify(mitre_heatmap())

@app.route("/api/mitre/full")
def api_mitre_full():
    return jsonify(mitre_full_matrix())

@app.route("/api/killchain")
def api_killchain():
    return jsonify(mitre_killchain())

# ==================== EXPORT ====================

@app.route("/export/pdf")
def export_pdf():
    pdf = build_dashboard_pdf()
    return send_file(
        pdf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="pysec_dashboard_report.pdf"
    )

# ==================== MAIN ====================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
