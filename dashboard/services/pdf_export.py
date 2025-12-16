import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

import matplotlib.pyplot as plt

from services.stats_service import global_stats, mitre_heatmap

def _fig_to_png_bytes(fig):
    buf = io.BytesIO()
    fig.tight_layout()
    fig.savefig(buf, format="png", dpi=180)
    plt.close(fig)
    buf.seek(0)
    return buf

def _chart_severity(stats):
    labels = list(stats["severity"].keys())
    values = list(stats["severity"].values())
    fig = plt.figure(figsize=(6, 3.2))
    ax = fig.add_subplot(111)
    ax.pie(values, labels=labels, autopct="%1.0f%%")
    ax.set_title("Alerts by Severity")
    return _fig_to_png_bytes(fig)

def _chart_timeline(stats, max_points=80):
    items = list(stats["timeline"].items())
    if len(items) > max_points:
        # downsample simple
        step = max(1, len(items) // max_points)
        items = items[::step]
    x = [k.replace("T", " ") for k, _ in items]
    y = [v for _, v in items]

    fig = plt.figure(figsize=(6, 3.2))
    ax = fig.add_subplot(111)
    ax.plot(x, y)
    ax.set_title("Attack Timeline (per minute)")
    ax.set_xlabel("Time")
    ax.set_ylabel("Alerts")
    ax.tick_params(axis="x", labelrotation=45, labelsize=7)
    return _fig_to_png_bytes(fig)

def _chart_mitre_top(stats):
    labels = list(stats["mitre_top"].keys())
    values = list(stats["mitre_top"].values())

    fig = plt.figure(figsize=(6, 3.2))
    ax = fig.add_subplot(111)
    ax.barh(labels, values)
    ax.set_title("Top MITRE Techniques")
    ax.set_xlabel("Count")
    return _fig_to_png_bytes(fig)

def _chart_heatmap(hm):
    tactics = hm["tactics"]
    techs = hm["techniques"]
    matrix = hm["matrix"]

    fig = plt.figure(figsize=(6, 3.4))
    ax = fig.add_subplot(111)
    im = ax.imshow(matrix, aspect="auto")

    ax.set_title("MITRE Heatmap (tactic x top techniques)")
    ax.set_yticks(range(len(tactics)))
    ax.set_yticklabels(tactics, fontsize=7)
    ax.set_xticks(range(len(techs)))
    ax.set_xticklabels(techs, fontsize=7, rotation=45, ha="right")

    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    return _fig_to_png_bytes(fig)

def build_dashboard_pdf():
    stats = global_stats()
    hm = mitre_heatmap()

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, h - 50, "PySec Dashboard Report")
    c.setFont("Helvetica", 10)
    c.drawString(40, h - 68, f"Generated: {datetime.now().isoformat(timespec='seconds')}")
    c.drawString(40, h - 83, f"Total alerts: {stats.get('total', 0)}")

    y = h - 120

    # Severity
    sev_png = _chart_severity(stats)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "1) Alerts by Severity")
    y -= 10
    c.drawImage(ImageReader(sev_png), 40, y - 190, width=520, height=190, preserveAspectRatio=True, anchor='sw')
    y -= 215

    # Timeline
    tl_png = _chart_timeline(stats)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "2) Timeline")
    y -= 10
    c.drawImage(ImageReader(tl_png), 40, y - 190, width=520, height=190, preserveAspectRatio=True, anchor='sw')
    y -= 215

    c.showPage()

    # MITRE top
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, h - 50, "MITRE ATT&CK Summary")
    y = h - 90

    mt_png = _chart_mitre_top(stats)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "3) Top Techniques")
    y -= 10
    c.drawImage(ImageReader(mt_png), 40, y - 210, width=520, height=210, preserveAspectRatio=True, anchor='sw')
    y -= 240

    # Heatmap
    if hm["tactics"] and hm["techniques"]:
        hm_png = _chart_heatmap(hm)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, "4) Heatmap (tactic x technique)")
        y -= 10
        c.drawImage(ImageReader(hm_png), 40, y - 240, width=520, height=240, preserveAspectRatio=True, anchor='sw')
        y -= 265
    else:
        c.setFont("Helvetica", 11)
        c.drawString(40, y, "Heatmap not available (no MITRE data yet).")
        y -= 20

    c.save()
    buf.seek(0)
    return buf

