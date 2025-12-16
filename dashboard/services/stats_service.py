from collections import Counter, defaultdict
from services.alerts_service import load_alerts

def global_stats():
    alerts = load_alerts()

    severity = Counter()
    timeline = defaultdict(int)
    mitre_counter = Counter()

    for a in alerts:
        severity[a.get("severity", "UNKNOWN")] += 1

        ts = a.get("timestamp")
        if ts:
            timeline[ts[:19].replace("T", " ")] += 1

        mitre = a.get("mitre") or {}
        if mitre.get("id"):
            mitre_counter[mitre["id"]] += 1

    return {
        "total": len(alerts),
        "severity": dict(severity),
        "timeline": dict(sorted(timeline.items())),
        "mitre_top": dict(mitre_counter.most_common(10)),
        "mitre": dict(mitre_counter)
    }

def risk_score_by_ip():
    alerts = load_alerts()
    ips = defaultdict(lambda: {
        "alerts": 0,
        "score": 0,
        "techniques": set(),
        "tactics": set()
    })

    for a in alerts:
        ip = a.get("src_ip", "unknown")
        sev = a.get("severity", "LOW")
        mitre = a.get("mitre", {})

        ips[ip]["alerts"] += 1
        ips[ip]["score"] += {"HIGH": 7, "MEDIUM": 3}.get(sev, 1)

        if mitre.get("id"):
            ips[ip]["techniques"].add(mitre["id"])
            ips[ip]["score"] += 5

        if mitre.get("tactic") in ["Privilege Escalation", "Command and Control"]:
            ips[ip]["tactics"].add(mitre["tactic"])
            ips[ip]["score"] += 10

    for ip in ips:
        ips[ip]["techniques"] = list(ips[ip]["techniques"])
        ips[ip]["tactics"] = list(ips[ip]["tactics"])

    return dict(ips)

def mitre_heatmap(top_n=10):
    alerts = load_alerts()
    tech_counter = Counter()
    tactic_set = set()

    for a in alerts:
        mitre = a.get("mitre") or {}
        if mitre.get("id"):
            tech_counter[mitre["id"]] += 1
        if mitre.get("tactic"):
            tactic_set.add(mitre["tactic"])

    top_techs = [t for t, _ in tech_counter.most_common(top_n)]
    tactics = sorted(tactic_set)

    matrix = defaultdict(lambda: defaultdict(int))
    max_val = 0

    for a in alerts:
        mitre = a.get("mitre") or {}
        t = mitre.get("tactic")
        tid = mitre.get("id")
        if t in tactics and tid in top_techs:
            matrix[t][tid] += 1
            max_val = max(max_val, matrix[t][tid])

    return {
        "tactics": tactics,
        "techniques": top_techs,
        "matrix": [[matrix[t][tid] for tid in top_techs] for t in tactics],
        "max": max_val
    }

def mitre_full_matrix():
    alerts = load_alerts()
    data = defaultdict(lambda: defaultdict(lambda: {
        "count": 0,
        "severity": Counter(),
        "alerts": []
    }))

    for a in alerts:
        mitre = a.get("mitre") or {}
        t = mitre.get("tactic")
        tid = mitre.get("id")
        if not t or not tid:
            continue

        sev = a.get("severity", "UNKNOWN")
        data[t][tid]["count"] += 1
        data[t][tid]["severity"][sev] += 1
        data[t][tid]["alerts"].append(a)

    return data
