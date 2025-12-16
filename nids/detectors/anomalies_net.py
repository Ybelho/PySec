def detect_port_scan(net_event):
    if not net_event:
        return None

    return {
        "type": "PORT_SCAN",
        "severity": net_event["severity"],
        "src_ip": net_event["src_ip"],
        "ports": net_event["ports"],
        "description": "Scan de ports détecté (NIDS réseau)"
    }

