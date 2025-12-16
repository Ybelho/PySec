def detect_command_signatures(event):
    if event.get("eventid") != "cowrie.command.input":
        return None

    cmd = event.get("input", "").lower()
    signatures = {
        "wget": "PAYLOAD_DOWNLOAD",
        "curl": "PAYLOAD_DOWNLOAD",
        "nmap": "RECONNAISSANCE",
        "whoami": "RECONNAISSANCE",
        "uname": "RECONNAISSANCE",
        "cat /etc/passwd": "RECONNAISSANCE",
        "sudo": "PRIV_ESC",
        "su ": "PRIV_ESC"
    }

    for sig, alert_type in signatures.items():
        if sig in cmd:
            return {
                "type": alert_type,
                "severity": "HIGH" if alert_type != "RECONNAISSANCE" else "MEDIUM",
                "command": event.get("input"),
                "description": f"Signature détectée : {sig}"
            }
    return None

