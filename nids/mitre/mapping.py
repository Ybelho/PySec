# nids/mitre/mapping.py
def detect_command_signatures(event):
    if event.get("eventid") != "cowrie.command.input":
        return None

    cmd = event.get("input", "").lower()

    SIGNATURES = {
        "whoami": ("DISCOVERY", "T1033", "Account Discovery"),
        "id": ("DISCOVERY", "T1033", "Account Discovery"),
        "uname": ("DISCOVERY", "T1082", "System Information Discovery"),
        "cat /etc/passwd": ("DISCOVERY", "T1087", "Account Discovery"),
        "ls": ("DISCOVERY", "T1083", "File and Directory Discovery"),
        "tar ": ("COLLECTION", "T1560", "Archive Collected Data"),
        "curl http": ("C2", "T1071.001", "Web Protocols"),
        "wget": ("C2", "T1105", "Ingress Tool Transfer"),
        "history -c": ("DEFENSE_EVASION", "T1070.003", "Clear Command History"),
        "rm -f ~/.bash_history": ("DEFENSE_EVASION", "T1070.003", "Clear Command History"),
    }

    for sig, (atype, tid, tname) in SIGNATURES.items():
        if sig in cmd:
            return {
                "type": atype,
                "severity": "MEDIUM" if atype == "DISCOVERY" else "HIGH",
                "command": event.get("input"),
                "mitre_override": {
                    "id": tid,
                    "technique": tname
                },
                "description": f"Signature détectée: {sig}"
            }

    return None

