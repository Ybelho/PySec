# nids/mitre/mapping.py

MITRE_MAPPING = {
    "PORT_SCAN": {
        "tactic": "Reconnaissance",
        "technique": "Network Service Discovery",
        "id": "T1046"
    },
    "BRUTE_FORCE": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "id": "T1110"
    },
    "PAYLOAD_DOWNLOAD": {
        "tactic": "Command and Control",
        "technique": "Ingress Tool Transfer",
        "id": "T1105"
    },
    "RECONNAISSANCE": {
        "tactic": "Discovery",
        "technique": "System Information Discovery",
        "id": "T1082"
    },
    "PRIVILEGE_ESCALATION": {
        "tactic": "Privilege Escalation",
        "technique": "Abuse Elevation Control Mechanism",
        "id": "T1548"
    }
}

def enrich_with_mitre(alert: dict) -> dict:
    """
    Ajoute le mapping MITRE ATT&CK à une alerte NIDS.
    """
    alert_type = alert.get("type")
    mitre = MITRE_MAPPING.get(alert_type)

    if mitre:
        alert["mitre"] = mitre
    else:
        alert["mitre"] = {
            "tactic": "Unknown",
            "technique": "Unknown",
            "id": "N/A"
        }

    return alert

