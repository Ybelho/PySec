import json

MITRE_FILE = "/app/logs/mitre_summary.txt"

def get_mitre_summary():
    try:
        with open(MITRE_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

