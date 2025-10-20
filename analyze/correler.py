#!/usr/bin/env python3
import json, pandas as pd, glob
# Lire alerts nids
alerts = []
for line in open("nids/logs/alerts.jsonl","r",errors="ignore"):
    try:
        alerts.append(json.loads(line))
    except:
        continue
df_alerts = pd.DataFrame(alerts)
print("=== Alerts NIDS ===")
print(df_alerts.groupby("type").size())

# Lire cowrie JSON (essayer plusieurs chemins)
cowrie_files = glob.glob("cowrie/var/log/cowrie/cowrie.json*")
events=[]
for f in cowrie_files:
    with open(f,"r",errors="ignore") as fh:
        for l in fh:
            try:
                events.append(json.loads(l))
            except:
                continue
df_cowrie = pd.DataFrame(events)
if not df_cowrie.empty:
    print("\nTop 10 IPs in Cowrie events:")
    print(df_cowrie['src_ip'].value_counts().head(10))
else:
    print("\nNo cowrie JSON logs found or empty.")
