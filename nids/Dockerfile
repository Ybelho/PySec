FROM python:3.11-slim

# Dépendances système pour scapy / pcap
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev tcpdump && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# COPIE DE TOUT LE CODE NIDS
COPY nids.py .
COPY sensors ./sensors
COPY detectors ./detectors
COPY reporter ./reporter
COPY mitre ./mitre

# Logs
RUN mkdir -p /app/logs

CMD ["python", "-u", "nids.py"]
