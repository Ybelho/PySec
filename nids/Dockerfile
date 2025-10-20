FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev tcpdump && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY nids.py .
RUN mkdir -p logs
CMD ["python","nids.py"]
