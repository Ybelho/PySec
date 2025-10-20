FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap sshpass curl hping3 iputils-ping netcat-openbsd openssh-client \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY auto_pentest.py .
RUN mkdir -p logs
CMD ["python","auto_pentest.py"]
