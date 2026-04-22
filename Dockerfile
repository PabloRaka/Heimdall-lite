FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DASHBOARD_PORT=8443

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    dbus \
    iproute2 \
    iptables \
    nftables \
    openssh-client \
    openssh-server \
    procps \
    sudo \
    systemd \
    ufw \
    util-linux \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x /app/scripts/docker-entrypoint.sh

EXPOSE 8443 2222 8888

ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
