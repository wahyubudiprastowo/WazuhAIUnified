FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsutils \
        iproute2 \
        net-tools \
        openssh-client \
        procps \
        whois \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -r -u 1001 -g root blueteam \
    && mkdir -p /var/log/blue-team-mcp /data \
    && chown -R 1001:0 /var/log/blue-team-mcp /data /app

USER 1001:0

EXPOSE 8000

CMD ["python", "main.py", "--transport", "streamable_http", "--host", "0.0.0.0", "--port", "8000"]
