# Stage 1: Build — install build tools and compile dependencies
FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry==1.8.2 \
    && poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock* ./
RUN poetry install --no-interaction --no-ansi --without dev --no-root

# Cloud provider SDKs for the cloud connectors (AWS, Azure, GCP)
COPY requirements-cloud.txt ./
RUN pip install --no-cache-dir -r requirements-cloud.txt

# Stage 2: Runtime — slim image without build tools
FROM python:3.12-slim

WORKDIR /app

# Runtime libs + curl/unzip for scanner installs
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 curl git tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# ── Install security scanner binaries (all non-fatal — core platform works without them) ──

# Semgrep + Checkov in isolated venvs (avoids dependency conflicts with FastAPI)
RUN python -m venv /opt/semgrep-venv && \
    /opt/semgrep-venv/bin/pip install --no-cache-dir semgrep && \
    ln -s /opt/semgrep-venv/bin/semgrep /usr/local/bin/semgrep \
    || echo "WARN: semgrep install failed — skipping"

RUN python -m venv /opt/checkov-venv && \
    /opt/checkov-venv/bin/pip install --no-cache-dir checkov && \
    ln -s /opt/checkov-venv/bin/checkov /usr/local/bin/checkov \
    || echo "WARN: checkov install failed — skipping"

# tfsec (static binary)
RUN TFSEC_VERSION="1.28.11" && \
    TFSEC_ARCH=$([ "${TARGETARCH}" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl --retry 3 --retry-delay 5 -sSL "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec-linux-${TFSEC_ARCH}" \
      -o /usr/local/bin/tfsec && \
    chmod +x /usr/local/bin/tfsec \
    || echo "WARN: tfsec install failed — skipping"

# Trivy (static binary)
RUN TRIVY_VERSION="0.76.1" && \
    TRIVY_ARCH=$([ "${TARGETARCH}" = "arm64" ] && echo "ARM64" || echo "64bit") && \
    curl --retry 3 --retry-delay 5 -sSL -o /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" && \
    tar xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    chmod +x /usr/local/bin/trivy && \
    rm /tmp/trivy.tar.gz \
    || echo "WARN: trivy install failed — skipping"

# Gitleaks (static binary)
RUN GITLEAKS_VERSION="8.30.1" && \
    GL_ARCH=$([ "${TARGETARCH}" = "arm64" ] && echo "arm64" || echo "x64") && \
    curl --retry 3 --retry-delay 5 -sSL -o /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz" && \
    tar xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks && \
    rm /tmp/gitleaks.tar.gz \
    || echo "WARN: gitleaks install failed — skipping"

COPY . .

ENV SEMGREP_SEND_METRICS=off

RUN adduser --disabled-password --gecos '' appuser && mkdir -p /app/data/plugin_cache && \
    chown -R appuser:appuser /app

# Record the SHA-256 of each scanner binary in this image. Every scan verifies
# the scanner against this file before running it. Owned by root, read-only.
RUN python -m app.services.plugins.integrity baseline /app/integrity-baseline.json && \
    chown root:root /app/integrity-baseline.json && chmod 0444 /app/integrity-baseline.json

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
