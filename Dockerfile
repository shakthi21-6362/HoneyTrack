# =============================================================================
# HoneyTrack - Multi-Stage Dockerfile
# Production-grade container for the HoneyTrack honeypot monitoring system
# =============================================================================

FROM python:3.12-slim AS base

# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------
LABEL maintainer="HoneyTrack Team"
LABEL description="HoneyTrack - Honeypot Monitoring & Threat Intelligence Dashboard"
LABEL version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/honeytrack/honeytrack"

# ---------------------------------------------------------------------------
# Environment variables
# ---------------------------------------------------------------------------
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# ---------------------------------------------------------------------------
# System dependencies
# ---------------------------------------------------------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        openssh-client \
        curl \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------
WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy entire project
COPY . .

# ---------------------------------------------------------------------------
# Create non-root user with permissions to bind to needed ports
# ---------------------------------------------------------------------------
RUN groupadd --gid 1000 honeytrack && \
    useradd --uid 1000 --gid honeytrack --shell /bin/bash --create-home honeytrack && \
    # Create directories for persistent data and SSH keys
    mkdir -p /app/data /app/ssh_keys && \
    # Make entrypoint executable
    chmod +x /app/scripts/docker-entrypoint.sh && \
    # Grant ownership of the app directory to honeytrack user
    chown -R honeytrack:honeytrack /app && \
    # Allow non-root user to bind to privileged ports (if any < 1024)
    apt-get update && \
    apt-get install -y --no-install-recommends libcap2-bin && \
    setcap 'cap_net_bind_service=+ep' "$(readlink -f /usr/local/bin/python3.12)" && \
    apt-get purge -y libcap2-bin && \
    rm -rf /var/lib/apt/lists/*

USER honeytrack

# ---------------------------------------------------------------------------
# Expose ports
# ---------------------------------------------------------------------------
# 5000 - Dashboard (Flask web UI)
# 2222 - SSH honeypot
# 8080 - HTTP honeypot
# 2121 - FTP honeypot
EXPOSE 5000 2222 8080 2121

# ---------------------------------------------------------------------------
# Healthcheck
# ---------------------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5000/login || exit 1

# ---------------------------------------------------------------------------
# Entrypoint & default command (Live production mode by default)
# ---------------------------------------------------------------------------
ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
CMD []
