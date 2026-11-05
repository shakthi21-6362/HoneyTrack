#!/usr/bin/env bash
# =============================================================================
# HoneyTrack - Docker Entrypoint Script
# Initializes the runtime environment before starting the application.
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# 1. Ensure the persistent data directory exists
# ---------------------------------------------------------------------------
DATA_DIR="/app/data"
if [ ! -d "$DATA_DIR" ]; then
    echo "[entrypoint] Creating data directory: $DATA_DIR"
    mkdir -p "$DATA_DIR"
fi

# ---------------------------------------------------------------------------
# 2. Set default DATABASE_PATH if not already overridden
# ---------------------------------------------------------------------------
export DATABASE_PATH="${DATABASE_PATH:-/app/honeytrack.db}"
echo "[entrypoint] DATABASE_PATH = $DATABASE_PATH"

# ---------------------------------------------------------------------------
# 3. Set default SSH_HOST_KEY_PATH if not already overridden
# ---------------------------------------------------------------------------
export SSH_HOST_KEY_PATH="${SSH_HOST_KEY_PATH:-/app/ssh_keys/ssh_host_key}"
echo "[entrypoint] SSH_HOST_KEY_PATH = $SSH_HOST_KEY_PATH"

# ---------------------------------------------------------------------------
# 4. Generate SSH host key if it does not exist
# ---------------------------------------------------------------------------
if [ ! -f "$SSH_HOST_KEY_PATH" ]; then
    echo "[entrypoint] SSH host key not found — generating a new RSA key..."
    mkdir -p "$(dirname "$SSH_HOST_KEY_PATH")"
    ssh-keygen -t rsa -b 2048 -f "$SSH_HOST_KEY_PATH" -N "" -q
    echo "[entrypoint] SSH host key generated at $SSH_HOST_KEY_PATH"
else
    echo "[entrypoint] SSH host key found at $SSH_HOST_KEY_PATH"
fi

# ---------------------------------------------------------------------------
# 5. Hand off to the main application
# ---------------------------------------------------------------------------
# Filter out legacy or default '--demo' flags unless DEMO_MODE=true is explicitly set
filtered_args=()
for arg in "$@"; do
    if [ "$arg" = "--demo" ]; then
        if [ "${DEMO_MODE:-false}" = "true" ]; then
            filtered_args+=("$arg")
        else
            echo "[entrypoint] Stripping default '--demo' flag; starting in LIVE PRODUCTION mode."
        fi
    else
        filtered_args+=("$arg")
    fi
done

echo "[entrypoint] Starting HoneyTrack..."
exec python main.py "${filtered_args[@]}"
