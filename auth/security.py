"""
HoneyTrack Security Middleware: Rate Limiting & Audit Logging
=============================================================
Provides thread-safe in-memory rate limiting and structured security audit logging
for operator management and authentication endpoints.
"""

import time
import logging
import threading
from typing import Dict, Tuple, Optional
from datetime import datetime, timezone

logger = logging.getLogger("honeytrack.security")

# Configure a dedicated audit log handler
audit_logger = logging.getLogger("honeytrack.audit")
if not audit_logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[AUDIT] %(asctime)s - %(message)s")
    handler.setFormatter(formatter)
    audit_logger.addHandler(handler)
    audit_logger.setLevel(logging.INFO)


class SimpleRateLimiter:
    """
    In-memory sliding-window rate limiter.
    Limits consecutive attempts per IP/identifier within a cooldown window.
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 60, lockout_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._history: Dict[str, list] = {}
        self._lockouts: Dict[str, float] = {}
        self._lock = threading.Lock()

    def is_rate_limited(self, identifier: str) -> Tuple[bool, int]:
        """
        Check if an identifier is rate-limited.
        Returns: (is_limited: bool, retry_after_seconds: int)
        """
        now = time.time()
        with self._lock:
            # Clean up old records periodically
            if len(self._history) > 1000:
                self._cleanup_unlocked(now)

            # Check if currently locked out
            lockout_expiry = self._lockouts.get(identifier, 0)
            if now < lockout_expiry:
                return True, int(lockout_expiry - now) + 1
            elif lockout_expiry > 0:
                del self._lockouts[identifier]
                self._history.pop(identifier, None)

            # Filter timestamps within window
            timestamps = [t for t in self._history.get(identifier, []) if now - t < self.window_seconds]
            self._history[identifier] = timestamps

            if len(timestamps) >= self.max_attempts:
                # Trigger lockout
                self._lockouts[identifier] = now + self.lockout_seconds
                return True, self.lockout_seconds

            return False, 0

    def record_attempt(self, identifier: str):
        """Records an attempt for the identifier."""
        now = time.time()
        with self._lock:
            if identifier not in self._history:
                self._history[identifier] = []
            self._history[identifier].append(now)

    def reset(self, identifier: str):
        """Resets rate limiting history on successful authentication."""
        with self._lock:
            self._history.pop(identifier, None)
            self._lockouts.pop(identifier, None)

    def _cleanup_unlocked(self, now: float):
        """Purges expired tracking entries."""
        for k in list(self._history.keys()):
            self._history[k] = [t for t in self._history[k] if now - t < self.window_seconds]
            if not self._history[k]:
                del self._history[k]
        for k, expiry in list(self._lockouts.items()):
            if now >= expiry:
                del self._lockouts[k]


# Global rate limiter instances:
# 1. Login / Register: 5 failed attempts per IP within 60s -> 5-minute lockout
auth_limiter = SimpleRateLimiter(max_attempts=5, window_seconds=60, lockout_seconds=300)

# 2. General sensitive API limiter: 30 requests per minute
api_limiter = SimpleRateLimiter(max_attempts=30, window_seconds=60, lockout_seconds=60)


def log_admin_action(operator_name: str, action: str, details: Optional[dict] = None, ip: str = "unknown"):
    """
    Writes a persistent, structured security audit record for critical administrative actions.
    """
    ts = datetime.now(timezone.utc).isoformat()
    detail_str = f" | Details: {details}" if details else ""
    audit_logger.info(f"OPERATOR: '{operator_name}' | IP: {ip} | ACTION: {action}{detail_str}")
