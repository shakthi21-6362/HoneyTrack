"""
Session management module for tracking active honeypot connections.
"""

import uuid
import threading
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

class SessionManager:
    """Tracks active sessions and their activity across honeypot services."""

    def __init__(self) -> None:
        """Initialize the SessionManager with an empty session dictionary and a lock."""
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()

    def start_session(self, ip: str, service: str) -> str:
        """
        Start a new session for a given IP and service.

        Args:
            ip: The source IP address.
            service: The service being accessed (e.g., 'SSH', 'FTP').

        Returns:
            A unique session ID (UUID as string).
        """
        session_id = str(uuid.uuid4())
        with self.lock:
            self.sessions[session_id] = {
                'id': session_id,
                'ip': ip,
                'service': service,
                'start_time': datetime.now(timezone.utc),
                'end_time': None,
                'username': None,
                'password': None,
                'commands': [],
                'attempt_count': self._get_attempt_count_unlocked(ip, service) + 1,
                'active': True
            }
        return session_id

    def update_session(
        self,
        session_id: str,
        command: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None
    ) -> None:
        """
        Update an existing session with new activity.

        Args:
            session_id: The ID of the session to update.
            command: A command executed during the session.
            username: The username attempted.
            password: The password attempted.
        """
        with self.lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                if command is not None:
                    session['commands'].append(command)
                if username is not None:
                    session['username'] = username
                if password is not None:
                    session['password'] = password
                
                if username or password:
                     session['attempt_count'] += 1

    def end_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Mark a session as ended and return its summary.

        Args:
            session_id: The ID of the session to end.

        Returns:
            The session summary dictionary, or None if not found.
        """
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id]['end_time'] = datetime.now(timezone.utc)
                self.sessions[session_id]['active'] = False
                return self.sessions[session_id].copy()
            return None

    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """
        Get a list of all currently active sessions.

        Returns:
            A list of active session dictionaries.
        """
        with self.lock:
            return [session.copy() for session in self.sessions.values() if session['active']]

    def get_attempt_count(self, ip: str, service: str) -> int:
        """
        Get the total number of attempts from a specific IP for a given service.

        Args:
            ip: The source IP address.
            service: The service name.

        Returns:
            The number of attempts.
        """
        with self.lock:
            return self._get_attempt_count_unlocked(ip, service)
            
    def _get_attempt_count_unlocked(self, ip: str, service: str) -> int:
        """Helper to get attempt count without acquiring the lock."""
        count = 0
        for session in self.sessions.values():
            if session['ip'] == ip and session['service'] == service:
                count += max(1, session.get('attempt_count', 1))
        return count

# Global instance for easy import
session_manager = SessionManager()
