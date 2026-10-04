"""
HoneyTrack Terminal Session Recorder & Replay Engine (v1.2)
============================================================
Records interactive honeypot shell sessions with sub-millisecond precision
in Asciinema v2 format for interactive terminal playback.
"""

import time
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Any, Optional
from database.database import SessionLocal
from database.models import SessionRecording

logger = logging.getLogger(__name__)

class TerminalSessionRecorder:
    """
    In-memory and persistent buffer for terminal input/output events.
    Format: [[timestamp_offset_seconds, event_type, payload_str], ...]
    """

    def __init__(self):
        self._active_recordings: Dict[str, Dict[str, Any]] = {}

    def start_recording(self, session_id: str, ip: str, service: str = "SSH", username: Optional[str] = None):
        """Initializes a new recording stream for a connected honeypot session."""
        self._active_recordings[session_id] = {
            "session_id": session_id,
            "source_ip": ip,
            "service": service,
            "username": username or "unknown",
            "start_epoch": time.time(),
            "start_time": datetime.now(timezone.utc),
            "events": [],
            "commands": []
        }

    def record_event(self, session_id: str, event_type: str, data: str):
        """
        Records an I/O event.
        event_type: 'o' for terminal output (server -> client), 'i' for input (client -> server)
        """
        rec = self._active_recordings.get(session_id)
        if not rec:
            return
        offset = round(time.time() - rec["start_epoch"], 3)
        rec["events"].append([offset, event_type, data])

    def record_command(self, session_id: str, command: str):
        """Tracks complete command string in session metadata."""
        rec = self._active_recordings.get(session_id)
        if rec and command:
            rec["commands"].append(command)

    def finalize_recording(self, session_id: str, is_demo: bool = False) -> Optional[Dict[str, Any]]:
        """
        Closes recording stream and persists session to SQLite.
        """
        rec = self._active_recordings.pop(session_id, None)
        if not rec:
            return None

        end_epoch = time.time()
        duration = round(end_epoch - rec["start_epoch"], 2)
        end_time = datetime.now(timezone.utc)

        # Persist to database
        db = SessionLocal()
        try:
            recording_model = SessionRecording(
                session_id=session_id,
                source_ip=rec["source_ip"],
                service=rec["service"],
                username=rec["username"],
                commands_count=len(rec["commands"]),
                duration_seconds=duration,
                start_time=rec["start_time"],
                end_time=end_time,
                replay_data=json.dumps(rec["events"]),
                is_demo=is_demo
            )
            db.add(recording_model)
            db.commit()
            logger.info(f"[RECORDER] Session recording saved: {session_id} ({duration}s, {len(rec['commands'])} cmds)")
        except Exception as e:
            logger.error(f"[RECORDER] Error persisting recording: {e}")
            db.rollback()
        finally:
            db.close()

        rec["duration_seconds"] = duration
        rec["end_time"] = end_time
        return rec


# Global singleton recorder instance
session_recorder = TerminalSessionRecorder()


def get_session_replay(session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves replay events and metadata for a specific session ID."""
    db = SessionLocal()
    try:
        record = db.query(SessionRecording).filter(SessionRecording.session_id == session_id).first()
        if not record:
            return None
        return {
            "session_id": record.session_id,
            "source_ip": record.source_ip,
            "service": record.service,
            "username": record.username,
            "commands_count": record.commands_count,
            "duration_seconds": record.duration_seconds,
            "start_time": record.start_time.isoformat() if record.start_time else None,
            "end_time": record.end_time.isoformat() if record.end_time else None,
            "events": json.loads(record.replay_data or "[]"),
            "is_demo": record.is_demo
        }
    finally:
        db.close()


def list_session_replays(limit: int = 50, mode: str = "all") -> List[Dict[str, Any]]:
    """Lists available recorded honeypot sessions."""
    db = SessionLocal()
    try:
        q = db.query(SessionRecording)
        if mode == "production":
            q = q.filter(SessionRecording.is_demo == False)
        elif mode == "demo":
            q = q.filter(SessionRecording.is_demo == True)
        
        records = q.order_by(SessionRecording.start_time.desc()).limit(limit).all()
        results = []
        for r in records:
            results.append({
                "session_id": r.session_id,
                "source_ip": r.source_ip,
                "service": r.service,
                "username": r.username,
                "commands_count": r.commands_count,
                "duration_seconds": r.duration_seconds,
                "start_time": r.start_time.isoformat() if r.start_time else None,
                "is_demo": r.is_demo
            })
        return results
    finally:
        db.close()


def create_sample_replay(
    session_id: str,
    ip: str,
    username: str,
    commands: List[Tuple[str, str]],
    is_demo: bool = True
) -> str:
    """
    Synthesizes a realistic asciinema session stream with realistic human typing pauses.
    commands: List of (command_str, output_str)
    """
    events = []
    current_time = 0.0

    motd = (
        "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n\r\n"
        f"Last login: {datetime.utcnow().strftime('%a %b %d %H:%M:%S %Y')} from {ip}\r\n"
    )
    events.append([round(current_time, 2), "o", motd])
    current_time += 0.5

    prompt = f"root@ubuntu-server:~# "
    events.append([round(current_time, 2), "o", prompt])
    current_time += 0.8

    for cmd, output in commands:
        # Simulate typing keystroke by keystroke
        for ch in cmd:
            current_time += 0.08 + (0.04 if ch in ' -_/' else 0.01)
            events.append([round(current_time, 2), "o", ch])
        
        # Enter key
        current_time += 0.2
        events.append([round(current_time, 2), "o", "\r\n"])
        
        # Server response
        current_time += 0.15
        events.append([round(current_time, 2), "o", output.replace('\n', '\r\n') + "\r\n"])
        
        # Prompt returned
        current_time += 0.2
        events.append([round(current_time, 2), "o", prompt])
        current_time += 0.6

    duration = round(current_time, 2)
    start_time = datetime.now(timezone.utc)

    db = SessionLocal()
    try:
        # Check if already exists
        existing = db.query(SessionRecording).filter(SessionRecording.session_id == session_id).first()
        if not existing:
            rec = SessionRecording(
                session_id=session_id,
                source_ip=ip,
                service="SSH",
                username=username,
                commands_count=len(commands),
                duration_seconds=duration,
                start_time=start_time,
                end_time=datetime.now(timezone.utc),
                replay_data=json.dumps(events),
                is_demo=is_demo
            )
            db.add(rec)
            db.commit()
    finally:
        db.close()

    return session_id
