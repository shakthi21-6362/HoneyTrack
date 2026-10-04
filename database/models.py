from datetime import datetime

from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean

from .database import Base


class AttackEvent(Base):
    __tablename__ = "attack_events"

    id = Column(Integer, primary_key=True, index=True)

    timestamp = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    source_ip = Column(String(45), nullable=False, index=True)

    service = Column(String(20), nullable=False)

    username = Column(String(255), nullable=True)

    password = Column(String(255), nullable=True)

    command = Column(Text, nullable=True)

    user_agent = Column(Text, nullable=True)

    country = Column(String(100), nullable=True)

    city = Column(String(100), nullable=True)

    isp = Column(String(255), nullable=True)

    latitude = Column(Float, nullable=True)

    longitude = Column(Float, nullable=True)

    attack_type = Column(String(50), nullable=True)

    risk_score = Column(Integer, default=0)

    is_tor = Column(Boolean, default=False)
    is_demo = Column(Boolean, default=False, nullable=False, index=True)
    origin_node = Column(String(64), default="local", index=True)


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    reason = Column(String(255), nullable=True)
    risk_score = Column(Integer, default=0)
    country = Column(String(100), nullable=True)
    blocked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    blocked_by = Column(String(50), default="Manual Operator", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    origin_node = Column(String(64), default="local", index=True)


class SessionRecording(Base):
    __tablename__ = "session_recordings"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), unique=True, nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    service = Column(String(20), default="SSH", nullable=False)
    username = Column(String(255), nullable=True)
    commands_count = Column(Integer, default=0)
    duration_seconds = Column(Float, default=0.0)
    start_time = Column(DateTime, default=datetime.utcnow, nullable=False)
    end_time = Column(DateTime, nullable=True)
    replay_data = Column(Text, nullable=False)  # JSON-encoded array of [[offset_sec, "o"|"i", text], ...]
    is_demo = Column(Boolean, default=False, nullable=False, index=True)


class FederatedNode(Base):
    __tablename__ = "federated_nodes"

    id = Column(Integer, primary_key=True, index=True)
    node_id = Column(String(64), unique=True, nullable=False, index=True)
    node_name = Column(String(100), nullable=False)
    endpoint_url = Column(String(255), nullable=True)
    region = Column(String(100), default="Global")
    status = Column(String(20), default="online", index=True)
    last_heartbeat = Column(DateTime, default=datetime.utcnow)
    attacks_reported = Column(Integer, default=0)
    secret_key_hash = Column(String(255), nullable=True)
    is_trusted = Column(Boolean, default=True)
    is_hub = Column(Boolean, default=False)
    is_local = Column(Boolean, default=False)