"""
HoneyTrack Node Manager & Federation Identity (v2.0)
====================================================
Manages sensor node identities, cryptographic HMAC signatures,
heartbeats, and node clustering.
"""

import hmac
import hashlib
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional

from config import settings
from database.database import SessionLocal
from database.models import FederatedNode

logger = logging.getLogger(__name__)


def generate_node_signature(payload_bytes: bytes, secret: Optional[str] = None) -> str:
    """Generates an HMAC-SHA256 hex digest for authenticating federated sync requests."""
    key = (secret or settings.FEDERATION_SECRET).encode('utf-8')
    return hmac.new(key, payload_bytes, hashlib.sha256).hexdigest()


def verify_node_signature(payload_bytes: bytes, signature: str, secret: Optional[str] = None) -> bool:
    """Cryptographically verifies incoming request signature in constant time."""
    if not signature or not isinstance(signature, str):
        return False
    expected = generate_node_signature(payload_bytes, secret)
    return hmac.compare_digest(expected.strip().lower(), signature.strip().lower())


def get_local_node_info() -> Dict[str, Any]:
    """Returns local sensor node identity and operating metadata."""
    return {
        "node_id": settings.NODE_ID,
        "node_name": settings.NODE_NAME,
        "region": settings.NODE_REGION,
        "status": "online",
        "is_hub": bool(settings.FEDERATION_HUB_URL == "" or settings.FEDERATION_HUB_URL is None),
        "sync_interval_sec": settings.FEDERATION_SYNC_INTERVAL_SEC,
        "federation_enabled": settings.FEDERATION_ENABLED
    }


class NodeManager:
    """Coordinates federated sensor nodes and peer telemetry."""

    def __init__(self):
        self._ensure_local_node_exists()

    def _ensure_local_node_exists(self):
        """Registers the local host node in the database if not present."""
        db = SessionLocal()
        try:
            local = db.query(FederatedNode).filter(FederatedNode.node_id == settings.NODE_ID).first()
            if not local:
                local = FederatedNode(
                    node_id=settings.NODE_ID,
                    node_name=settings.NODE_NAME,
                    region=settings.NODE_REGION,
                    status="online",
                    last_heartbeat=datetime.now(timezone.utc),
                    is_trusted=True,
                    is_hub=bool(not settings.FEDERATION_HUB_URL),
                    is_local=True
                )
                db.add(local)
                db.commit()
            else:
                local.node_name = settings.NODE_NAME
                local.region = settings.NODE_REGION
                local.status = "online"
                local.last_heartbeat = datetime.now(timezone.utc)
                local.is_local = True
                db.commit()
        except Exception as e:
            logger.error(f"[FEDERATION] Error registering local node: {e}")
            db.rollback()
        finally:
            db.close()

    def register_or_update_node(
        self,
        node_id: str,
        node_name: str,
        region: str = "Global",
        endpoint_url: Optional[str] = None,
        is_hub: bool = False,
        attacks_reported: int = 0
    ) -> Dict[str, Any]:
        """Registers a remote sensor node or updates an existing one."""
        if not node_id:
            raise ValueError("node_id is required.")

        db = SessionLocal()
        try:
            node = db.query(FederatedNode).filter(FederatedNode.node_id == node_id).first()
            now = datetime.now(timezone.utc)
            if not node:
                node = FederatedNode(
                    node_id=node_id,
                    node_name=node_name or node_id,
                    region=region or "Global",
                    endpoint_url=endpoint_url,
                    status="online",
                    last_heartbeat=now,
                    attacks_reported=attacks_reported,
                    is_trusted=True,
                    is_hub=is_hub,
                    is_local=(node_id == settings.NODE_ID)
                )
                db.add(node)
            else:
                node.node_name = node_name or node.node_name
                node.region = region or node.region
                if endpoint_url is not None:
                    node.endpoint_url = endpoint_url
                node.status = "online"
                node.last_heartbeat = now
                node.attacks_reported = max(node.attacks_reported, attacks_reported)
                node.is_hub = is_hub

            db.commit()
            return {
                "node_id": node.node_id,
                "node_name": node.node_name,
                "region": node.region,
                "status": node.status,
                "attacks_reported": node.attacks_reported
            }
        finally:
            db.close()

    def record_heartbeat(self, node_id: str, attacks_count: Optional[int] = None) -> bool:
        """Records a heartbeat beacon from a remote sensor node."""
        db = SessionLocal()
        try:
            node = db.query(FederatedNode).filter(FederatedNode.node_id == node_id).first()
            if not node:
                return False
            node.last_heartbeat = datetime.now(timezone.utc)
            node.status = "online"
            if attacks_count is not None:
                node.attacks_reported = attacks_count
            db.commit()
            return True
        finally:
            db.close()

    def get_nodes(self, include_offline: bool = True) -> List[Dict[str, Any]]:
        """Retrieves list of registered sensor nodes with live status."""
        db = SessionLocal()
        try:
            nodes = db.query(FederatedNode).all()
            now = datetime.now(timezone.utc)
            results = []
            for n in nodes:
                # Mark offline if no heartbeat within 120 seconds (unless local node)
                last_hb = n.last_heartbeat
                if last_hb and last_hb.tzinfo is None:
                    last_hb = last_hb.replace(tzinfo=timezone.utc)

                is_stale = False
                if last_hb:
                    is_stale = (now - last_hb) > timedelta(seconds=120)

                current_status = n.status
                if is_stale and not n.is_local:
                    current_status = "offline"

                results.append({
                    "node_id": n.node_id,
                    "node_name": n.node_name,
                    "endpoint_url": n.endpoint_url,
                    "region": n.region,
                    "status": current_status,
                    "last_heartbeat": n.last_heartbeat.isoformat() if n.last_heartbeat else None,
                    "attacks_reported": n.attacks_reported,
                    "is_trusted": n.is_trusted,
                    "is_hub": n.is_hub,
                    "is_local": n.is_local
                })
            return results
        finally:
            db.close()


# Global singleton instance
node_manager = NodeManager()


def register_or_update_node(node_id: str, node_name: str, region: str = "Global", endpoint_url: Optional[str] = None, is_hub: bool = False, attacks_reported: int = 0) -> Dict[str, Any]:
    return node_manager.register_or_update_node(node_id, node_name, region, endpoint_url, is_hub, attacks_reported)


def record_heartbeat(node_id: str, attacks_count: Optional[int] = None) -> bool:
    return node_manager.record_heartbeat(node_id, attacks_count)


def get_federated_nodes(include_offline: bool = True) -> List[Dict[str, Any]]:
    return node_manager.get_nodes(include_offline=include_offline)


def seed_default_demo_nodes():
    """Seeds diverse global sensor nodes for multi-region demonstration."""
    demo_nodes = [
        ("node-eu-frankfurt", "Sensor Node (Frankfurt)", "EU-Central (Germany)", "https://de.sensor.honeytrack.net", 412),
        ("node-us-virginia", "Sensor Node (N. Virginia)", "US-East (USA)", "https://us.sensor.honeytrack.net", 789),
        ("node-ap-singapore", "Sensor Node (Singapore)", "AP-Southeast (Singapore)", "https://sg.sensor.honeytrack.net", 245),
        ("node-sa-saopaulo", "Sensor Node (São Paulo)", "SA-East (Brazil)", "https://br.sensor.honeytrack.net", 188),
    ]
    for nid, name, reg, url, attacks in demo_nodes:
        register_or_update_node(
            node_id=nid,
            node_name=name,
            region=reg,
            endpoint_url=url,
            is_hub=False,
            attacks_reported=attacks
        )
