"""
HoneyTrack Federated Threat Intelligence Exchange (FTIX) (v2.0)
===============================================================
Exchanges IoCs, high-risk attacks, and active defense blacklists
across distributed sensor nodes with HMAC signature verification.
"""

import time
import json
import logging
import threading
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from config import settings
from database.database import SessionLocal
from database.models import AttackEvent, BlockedIP, FederatedNode
from defense.firewall import block_ip, is_ip_blocked
from federation.node_manager import record_heartbeat

logger = logging.getLogger(__name__)


def export_local_threat_intel(limit: int = 100) -> Dict[str, Any]:
    """
    Exports local indicators of compromise (IoCs) and high-risk attacks
    for distribution to peer federated sensor nodes.
    """
    db = SessionLocal()
    try:
        # 1. Active blacklisted IPs
        blocked_records = db.query(BlockedIP).filter(BlockedIP.is_active == True).limit(limit).all()
        blocked_ips = []
        for b in blocked_records:
            blocked_ips.append({
                "ip": b.ip_address,
                "reason": b.reason,
                "risk_score": b.risk_score,
                "country": b.country,
                "blocked_at": b.blocked_at.isoformat() if b.blocked_at else None,
                "origin_node": getattr(b, "origin_node", "local")
            })

        # 2. Critical threat events (risk_score >= 70)
        events_records = (
            db.query(AttackEvent)
            .filter(AttackEvent.risk_score >= 70)
            .order_by(AttackEvent.timestamp.desc())
            .limit(limit)
            .all()
        )
        critical_events = []
        for e in events_records:
            critical_events.append({
                "source_ip": e.source_ip,
                "service": e.service,
                "username": e.username,
                "command": e.command,
                "attack_type": e.attack_type,
                "risk_score": e.risk_score,
                "country": e.country,
                "city": e.city,
                "isp": e.isp,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "origin_node": getattr(e, "origin_node", "local")
            })

        return {
            "origin_node": settings.NODE_ID,
            "node_name": settings.NODE_NAME,
            "region": settings.NODE_REGION,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "blocked_ips": blocked_ips,
            "critical_events": critical_events
        }
    finally:
        db.close()


def ingest_federated_threat_intel(payload: Dict[str, Any], origin_node: str) -> Dict[str, Any]:
    """
    Ingests IoCs and threat intel received from a federated peer node.
    Automatically propagates blacklisted malicious IPs into local active defense!
    """
    remote_node_id = payload.get("origin_node") or origin_node
    blocked_list = payload.get("blocked_ips", [])
    events_list = payload.get("critical_events", [])

    new_blocks = 0
    new_events = 0

    # 1. Ingest Blocked IPs into local defense
    for b in blocked_list:
        ip = b.get("ip")
        if not ip:
            continue
        if not is_ip_blocked(ip):
            reason = f"Federated IoC from {remote_node_id}: {b.get('reason', 'Malicious intrusion')}"
            success, msg = block_ip(
                ip=ip,
                reason=reason,
                risk_score=b.get("risk_score", 85),
                country=b.get("country", "Unknown"),
                blocked_by=f"Federation ({remote_node_id})"
            )
            if success:
                new_blocks += 1

    # 2. Ingest critical events
    db = SessionLocal()
    try:
        for e in events_list:
            src_ip = e.get("source_ip")
            if not src_ip:
                continue
            # Avoid storing duplicates within same hour
            evt = AttackEvent(
                source_ip=src_ip,
                service=e.get("service", "SSH"),
                username=e.get("username"),
                password=None,
                command=e.get("command"),
                user_agent=None,
                country=e.get("country"),
                city=e.get("city"),
                isp=e.get("isp"),
                attack_type=e.get("attack_type"),
                risk_score=e.get("risk_score", 70),
                is_tor=False,
                is_demo=False,
                origin_node=remote_node_id
            )
            db.add(evt)
            new_events += 1
        db.commit()
    except Exception as err:
        logger.error(f"[FEDERATION] Error ingesting events: {err}")
        db.rollback()
    finally:
        db.close()

    # Record heartbeat and update attacks count for remote node
    record_heartbeat(remote_node_id, attacks_count=len(events_list))

    logger.info(f"[FEDERATION] Ingested intel from {remote_node_id}: {new_blocks} new blocked IPs, {new_events} events")

    return {
        "status": "success",
        "origin_node": remote_node_id,
        "synced_blocked_ips": new_blocks,
        "synced_events": new_events,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


class ThreatSyncEngine:
    """Manages periodic threat intelligence synchronization with remote nodes."""

    def __init__(self):
        self._running = False
        self._worker_thread = None

    def start(self):
        """Starts the background federation sync worker daemon."""
        if self._running or not settings.FEDERATION_ENABLED:
            return
        self._running = True
        self._worker_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self._worker_thread.start()
        logger.info("[FEDERATION] Threat sync engine started.")

    def stop(self):
        """Stops the sync worker."""
        self._running = False

    def _sync_loop(self):
        """Periodic sync cycle."""
        while self._running:
            try:
                # If configured with a hub URL, sync with hub
                if settings.FEDERATION_HUB_URL:
                    self._sync_with_hub(settings.FEDERATION_HUB_URL)
            except Exception as e:
                logger.error(f"[FEDERATION] Sync loop error: {e}")

            time.sleep(settings.FEDERATION_SYNC_INTERVAL_SEC)

    def _sync_with_hub(self, hub_url: str):
        """Pushes local intel to Hub and pulls global federated blacklist."""
        import requests
        from federation.node_manager import generate_node_signature
        try:
            intel = export_local_threat_intel(limit=50)
            payload_bytes = json.dumps(intel).encode('utf-8')
            signature = generate_node_signature(payload_bytes)

            headers = {
                "Content-Type": "application/json",
                "X-HoneyTrack-Node-Id": settings.NODE_ID,
                "X-HoneyTrack-Signature": signature
            }

            resp = requests.post(
                f"{hub_url.rstrip('/')}/api/federation/sync",
                data=payload_bytes,
                headers=headers,
                timeout=10
            )
            if resp.status_code == 200:
                hub_data = resp.json()
                if "hub_intel" in hub_data:
                    ingest_federated_threat_intel(hub_data["hub_intel"], origin_node="Hub")
        except Exception as e:
            logger.debug(f"[FEDERATION] Hub sync communication skipped: {e}")


# Global singleton instance
threat_sync = ThreatSyncEngine()
