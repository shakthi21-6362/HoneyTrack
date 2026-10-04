"""
HoneyTrack — TOR Exit Node Detection Module

Provides high-performance, real-time Tor exit node identification:
1. In-memory set lookup for O(1) matching against Tor Project exit lists.
2. Background synchronization with official Tor bulk exit list (https://check.torproject.org/torbulkexitlist).
3. Fallback cache of verified Tor exit nodes for zero-latency offline operation.
4. Real-time DNS Exit List (DNSEL) fallback verification.
"""

import time
import socket
import logging
import threading
import requests
from datetime import datetime

logger = logging.getLogger(__name__)

TOR_BULK_EXIT_URL = "https://check.torproject.org/torbulkexitlist"
TOR_DNSEL_SUFFIX = "dnsel.torproject.org"
CACHE_TTL_SECONDS = 86400  # Refresh every 24 hours

# Verified seed list of known high-activity Tor Exit Nodes
# Ensures instantaneous detection even before network sync
SEED_TOR_EXIT_NODES = {
    "185.220.101.35",
    "185.220.101.45",
    "185.220.102.8",
    "185.220.101.5",
    "185.220.101.6",
    "185.220.101.7",
    "185.220.101.8",
    "185.220.101.9",
    "185.220.101.10",
    "185.220.101.11",
    "185.220.101.12",
    "185.220.101.13",
    "185.220.101.14",
    "185.220.101.15",
    "185.220.101.16",
    "185.220.101.17",
    "185.220.101.18",
    "185.220.101.19",
    "185.220.101.20",
    "199.249.230.70",
    "199.249.230.71",
    "199.249.230.72",
    "199.249.230.73",
    "199.249.230.74",
    "199.249.230.75",
    "199.249.230.76",
    "199.249.230.77",
    "199.249.230.78",
    "199.249.230.79",
    "199.249.230.80",
    "51.15.43.205",
    "171.25.193.77",
    "171.25.193.78",
    "178.17.170.101",
    "178.17.170.102",
    "193.218.118.177",
    "193.218.118.178",
    "109.70.100.18",
    "109.70.100.19",
    "109.70.100.20",
    "109.70.100.21",
    "45.66.35.35",
    "45.66.35.36",
    "45.66.35.37",
    "23.129.64.100",
    "23.129.64.101",
    "23.129.64.102",
    "23.129.64.103",
    "23.129.64.104",
    "23.129.64.105",
    "23.129.64.106",
    "23.129.64.107",
    "23.129.64.108",
    "23.129.64.109",
    "23.129.64.110",
}

_tor_nodes = set(SEED_TOR_EXIT_NODES)
_last_sync_time = 0
_sync_lock = threading.Lock()


def sync_tor_exit_nodes(force: bool = False):
    """
    Download and update the active Tor Exit Node list from official Tor Project servers.
    Runs safely without blocking the application.
    """
    global _tor_nodes, _last_sync_time

    current_time = time.time()
    if not force and (current_time - _last_sync_time < CACHE_TTL_SECONDS) and len(_tor_nodes) > len(SEED_TOR_EXIT_NODES):
        return len(_tor_nodes)

    with _sync_lock:
        try:
            resp = requests.get(TOR_BULK_EXIT_URL, timeout=8)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                fresh_nodes = set()
                for line in lines:
                    ip = line.strip()
                    if ip and not ip.startswith("#"):
                        fresh_nodes.add(ip)
                
                if fresh_nodes:
                    # Union with seed nodes to ensure no regressions
                    _tor_nodes = fresh_nodes.union(SEED_TOR_EXIT_NODES)
                    _last_sync_time = current_time
                    logger.info(f"[TOR DETECTOR] Successfully synchronized {len(_tor_nodes)} Tor Exit Nodes from Tor Project.")
                    return len(_tor_nodes)
        except Exception as e:
            logger.warning(f"[TOR DETECTOR] Online sync failed ({e}), using cached {len(_tor_nodes)} seed exit nodes.")
    
    return len(_tor_nodes)


def start_background_tor_sync():
    """Start automated background refresh daemon."""
    def _worker():
        sync_tor_exit_nodes(force=True)
        while True:
            time.sleep(CACHE_TTL_SECONDS)
            sync_tor_exit_nodes(force=True)

    thread = threading.Thread(target=_worker, name="TorExitSyncDaemon", daemon=True)
    thread.start()


def check_dns_tor_exit(ip: str) -> bool:
    """
    Query the Tor DNSEL service for real-time DNS-based exit node verification.
    Format: <d.c.b.a>.dnsel.torproject.org
    Returns True if response is 127.0.0.2 (active Tor exit node).
    """
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        reversed_ip = ".".join(reversed(parts))
        query_host = f"{reversed_ip}.{TOR_DNSEL_SUFFIX}"
        addr = socket.gethostbyname(query_host)
        return addr == "127.0.0.2"
    except Exception:
        return False


def is_tor_exit_node(ip: str, check_dns_fallback: bool = False) -> bool:
    """
    Check if an IP address is an active Tor exit node.
    
    Args:
        ip: Target IPv4 address
        check_dns_fallback: Whether to query dnsel.torproject.org if not in local cache
    
    Returns:
        bool: True if identified as a Tor Exit Node
    """
    if not ip or ip in ("127.0.0.1", "localhost", "0.0.0.0"):
        return False

    # 1. Fast O(1) in-memory set check
    if ip in _tor_nodes:
        return True

    # 2. Check if IP falls within known Tor Exit subnets
    if ip.startswith("185.220.101.") or ip.startswith("185.220.102.") or ip.startswith("23.129.64.") or ip.startswith("199.249.230."):
        return True

    # 3. Optional real-time DNS lookup for zero-day relays
    if check_dns_fallback:
        if check_dns_tor_exit(ip):
            _tor_nodes.add(ip)
            return True

    return False


def get_tor_stats() -> dict:
    """Return status metadata about the Tor detection system."""
    return {
        "active_exit_nodes_count": len(_tor_nodes),
        "last_sync_utc": datetime.utcfromtimestamp(_last_sync_time).isoformat() if _last_sync_time > 0 else "Seed Loaded",
        "dnsel_enabled": True
    }


# Automatically launch background synchronization on import
try:
    start_background_tor_sync()
except Exception:
    pass
