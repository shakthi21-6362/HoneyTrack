"""
HoneyTrack Node Federation Package (v2.0)
=========================================
Distributed threat intelligence sharing, peer sensor synchronization,
and collaborative active defense network.
"""

from .node_manager import (
    node_manager,
    NodeManager,
    generate_node_signature,
    verify_node_signature,
    get_local_node_info,
    register_or_update_node,
    record_heartbeat,
    get_federated_nodes,
    seed_default_demo_nodes
)
from .sync import (
    threat_sync,
    ThreatSyncEngine,
    export_local_threat_intel,
    ingest_federated_threat_intel
)

__all__ = [
    "node_manager",
    "NodeManager",
    "threat_sync",
    "ThreatSyncEngine",
    "generate_node_signature",
    "verify_node_signature",
    "get_local_node_info",
    "register_or_update_node",
    "record_heartbeat",
    "get_federated_nodes",
    "seed_default_demo_nodes",
    "export_local_threat_intel",
    "ingest_federated_threat_intel"
]
