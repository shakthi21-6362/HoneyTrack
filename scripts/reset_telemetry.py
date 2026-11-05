"""
HoneyTrack - Database Telemetry & Federation Reset Utility
Purges demo simulation records and mock test nodes so HoneyTrack
runs cleanly in pure live production mode.
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.database import SessionLocal, init_db
from database.models import AttackEvent, BlockedIP, SessionRecording, FederatedNode
from config import settings

def reset_to_clean_live(purge_all_attacks=True, purge_users=False):
    """Resets the database so only pure live telemetry will be captured."""
    init_db()
    db = SessionLocal()
    try:
        # 1. Reset federated nodes: keep ONLY the authentic local primary node
        nodes_deleted = db.query(FederatedNode).filter(FederatedNode.node_id != settings.NODE_ID).delete()
        
        # 2. Reset attack telemetry
        if purge_all_attacks:
            attacks_deleted = db.query(AttackEvent).delete()
            label = "all (demo + prior live)"
        else:
            attacks_deleted = db.query(AttackEvent).filter(AttackEvent.is_demo == True).delete()
            label = "simulation demo"

        blocked_deleted = db.query(BlockedIP).delete()
        sessions_deleted = db.query(SessionRecording).delete()

        users_deleted = 0
        if purge_users:
            from database.user_model import User
            users_deleted = db.query(User).delete()

        db.commit()

        # 3. If running on TimescaleDB, also reset SQLite files so everything stays pristine
        import sqlite3
        for db_file in [os.path.join(settings.BASE_DIR, "honeytrack.db"), os.path.join(settings.BASE_DIR, "data", "honeytrack.db")]:
            if os.path.exists(db_file):
                try:
                    c = sqlite3.connect(db_file)
                    c.execute("DELETE FROM attack_events;")
                    c.execute("DELETE FROM blocked_ips;")
                    c.execute("DELETE FROM session_recordings;")
                    c.execute(f"DELETE FROM federated_nodes WHERE node_id != '{settings.NODE_ID}';")
                    if purge_users:
                        c.execute("DELETE FROM users;")
                    c.commit()
                    c.close()
                except Exception:
                    pass

        print("[+] HoneyTrack Database Reset Complete:")
        print(f"    - Cleared {attacks_deleted} {label} attack records.")
        print(f"    - Cleared {blocked_deleted} blocked IP records.")
        print(f"    - Cleared {sessions_deleted} raw session recordings.")
        print(f"    - Removed {nodes_deleted} mock/test federated nodes (retained 1 local primary sensor).")
        if purge_users:
            print(f"    - Cleared {users_deleted} operator accounts.")
        print("[*] HoneyTrack is now in a pristine state for live production honeypot tracking.")
    except Exception as e:
        db.rollback()
        print(f"[-] Error resetting database: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    purge_all = "--keep-live" not in sys.argv
    purge_u = "--reset-users" in sys.argv or "--all" in sys.argv
    reset_to_clean_live(purge_all_attacks=purge_all, purge_users=purge_u)
