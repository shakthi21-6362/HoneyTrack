"""
HoneyTrack — Main Entry Point

A defensive cybersecurity honeypot that deploys fake SSH, HTTP,
and FTP services to attract and profile real-world attackers.

Usage:
    python main.py               Start all honeypot listeners + dashboard
    python main.py --demo        Start in demo mode (fake attacks for presentations)
    python main.py --demo-only   Start only demo mode + dashboard (no listeners)
"""

import sys
import argparse
import signal
import threading
import time
import logging

from config.settings import (
    SSH_PORT, HTTP_PORT, FTP_PORT, DASHBOARD_PORT,
    DASHBOARD_HOST,
)

# ──────────────────────────────────────────────────────
# Configure logging
# ──────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("honeytrack")


# ──────────────────────────────────────────────────────
# ASCII Banner
# ──────────────────────────────────────────────────────

BANNER = r"""
  _   _                        _____               _
 | | | | ___  _ __   ___ _   _|_   _| __ __ _  ___| | __
 | |_| |/ _ \| '_ \ / _ \ | | | | | | '__/ _` |/ __| |/ /
 |  _  | (_) | | | |  __/ |_| | | | | | | (_| | (__|   <
 |_| |_|\___/|_| |_|\___|\__, | |_| |_|  \__,_|\___|_|\_\
                          |___/

  [+] Real-Time Honeypot Intelligence System
  =============================================
"""


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="HoneyTrack — Honeypot Intelligence System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py               Start all services (SSH + HTTP + FTP + Dashboard)
  python main.py --demo        Start all services + demo event generator
  python main.py --demo-only   Start only dashboard + demo generator (no listeners)
        """
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Enable demo mode: generate fake attacks alongside live listeners"
    )
    parser.add_argument(
        "--demo-only",
        action="store_true",
        help="Run only demo mode + dashboard (no honeypot listeners)"
    )
    parser.add_argument(
        "--no-ssh",
        action="store_true",
        help="Disable SSH honeypot listener"
    )
    parser.add_argument(
        "--no-http",
        action="store_true",
        help="Disable HTTP honeypot listener"
    )
    parser.add_argument(
        "--no-ftp",
        action="store_true",
        help="Disable FTP honeypot listener"
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=DASHBOARD_PORT,
        help=f"Dashboard port (default: {DASHBOARD_PORT})"
    )
    parser.add_argument(
        "--reset-live",
        action="store_true",
        help="Purge prior live production telemetry for a clean zero-attack start"
    )
    parser.add_argument(
        "--reset-all",
        action="store_true",
        help="Purge all attack telemetry (both live and demo simulation records)"
    )
    return parser.parse_args()


def start_listener_thread(name, target_func, **kwargs):
    """Start a honeypot listener in a daemon thread."""
    thread = threading.Thread(
        target=target_func,
        kwargs=kwargs,
        name=f"HoneyTrack-{name}",
        daemon=True
    )
    thread.start()
    return thread


def main():
    """Main entry point for HoneyTrack."""
    args = parse_args()

    # Set operational mode
    import config.settings as settings
    settings.IS_DEMO_MODE = bool(args.demo or args.demo_only)

    print(BANNER)
    if settings.IS_DEMO_MODE:
        logger.info("  [+] OPERATIONAL MODE: SIMULATION & DEMO GENERATOR")
    else:
        logger.info("  [+] OPERATIONAL MODE: LIVE PRODUCTION DEPLOYMENT")
        logger.info("  [*] Isolated from simulation — tracking pure live production attacks.")
    logger.info("  =============================================\n")

    # ── Initialize Database ──
    from database.database import init_db, SessionLocal
    from database.models import AttackEvent, BlockedIP, SessionRecording, FederatedNode
    init_db()

    # ── Handle Database Reset Flags ──
    if args.reset_live or args.reset_all:
        db = SessionLocal()
        try:
            if args.reset_all:
                evt_count = db.query(AttackEvent).delete()
                ip_count = db.query(BlockedIP).delete()
                sess_count = db.query(SessionRecording).delete()
                db.query(FederatedNode).filter(FederatedNode.node_id != settings.NODE_ID).delete()
                db.commit()
                logger.info(f"[MAIN] [+] Complete Reset: Cleared {evt_count} attacks, {ip_count} blocked IPs, {sess_count} recordings, and reset sensor nodes.")
            elif args.reset_live:
                count = db.query(AttackEvent).filter(AttackEvent.is_demo == False).delete()
                db.commit()
                logger.info(f"[MAIN] [+] Cleared {count} past live production attack records for a clean start.")
        except Exception as e:
            db.rollback()
            logger.error(f"[MAIN] [-] Failed to clear database: {e}")
        finally:
            db.close()

    threads = []

    # ── Start Honeypot Listeners ──
    if not args.demo_only:
        # SSH Honeypot
        if not args.no_ssh:
            try:
                logger.info(f"[MAIN] [+] Starting SSH honeypot on port {SSH_PORT}...")
                from honeypot.ssh_listener import start_ssh_honeypot
                t = start_listener_thread("SSH", start_ssh_honeypot)
                threads.append(t)
            except Exception as e:
                logger.error(f"[MAIN] [-] SSH honeypot failed: {e}")

        # HTTP Honeypot
        if not args.no_http:
            try:
                logger.info(f"[MAIN] [+] Starting HTTP honeypot on port {HTTP_PORT}...")
                from honeypot.http_listener import start_http_honeypot
                t = start_listener_thread("HTTP", start_http_honeypot)
                threads.append(t)
            except Exception as e:
                logger.error(f"[MAIN] [-] HTTP honeypot failed: {e}")

        # FTP Honeypot
        if not args.no_ftp:
            try:
                logger.info(f"[MAIN] [+] Starting FTP honeypot on port {FTP_PORT}...")
                from honeypot.ftp_listener import start_ftp_honeypot
                t = start_listener_thread("FTP", start_ftp_honeypot)
                threads.append(t)
            except Exception as e:
                logger.error(f"[MAIN] [-] FTP honeypot failed: {e}")

    # ── Start Demo Mode ──
    if args.demo or args.demo_only:
        from demo import start_demo_mode
        start_demo_mode()
        logger.info("[MAIN] [+] Demo mode activated")

    # ── Start Dashboard ──
    dashboard_port = args.dashboard_port
    logger.info("")
    logger.info("  ==========================================")
    logger.info(f"  [+] Dashboard -> http://localhost:{dashboard_port}")
    logger.info("  ==========================================")
    logger.info("")

    try:
        from api.app import start_dashboard
        start_dashboard(host=DASHBOARD_HOST, port=dashboard_port)
    except KeyboardInterrupt:
        logger.info("\n[MAIN] Shutting down HoneyTrack...")
    except Exception as e:
        logger.error(f"[MAIN] Dashboard failed: {e}")
        # Keep running if listeners are active
        if threads:
            logger.info("[MAIN] Listeners still running. Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("\n[MAIN] Shutting down HoneyTrack...")

    logger.info("[MAIN] HoneyTrack stopped. Goodbye!")


if __name__ == "__main__":
    main()