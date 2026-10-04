"""
HoneyTrack — Active Defense & Firewall Automation
Manages IP blacklisting, OS firewall rule generation (iptables, ufw, Windows netsh),
automated threat mitigation, and real-time packet dropping on decoy honeypots.
"""

import sys
import subprocess
import logging
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from config import settings
from database.database import SessionLocal
from database.models import BlockedIP

logger = logging.getLogger(__name__)

# Thread-safe in-memory cache of active blocked IP addresses
_blocked_ips_cache: set = set()
_cache_lock = threading.Lock()
_cache_initialized = False


def _init_cache_if_needed():
    """Load all currently active blocked IPs into memory for O(1) checks."""
    global _blocked_ips_cache, _cache_initialized
    if _cache_initialized:
        return

    with _cache_lock:
        if _cache_initialized:
            return
        db = SessionLocal()
        try:
            blocked = db.query(BlockedIP.ip_address).filter(BlockedIP.is_active == True).all()
            _blocked_ips_cache = {row[0] for row in blocked}
            _cache_initialized = True
            logger.info(f"[FIREWALL] Loaded {len(_blocked_ips_cache)} active blacklisted IPs into memory cache.")
        except Exception as e:
            logger.error(f"[FIREWALL] Failed to initialize blacklist cache: {e}")
        finally:
            db.close()


import ipaddress


def validate_ip_address(ip_str: str) -> str:
    """
    Validates that the provided string is strictly a valid IPv4 or IPv6 address.
    Neutralizes any command injection attempts or illegal metacharacters.
    """
    if not ip_str or not isinstance(ip_str, str):
        raise ValueError("IP address must be a non-empty string.")

    cleaned = ip_str.strip().replace("::ffff:", "")
    if cleaned in ("localhost", "127.0.0.1", "::1"):
        return "127.0.0.1"

    try:
        ip_obj = ipaddress.ip_address(cleaned)
        return str(ip_obj)
    except ValueError:
        raise ValueError(f"Security error: Invalid IP address format '{ip_str}'")


def is_ip_blocked(ip: str) -> bool:
    """Fast check whether an IP is currently blocked by active defense."""
    if not ip:
        return False
    _init_cache_if_needed()
    try:
        clean_ip = validate_ip_address(ip)
    except ValueError:
        return False

    with _cache_lock:
        if clean_ip in _blocked_ips_cache or ip in _blocked_ips_cache:
            return True
        if clean_ip in ("127.0.0.1", "localhost", "::1"):
            return ("127.0.0.1" in _blocked_ips_cache or "localhost" in _blocked_ips_cache or "::1" in _blocked_ips_cache)
        return False


def generate_firewall_commands(ip: str) -> Dict[str, str]:
    """
    Generates ready-to-run system firewall blocking and unblocking commands
    for Linux (ufw, iptables) and Windows (netsh advfirewall).
    """
    try:
        clean_ip = validate_ip_address(ip)
    except ValueError:
        clean_ip = "0.0.0.0"

    return {
        "ip": clean_ip,
        "iptables_block": f"sudo iptables -I INPUT -s {clean_ip} -j DROP -m comment --comment 'HoneyTrack Auto-Block'",
        "iptables_unblock": f"sudo iptables -D INPUT -s {clean_ip} -j DROP",
        "ufw_block": f"sudo ufw insert 1 deny from {clean_ip} to any comment 'HoneyTrack Auto-Block'",
        "ufw_unblock": f"sudo ufw delete deny from {clean_ip}",
        "windows_netsh_block": f'netsh advfirewall firewall add rule name="HoneyTrack Block {clean_ip}" dir=in action=block remoteip={clean_ip}',
        "windows_netsh_unblock": f'netsh advfirewall firewall delete rule name="HoneyTrack Block {clean_ip}"'
    }


def block_ip(
    ip: str,
    reason: str = "High Risk Adversary Intrusion",
    risk_score: int = 0,
    country: str = "Unknown",
    blocked_by: str = "Operator",
    execute_system: Optional[bool] = None
) -> Tuple[bool, str]:
    """
    Blacklists an IP address in the HoneyTrack active defense database
    and optionally executes host firewall blocking rules.
    """
    try:
        clean_ip = validate_ip_address(ip)
    except ValueError as e:
        return False, str(e)

    _init_cache_if_needed()
    db = SessionLocal()
    try:
        record = db.query(BlockedIP).filter(BlockedIP.ip_address == clean_ip).first()
        if record:
            record.is_active = True
            record.reason = reason
            record.risk_score = risk_score
            record.country = country or record.country
            record.blocked_at = datetime.now(timezone.utc)
            record.blocked_by = blocked_by
        else:
            record = BlockedIP(
                ip_address=clean_ip,
                reason=reason,
                risk_score=risk_score,
                country=country or "Unknown",
                blocked_at=datetime.now(timezone.utc),
                blocked_by=blocked_by,
                is_active=True
            )
            db.add(record)
        db.commit()

        with _cache_lock:
            _blocked_ips_cache.add(clean_ip)
            if clean_ip in ("127.0.0.1", "localhost", "::1"):
                _blocked_ips_cache.update(["127.0.0.1", "localhost", "::1"])

        print(f"[FIREWALL] Blacklisted IP {clean_ip} | Reason: {reason} | By: {blocked_by}")
        logger.info(f"[FIREWALL] Blacklisted IP {clean_ip} ({reason}) by {blocked_by}")

        # Optional OS firewall command execution
        should_exec = execute_system if execute_system is not None else settings.FIREWALL_EXECUTE_SYSTEM_RULES
        sys_msg = ""
        if should_exec:
            sys_ok, sys_err = _execute_os_block(clean_ip)
            sys_msg = f" (System rule: {'Applied' if sys_ok else 'Failed - ' + sys_err})"

        return True, f"IP {clean_ip} successfully blacklisted.{sys_msg}"
    except Exception as e:
        db.rollback()
        logger.error(f"[FIREWALL] Error blacklisting {clean_ip}: {e}")
        return False, str(e)
    finally:
        db.close()


def unblock_ip(ip: str, execute_system: Optional[bool] = None) -> Tuple[bool, str]:
    """
    Removes an IP address from the active defense blacklist.
    """
    if not ip:
        return False, "No IP address specified."

    clean_ip = ip.strip().replace("::ffff:", "")

    _init_cache_if_needed()
    db = SessionLocal()
    try:
        if clean_ip in ("127.0.0.1", "localhost", "::1"):
            records = db.query(BlockedIP).filter(BlockedIP.ip_address.in_(["127.0.0.1", "localhost", "::1"])).all()
            for r in records:
                r.is_active = False
            db.commit()
            with _cache_lock:
                _blocked_ips_cache.difference_update(["127.0.0.1", "localhost", "::1"])
            print(f"[FIREWALL] Unblocked local address from active defense.")
            return True, f"IP {clean_ip} successfully unblocked."

        record = db.query(BlockedIP).filter(BlockedIP.ip_address == clean_ip).first()
        if not record:
            return False, f"IP {clean_ip} is not currently blacklisted."

        record.is_active = False
        db.commit()

        with _cache_lock:
            _blocked_ips_cache.discard(clean_ip)

        print(f"[FIREWALL] Unblocked IP {clean_ip} from active defense.")
        logger.info(f"[FIREWALL] Unblocked IP {clean_ip}")

        should_exec = execute_system if execute_system is not None else settings.FIREWALL_EXECUTE_SYSTEM_RULES
        sys_msg = ""
        if should_exec:
            sys_ok, sys_err = _execute_os_unblock(ip)
            sys_msg = f" (System rule: {'Removed' if sys_ok else 'Failed - ' + sys_err})"

        return True, f"IP {ip} successfully unblocked.{sys_msg}"
    except Exception as e:
        db.rollback()
        logger.error(f"[FIREWALL] Error unblocking {ip}: {e}")
        return False, str(e)
    finally:
        db.close()


def check_and_auto_block(event_data: dict) -> bool:
    """
    Evaluates an incoming attack event against automated firewall policies.
    Returns True if the IP was auto-blocked, False otherwise.
    """
    if not settings.FIREWALL_AUTO_BLOCK_ENABLED:
        return False

    source_ip = event_data.get("source_ip")
    if not source_ip or is_ip_blocked(source_ip):
        return False

    risk_score = event_data.get("risk_score", 0)
    is_tor = event_data.get("is_tor", False)

    should_block = False
    reason = ""

    if risk_score >= settings.FIREWALL_AUTO_BLOCK_THRESHOLD:
        should_block = True
        reason = f"Automated defense: Critical threat score ({risk_score}/100)"
    elif is_tor and settings.FIREWALL_BLOCK_TOR_EXIT_NODES:
        should_block = True
        reason = "Automated defense: Malicious Tor exit node detected"

    if should_block:
        success, _ = block_ip(
            ip=source_ip,
            reason=reason,
            risk_score=risk_score,
            country=event_data.get("country", "Unknown"),
            blocked_by="Auto-Defense Engine"
        )
        return success

    return False


def get_all_blocked_ips(active_only: bool = True) -> List[Dict]:
    """Retrieve all blacklisted IP records from the database."""
    _init_cache_if_needed()
    db = SessionLocal()
    try:
        query = db.query(BlockedIP)
        if active_only:
            query = query.filter(BlockedIP.is_active == True)
        records = query.order_by(BlockedIP.blocked_at.desc()).all()

        return [
            {
                "id": r.id,
                "ip_address": r.ip_address,
                "reason": r.reason,
                "risk_score": r.risk_score,
                "country": r.country,
                "blocked_at": r.blocked_at.isoformat() if r.blocked_at else None,
                "blocked_by": r.blocked_by,
                "is_active": r.is_active,
                "commands": generate_firewall_commands(r.ip_address)
            }
            for r in records
        ]
    finally:
        db.close()


def _execute_os_block(ip: str) -> Tuple[bool, str]:
    """Executes host OS firewall block rule safely without shell interpolation."""
    try:
        valid_ip = validate_ip_address(ip)
    except ValueError as e:
        return False, str(e)

    is_windows = sys.platform.startswith("win")
    try:
        if is_windows:
            rule_name = f"HoneyTrack Block {valid_ip}"
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=block", f"remoteip={valid_ip}"]
            res = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return True, "Rule applied"
            return False, res.stderr.strip() or res.stdout.strip()
        else:
            cmd = ["ufw", "insert", "1", "deny", "from", valid_ip, "to", "any", "comment", "HoneyTrack Auto-Block"]
            res = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return True, "UFW rule applied"
            cmd_ip = ["iptables", "-I", "INPUT", "-s", valid_ip, "-j", "DROP"]
            res2 = subprocess.run(cmd_ip, shell=False, capture_output=True, text=True, timeout=5)
            if res2.returncode == 0:
                return True, "iptables rule applied"
            return False, res.stderr.strip() or res2.stderr.strip()
    except Exception as e:
        return False, str(e)


def _execute_os_unblock(ip: str) -> Tuple[bool, str]:
    """Removes host OS firewall block rule safely without shell interpolation."""
    try:
        valid_ip = validate_ip_address(ip)
    except ValueError as e:
        return False, str(e)

    is_windows = sys.platform.startswith("win")
    try:
        if is_windows:
            rule_name = f"HoneyTrack Block {valid_ip}"
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            res = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=5)
            return (res.returncode == 0), (res.stderr.strip() or res.stdout.strip())
        else:
            cmd = ["ufw", "delete", "deny", "from", valid_ip]
            res = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return True, "UFW rule removed"
            cmd_ip = ["iptables", "-D", "INPUT", "-s", valid_ip, "-j", "DROP"]
            res2 = subprocess.run(cmd_ip, shell=False, capture_output=True, text=True, timeout=5)
            return (res2.returncode == 0), (res.stderr.strip() or res2.stderr.strip())
    except Exception as e:
        return False, str(e)
