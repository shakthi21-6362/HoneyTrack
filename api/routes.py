import io
from datetime import datetime
from flask import Blueprint, jsonify, request, render_template, session, redirect, send_file
from sqlalchemy import func, desc, distinct
from database.database import SessionLocal
from database.models import AttackEvent
import config.settings as settings

api_bp = Blueprint('api', __name__)


def get_current_mode():
    """
    Returns active operating mode: 'production', 'demo', or 'all'.
    Defaults to the server's running configuration.
    """
    mode = request.args.get('mode', default=None, type=str)
    if mode in ('production', 'demo', 'all'):
        return mode
    return 'demo' if settings.IS_DEMO_MODE else 'production'


def apply_mode_filter(query, mode=None):
    """
    Strictly partitions live production sensor activity from demo simulations.
    In 'production' mode: returns only authentic honeypot attacks (is_demo == False).
    In 'demo' mode: returns simulation attacks (is_demo == True).
    In 'all' mode: returns unpartitioned database records.
    """
    if mode is None:
        mode = get_current_mode()
    if mode == 'production':
        return query.filter(AttackEvent.is_demo == False)
    elif mode == 'demo':
        return query.filter(AttackEvent.is_demo == True)
    return query


@api_bp.before_request
def enforce_authentication():
    """
    Enforces operator session authentication.
    - Page views (/ and /dashboard) redirect unauthenticated users to /login.
    - API endpoints (/api/*) reject unauthenticated requests with HTTP 401.
    """
    if request.path in ('/', '/dashboard'):
        if not session.get('user_id'):
            return redirect('/login')
        return None

    if request.path.startswith('/api/'):
        # Machine-to-machine federation endpoints can authenticate via HMAC signature
        if request.path in ('/api/federation/sync', '/api/federation/register', '/api/federation/heartbeat'):
            sig = request.headers.get('X-HoneyTrack-Signature')
            node_id = request.headers.get('X-HoneyTrack-Node-Id')
            if sig and node_id:
                from federation.node_manager import verify_node_signature
                if verify_node_signature(request.get_data(), sig):
                    return None  # Authenticated cryptographically via HMAC
            if session.get('user_id'):
                return None
            return jsonify({
                "error": "Unauthorized",
                "message": "Valid X-HoneyTrack-Signature or active operator session required."
            }), 401

        if not session.get('user_id'):
            return jsonify({
                "error": "Unauthorized",
                "message": "Authentication required. Please sign in to the HoneyTrack operator console."
            }), 401
    return None


@api_bp.route('/')
@api_bp.route('/dashboard')
def index():
    """Serves the dashboard template directly."""
    current_mode = "DEMO" if settings.IS_DEMO_MODE else "PRODUCTION"
    return render_template('dashboard.html', 
                           user_name=session.get('user_name', 'Ghost'),
                           user_email=session.get('user_email', 'shakthin21@gmail.com'),
                           system_mode=current_mode)


@api_bp.route('/api/events', methods=['GET'])
def get_events():
    """Get list of events with pagination and filtering."""
    db = SessionLocal()
    try:
        limit = request.args.get('limit', default=200, type=int)
        offset = request.args.get('offset', default=0, type=int)
        service_filter = request.args.get('service', default=None, type=str)
        min_risk_filter = request.args.get('min_risk', default=None, type=float)
        search = request.args.get('search', default=None, type=str)

        query = db.query(AttackEvent)
        query = apply_mode_filter(query)

        if service_filter and service_filter != 'ALL':
            query = query.filter(AttackEvent.service == service_filter)
        if min_risk_filter is not None:
            query = query.filter(AttackEvent.risk_score >= min_risk_filter)
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                (AttackEvent.source_ip.like(search_pattern)) |
                (AttackEvent.command.like(search_pattern)) |
                (AttackEvent.username.like(search_pattern)) |
                (AttackEvent.country.like(search_pattern)) |
                (AttackEvent.city.like(search_pattern)) |
                (AttackEvent.isp.like(search_pattern))
            )

        events = query.order_by(desc(AttackEvent.timestamp)).offset(offset).limit(limit).all()

        events_list = [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "source_ip": e.source_ip,
                "service": e.service,
                "username": e.username,
                "password": e.password,
                "command": e.command,
                "user_agent": e.user_agent,
                "country": e.country,
                "city": e.city,
                "isp": e.isp,
                "latitude": e.latitude,
                "longitude": e.longitude,
                "attack_type": e.attack_type,
                "risk_score": e.risk_score,
                "is_tor": e.is_tor,
                "is_demo": e.is_demo
            }
            for e in events
        ]
        return jsonify(events_list)
    except Exception as e:
        print(f"[API] Error in /api/events: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


@api_bp.route('/api/events/latest', methods=['GET'])
def get_latest_events():
    """Get events since a specific ID for polling."""
    db = SessionLocal()
    try:
        since_id = request.args.get('since_id', default=0, type=int)
        query = db.query(AttackEvent).filter(AttackEvent.id > since_id)
        query = apply_mode_filter(query)
        events = query.order_by(desc(AttackEvent.timestamp)).all()

        events_list = [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "source_ip": e.source_ip,
                "service": e.service,
                "username": e.username,
                "password": e.password,
                "command": e.command,
                "user_agent": e.user_agent,
                "country": e.country,
                "city": e.city,
                "isp": e.isp,
                "latitude": e.latitude,
                "longitude": e.longitude,
                "attack_type": e.attack_type,
                "risk_score": e.risk_score,
                "is_tor": e.is_tor,
                "is_demo": e.is_demo
            }
            for e in events
        ]
        return jsonify(events_list)
    except Exception as e:
        print(f"[API] Error in /api/events/latest: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


@api_bp.route('/api/stats', methods=['GET'])
def get_stats():
    """Get statistical data for the dashboard isolated by operational mode."""
    db = SessionLocal()
    try:
        mode = get_current_mode()

        total_attacks = apply_mode_filter(db.query(func.count(AttackEvent.id)), mode).scalar() or 0
        unique_ips = apply_mode_filter(db.query(func.count(distinct(AttackEvent.source_ip))), mode).scalar() or 0
        unique_countries = apply_mode_filter(db.query(func.count(distinct(AttackEvent.country))), mode).scalar() or 0
        
        latest_event = apply_mode_filter(db.query(AttackEvent), mode).order_by(desc(AttackEvent.timestamp)).first()
        latest_attack = {
            "id": latest_event.id,
            "timestamp": latest_event.timestamp.isoformat() if latest_event.timestamp else None,
            "source_ip": latest_event.source_ip,
            "service": latest_event.service,
            "country": latest_event.country,
            "city": latest_event.city,
            "attack_type": latest_event.attack_type,
            "risk_score": latest_event.risk_score,
            "is_tor": latest_event.is_tor
        } if latest_event else None

        # Services count
        services_data = apply_mode_filter(db.query(AttackEvent.service, func.count(AttackEvent.id)), mode).group_by(AttackEvent.service).all()
        services = {service: count for service, count in services_data if service}
        
        # Risk distribution
        low_count = apply_mode_filter(db.query(func.count(AttackEvent.id)).filter(AttackEvent.risk_score < 40), mode).scalar() or 0
        medium_count = apply_mode_filter(db.query(func.count(AttackEvent.id)).filter(AttackEvent.risk_score >= 40, AttackEvent.risk_score < 70), mode).scalar() or 0
        high_count = apply_mode_filter(db.query(func.count(AttackEvent.id)).filter(AttackEvent.risk_score >= 70, AttackEvent.risk_score < 90), mode).scalar() or 0
        critical_count = apply_mode_filter(db.query(func.count(AttackEvent.id)).filter(AttackEvent.risk_score >= 90), mode).scalar() or 0
        
        risk_distribution = {
            "low": low_count,
            "medium": medium_count,
            "high": high_count,
            "critical": critical_count
        }

        # Top 10 countries
        top_countries_data = apply_mode_filter(
            db.query(AttackEvent.country, func.count(AttackEvent.id).label('count')), mode
        ).group_by(AttackEvent.country).order_by(desc('count')).limit(10).all()
        top_countries = [{"country": c[0] if c[0] else "Unknown", "count": c[1]} for c in top_countries_data]

        # Top 10 usernames
        top_usernames_data = apply_mode_filter(
            db.query(AttackEvent.username, func.count(AttackEvent.id).label('count')).filter(AttackEvent.username != None), mode
        ).group_by(AttackEvent.username).order_by(desc('count')).limit(10).all()
        top_usernames = [{"username": u[0], "count": u[1]} for u in top_usernames_data if u[0]]

        stats = {
            "system_mode": mode.upper(),
            "total_attacks": total_attacks,
            "unique_ips": unique_ips,
            "unique_countries": unique_countries,
            "services": services,
            "risk_distribution": risk_distribution,
            "latest_attack": latest_attack,
            "top_countries": top_countries,
            "top_usernames": top_usernames
        }
        
        return jsonify(stats)
    except Exception as e:
        print(f"[API] Error in /api/stats: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


@api_bp.route('/api/map-data', methods=['GET'])
def get_map_data():
    """Get location data for rendering the map."""
    db = SessionLocal()
    try:
        service_filter = request.args.get('service', default=None, type=str)
        is_tor_filter = request.args.get('is_tor', default=None, type=str)
        
        query = db.query(AttackEvent).filter(
            AttackEvent.latitude != None,
            AttackEvent.longitude != None,
            AttackEvent.latitude != 0,
            AttackEvent.longitude != 0
        )
        query = apply_mode_filter(query)
        
        if service_filter and service_filter != 'ALL':
            query = query.filter(AttackEvent.service == service_filter)
        if is_tor_filter == 'true':
            query = query.filter(AttackEvent.is_tor == True)

        events = query.order_by(desc(AttackEvent.timestamp)).limit(500).all()

        map_data = [
            {
                "latitude": e.latitude,
                "longitude": e.longitude,
                "lat": e.latitude,
                "lon": e.longitude,
                "source_ip": e.source_ip,
                "country": e.country,
                "city": e.city,
                "isp": e.isp,
                "risk_score": e.risk_score,
                "attack_type": e.attack_type,
                "service": e.service,
                "is_tor": e.is_tor,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None
            }
            for e in events
        ]
        return jsonify(map_data)
    except Exception as e:
        print(f"[API] Error in /api/map-data: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


@api_bp.route('/api/reports/pdf', methods=['GET'])
def download_pdf_report():
    """Generates and downloads a tactical HackerOne PDF threat intelligence report."""
    db = SessionLocal()
    try:
        mode = get_current_mode()
        service_filter = request.args.get('service', default=None, type=str)
        min_risk_filter = request.args.get('min_risk', default=None, type=float)
        max_risk_filter = request.args.get('max_risk', default=None, type=float)
        is_tor_filter = request.args.get('is_tor', default=None, type=str)
        search = request.args.get('search', default=None, type=str)
        limit = request.args.get('limit', default=50, type=int)

        query = db.query(AttackEvent)
        query = apply_mode_filter(query, mode)

        active_filters = []
        mode_label = "Live Production Sensors" if mode == "production" else ("Demo Simulation" if mode == "demo" else "All Incursions")
        active_filters.append(f"Scope: {mode_label}")

        if service_filter and service_filter != 'ALL':
            query = query.filter(AttackEvent.service == service_filter)
            active_filters.append(f"Service: {service_filter}")
        if min_risk_filter is not None and min_risk_filter > 0:
            query = query.filter(AttackEvent.risk_score >= min_risk_filter)
            active_filters.append(f"Min Risk: {min_risk_filter}")
        if max_risk_filter is not None:
            query = query.filter(AttackEvent.risk_score <= max_risk_filter)
            active_filters.append(f"Max Risk: {max_risk_filter}")
        if is_tor_filter == 'true':
            query = query.filter(AttackEvent.is_tor == True)
            active_filters.append("TOR Only")
        elif is_tor_filter == 'false':
            query = query.filter(AttackEvent.is_tor == False)
            active_filters.append("Direct Traffic Only")
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                (AttackEvent.source_ip.like(search_pattern)) |
                (AttackEvent.command.like(search_pattern)) |
                (AttackEvent.username.like(search_pattern)) |
                (AttackEvent.country.like(search_pattern)) |
                (AttackEvent.city.like(search_pattern)) |
                (AttackEvent.isp.like(search_pattern))
            )
            active_filters.append(f"Query: '{search}'")

        filter_desc = " | ".join(active_filters)

        events = query.order_by(desc(AttackEvent.timestamp)).limit(limit).all()
        events_list = [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "source_ip": e.source_ip,
                "service": e.service,
                "username": e.username,
                "password": e.password,
                "command": e.command,
                "user_agent": e.user_agent,
                "country": e.country,
                "city": e.city,
                "isp": e.isp,
                "latitude": e.latitude,
                "longitude": e.longitude,
                "attack_type": e.attack_type,
                "risk_score": e.risk_score,
                "is_tor": e.is_tor,
                "is_demo": e.is_demo
            }
            for e in events
        ]

        # Calculate stats strictly for this operational mode
        total_attacks = apply_mode_filter(db.query(func.count(AttackEvent.id)), mode).scalar() or 0
        unique_ips = apply_mode_filter(db.query(func.count(distinct(AttackEvent.source_ip))), mode).scalar() or 0
        unique_countries = apply_mode_filter(db.query(func.count(distinct(AttackEvent.country))), mode).scalar() or 0
        
        services_data = apply_mode_filter(db.query(AttackEvent.service, func.count(AttackEvent.id)), mode).group_by(AttackEvent.service).all()
        services = {service: count for service, count in services_data if service}
        
        low_count = apply_mode_filter(db.query(func.count(AttackEvent.id)).filter(AttackEvent.risk_score < 40), mode).scalar() or 0
        medium_count = apply_mode_filter(db.query(func.count(AttackEvent.id)).filter(AttackEvent.risk_score >= 40, AttackEvent.risk_score < 70), mode).scalar() or 0
        high_count = apply_mode_filter(db.query(func.count(AttackEvent.id)).filter(AttackEvent.risk_score >= 70, AttackEvent.risk_score < 90), mode).scalar() or 0
        critical_count = apply_mode_filter(db.query(func.count(AttackEvent.id)).filter(AttackEvent.risk_score >= 90), mode).scalar() or 0
        
        top_countries_data = apply_mode_filter(
            db.query(AttackEvent.country, func.count(AttackEvent.id).label('count')), mode
        ).group_by(AttackEvent.country).order_by(desc('count')).limit(10).all()
        top_countries = [{"country": c[0] if c[0] else "Unknown", "count": c[1]} for c in top_countries_data]

        top_usernames_data = apply_mode_filter(
            db.query(AttackEvent.username, func.count(AttackEvent.id).label('count')).filter(AttackEvent.username != None), mode
        ).group_by(AttackEvent.username).order_by(desc('count')).limit(10).all()
        top_usernames = [{"username": u[0], "count": u[1]} for u in top_usernames_data if u[0]]

        stats = {
            "total_attacks": total_attacks,
            "unique_ips": unique_ips,
            "unique_countries": unique_countries,
            "services": services,
            "risk_distribution": {
                "low": low_count,
                "medium": medium_count,
                "high": high_count,
                "critical": critical_count
            },
            "top_countries": top_countries,
            "top_usernames": top_usernames
        }

        from reports.pdf_generator import generate_threat_report_pdf
        pdf_bytes = generate_threat_report_pdf(stats, events_list, filter_summary=filter_desc)

        filename = f"HoneyTrack_{mode.upper()}_Report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        print(f"[API] Error in /api/reports/pdf: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


@api_bp.route('/api/admin/clear-live', methods=['POST'])
def clear_live_events():
    """Clears authentic live production telemetry so operators can restart fresh counts."""
    db = SessionLocal()
    try:
        deleted = db.query(AttackEvent).filter(AttackEvent.is_demo == False).delete()
        db.commit()
        return jsonify({"success": True, "cleared_records": deleted})
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


@api_bp.route('/api/alerts/status', methods=['GET'])
def get_alert_status():
    """Get email alert configuration status and active recipient."""
    recipient = session.get('user_email') or settings.ALERT_TO_EMAIL or settings.SMTP_USERNAME
    return jsonify({
        "enabled": settings.EMAIL_ALERTS_ENABLED,
        "smtp_host": settings.SMTP_HOST,
        "smtp_port": settings.SMTP_PORT,
        "smtp_username": settings.SMTP_USERNAME,
        "recipient": recipient,
        "threshold": settings.ALERT_RISK_THRESHOLD,
        "cooldown_seconds": settings.ALERT_COOLDOWN_SECONDS
    })


@api_bp.route('/api/alerts/test', methods=['POST'])
def test_alert_email():
    """Triggers an authenticated test alert email to verify SMTP credentials."""
    from alerts.email_alerts import test_smtp_connection
    req_data = request.get_json(silent=True) or {}
    recipient = req_data.get('email') or session.get('user_email') or settings.ALERT_TO_EMAIL
    
    success, message = test_smtp_connection(test_recipient=recipient)
    return jsonify({
        "success": success,
        "recipient": recipient,
        "message": message
    }), (200 if success else 400)


# ──────────────────────────────────────────────
# Firewall & Active Defense API Endpoints
# ──────────────────────────────────────────────

@api_bp.route('/api/firewall/blocked', methods=['GET'])
def get_blocked_ips_list():
    """List all currently blacklisted IPs and mitigation rules."""
    from defense.firewall import get_all_blocked_ips
    active_only = request.args.get('active_only', 'true').lower() == 'true'
    blocked = get_all_blocked_ips(active_only=active_only)
    return jsonify(blocked)


@api_bp.route('/api/firewall/status/<ip>', methods=['GET'])
def get_ip_firewall_status(ip):
    """Check if an IP is blocked and retrieve its copyable OS firewall commands."""
    from defense.firewall import is_ip_blocked, generate_firewall_commands
    blocked = is_ip_blocked(ip)
    commands = generate_firewall_commands(ip)
    return jsonify({
        "ip": ip,
        "is_blocked": blocked,
        "commands": commands
    })


@api_bp.route('/api/firewall/block', methods=['POST'])
def block_ip_endpoint():
    """Manually or programmatically blacklist an attacker IP address."""
    from defense.firewall import block_ip
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    reason = data.get('reason', 'Operator Manual Blacklist')
    risk_score = data.get('risk_score', 0)
    country = data.get('country', 'Unknown')
    operator_name = session.get('user_name', 'Operator')
    execute_system = data.get('execute_system', None)

    if not ip:
        return jsonify({"error": "Missing 'ip' field."}), 400

    success, message = block_ip(
        ip=ip,
        reason=reason,
        risk_score=risk_score,
        country=country,
        blocked_by=f"Operator ({operator_name})",
        execute_system=execute_system
    )
    return jsonify({
        "success": success,
        "ip": ip,
        "message": message,
        "is_blocked": success
    }), (200 if success else 400)


@api_bp.route('/api/firewall/unblock', methods=['POST'])
def unblock_ip_endpoint():
    """Remove an IP address from the active blacklist."""
    from defense.firewall import unblock_ip
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    execute_system = data.get('execute_system', None)

    if not ip:
        return jsonify({"error": "Missing 'ip' field."}), 400

    success, message = unblock_ip(ip=ip, execute_system=execute_system)
    return jsonify({
        "success": success,
        "ip": ip,
        "message": message,
        "is_blocked": not success
    }), (200 if success else 400)


@api_bp.route('/api/sessions', methods=['GET'])
def get_sessions_endpoint():
    """Returns list of recorded honeypot terminal sessions."""
    from sessions.session_recorder import list_session_replays
    mode = get_current_mode()
    limit = request.args.get('limit', default=50, type=int)
    sessions_list = list_session_replays(limit=limit, mode=mode)
    return jsonify({
        "status": "success",
        "count": len(sessions_list),
        "sessions": sessions_list
    })


@api_bp.route('/api/sessions/<session_id>/replay', methods=['GET'])
def get_session_replay_endpoint(session_id):
    """Returns interactive replay event stream for a specific session."""
    from sessions.session_recorder import get_session_replay
    replay = get_session_replay(session_id)
    if not replay:
        return jsonify({"error": "Session recording not found"}), 404
    return jsonify({
        "status": "success",
        "session": replay
    })


# ──────────────────────────────────────────────
# Distributed Node Federation Endpoints (v2.0)
# ──────────────────────────────────────────────

@api_bp.route('/api/federation/nodes', methods=['GET'])
def get_federation_nodes_endpoint():
    """Returns registered sensor nodes and local node telemetry."""
    from federation.node_manager import get_local_node_info, get_federated_nodes
    local_info = get_local_node_info()
    nodes = get_federated_nodes(include_offline=True)
    return jsonify({
        "status": "success",
        "local_node": local_info,
        "nodes_count": len(nodes),
        "nodes": nodes
    })


@api_bp.route('/api/federation/register', methods=['POST'])
def register_federation_node_endpoint():
    """Registers a remote sensor node with the federation mesh."""
    from federation.node_manager import register_or_update_node
    data = request.get_json(silent=True) or {}
    node_id = data.get("node_id")
    node_name = data.get("node_name") or node_id
    region = data.get("region", "Global")
    endpoint_url = data.get("endpoint_url")
    is_hub = bool(data.get("is_hub", False))

    if not node_id:
        return jsonify({"error": "Missing 'node_id' parameter."}), 400

    node_data = register_or_update_node(
        node_id=node_id,
        node_name=node_name,
        region=region,
        endpoint_url=endpoint_url,
        is_hub=is_hub
    )
    return jsonify({
        "status": "success",
        "message": f"Node '{node_id}' registered successfully.",
        "node": node_data
    })


@api_bp.route('/api/federation/heartbeat', methods=['POST'])
def federation_heartbeat_endpoint():
    """Receives sensor health ping from a remote node."""
    from federation.node_manager import record_heartbeat
    data = request.get_json(silent=True) or {}
    node_id = data.get("node_id") or request.headers.get("X-HoneyTrack-Node-Id")
    attacks_count = data.get("attacks_count")

    if not node_id:
        return jsonify({"error": "Missing 'node_id'."}), 400

    ok = record_heartbeat(node_id, attacks_count=attacks_count)
    return jsonify({
        "status": "success" if ok else "unknown_node",
        "node_id": node_id,
        "acknowledged": ok
    })


@api_bp.route('/api/federation/sync', methods=['POST'])
def federation_sync_endpoint():
    """
    Bi-directional threat intelligence synchronization.
    Ingests peer indicators and responds with local active threat intel.
    """
    from federation.sync import ingest_federated_threat_intel, export_local_threat_intel
    data = request.get_json(silent=True) or {}
    origin_node = request.headers.get("X-HoneyTrack-Node-Id") or data.get("origin_node", "unknown-node")

    # Ingest incoming threat intel
    ingest_result = ingest_federated_threat_intel(data, origin_node=origin_node)

    # Export local intel in response for peer synchronization
    local_intel = export_local_threat_intel(limit=50)

    return jsonify({
        "status": "success",
        "ingest_summary": ingest_result,
        "local_intel": local_intel
    })


@api_bp.route('/api/federation/nodes/seed-demo', methods=['POST'])
def federation_seed_demo_endpoint():
    """Seeds global sensor nodes for presentations and multi-region testing."""
    from federation.node_manager import seed_default_demo_nodes, get_federated_nodes
    seed_default_demo_nodes()
    nodes = get_federated_nodes()
    return jsonify({
        "status": "success",
        "message": "Demo federation sensor nodes seeded.",
        "nodes": nodes
    })


@api_bp.route('/api/federation/nodes/<node_id>', methods=['DELETE'])
def delete_federation_node_endpoint(node_id):
    """Removes a registered sensor node from the federation roster."""
    db = SessionLocal()
    try:
        from database.models import FederatedNode
        node = db.query(FederatedNode).filter(FederatedNode.node_id == node_id).first()
        if not node:
            return jsonify({"error": "Node not found"}), 404
        if node.is_local:
            return jsonify({"error": "Cannot delete primary local node"}), 400
        db.delete(node)
        db.commit()
        return jsonify({"status": "success", "message": f"Node '{node_id}' deleted."})
    finally:
        db.close()


@api_bp.route('/api/federation/search', methods=['GET'])
def search_federation_threat_endpoint():
    """
    Cross-node adversary search by IP.
    Returns intercepted threat intelligence, originating sensor node, and matching terminal session replay.
    """
    import time
    ip = (request.args.get('ip') or '').strip()
    if not ip:
        return jsonify({"error": "Missing 'ip' parameter."}), 400

    db = SessionLocal()
    try:
        from database.models import AttackEvent, SessionRecording
        # Find events matching this IP
        events = db.query(AttackEvent).filter(AttackEvent.source_ip == ip).order_by(AttackEvent.timestamp.desc()).all()

        # Collect actual commands executed by this IP
        commands_list = list(set([e.command for e in events if e.command]))

        # Check if an Asciinema session replay exists for this IP
        session_rec = db.query(SessionRecording).filter(SessionRecording.source_ip == ip).order_by(SessionRecording.start_time.desc()).first()
        
        session_id = session_rec.session_id if session_rec else None

        # Only synthesize a replay stream if the attacker ACTUALLY executed commands
        if not session_id and commands_list:
            cmds = [(cmd, f"executed: {cmd}") for cmd in commands_list]
            from sessions.session_recorder import create_sample_replay
            synth_id = f"replay-{ip.replace('.', '-')}-{int(time.time())}"
            session_id = create_sample_replay(
                session_id=synth_id,
                ip=ip,
                username=events[0].username or "root",
                commands=cmds,
                is_demo=events[0].is_demo
            )

        has_commands = bool(commands_list or (session_rec and session_rec.commands_count > 0))

        if not events and not session_id:
            return jsonify({
                "status": "success",
                "found": False,
                "message": f"No telemetry recorded for IP '{ip}' across federated sensors."
            })

        latest = events[0] if events else None

        return jsonify({
            "status": "success",
            "found": True,
            "ip": ip,
            "country": latest.country if latest else "Unknown",
            "city": latest.city if latest else "Unknown",
            "isp": latest.isp if latest else "Internet Service Provider",
            "risk_score": latest.risk_score if latest else 50,
            "service": latest.service if latest else "SSH",
            "attack_type": latest.attack_type if latest else "intrusion_attempt",
            "origin_node": latest.origin_node if latest and latest.origin_node else "HoneyTrack Primary Node",
            "total_attacks": len(events),
            "commands": commands_list,
            "has_commands": has_commands,
            "session_id": session_id,
            "has_replay": bool(has_commands and session_id)
        })
    finally:
        db.close()



