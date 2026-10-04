"""HTTP Honeypot Listener for HoneyTrack.

Serves a fake admin login page on port 8080.
Every form submission is fingerprinted, risk-scored,
and saved to the database.
"""

from flask import Flask, request, render_template_string
from datetime import datetime

from config.settings import HTTP_HOST, HTTP_PORT
from database.database import SessionLocal
from database.repositories import save_event
from analysis.fingerprint import analyze_event


app = Flask(__name__)


LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login</title>
    <style>
        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #111827;
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .login-box {
            width: 350px;
            padding: 30px;
            background: #1f2937;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
        }
        h1 {
            text-align: center;
            margin-bottom: 25px;
            color: #22c55e;
        }
        input {
            width: 100%;
            box-sizing: border-box;
            padding: 12px;
            margin-bottom: 15px;
            border: 1px solid #374151;
            border-radius: 5px;
            background: #0f172a;
            color: #e5e7eb;
            font-size: 14px;
        }
        input:focus {
            outline: none;
            border-color: #22c55e;
        }
        button {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 5px;
            background: #22c55e;
            color: #111827;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
        }
        button:hover {
            background: #16a34a;
        }
        .error-msg {
            color: #ef4444;
            text-align: center;
            margin-top: 15px;
            font-size: 13px;
        }
        .subtitle {
            text-align: center;
            color: #6b7280;
            font-size: 12px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
<div class="login-box">
    <h1>🔐 Admin Portal</h1>
    <p class="subtitle">Authorized personnel only</p>
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    {% if error %}
    <p class="error-msg">{{ error }}</p>
    {% endif %}
</div>
</body>
</html>
"""


@app.before_request
def check_firewall_blacklist():
    source_ip = request.remote_addr or "unknown"
    from defense.firewall import is_ip_blocked
    if is_ip_blocked(source_ip):
        print(f"[HTTP/FIREWALL] Dropped HTTP request from blacklisted IP {source_ip}")
        from flask import Response
        return Response("Access denied: IP is blacklisted by HoneyTrack Active Defense Firewall.\r\n", status=403, mimetype="text/plain")


@app.route("/", methods=["GET", "POST"])
def login():
    """Serve the fake login page and capture POST submissions."""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        source_ip = request.remote_addr or "unknown"
        user_agent = request.headers.get("User-Agent", "unknown")

        # ── Run the analysis pipeline ──
        analysis = analyze_event(
            source_ip=source_ip,
            service="HTTP",
            username=username,
            password=password,
            command=None,
            attempt_count=1
        )

        # ── Build event data ──
        event_data = {
            "timestamp":   datetime.utcnow(),
            "source_ip":   source_ip,
            "service":     "HTTP",
            "username":    username,
            "password":    password,
            "command":     None,
            "user_agent":  user_agent,
            "country":     analysis["country"],
            "city":        analysis["city"],
            "isp":         analysis["isp"],
            "latitude":    analysis["latitude"],
            "longitude":   analysis["longitude"],
            "attack_type": analysis["attack_type"],
            "risk_score":  analysis["risk_score"],
            "is_tor":      analysis["is_tor"],
            "is_demo":     False,
        }

        # ── Save to database ──
        db = SessionLocal()
        try:
            event = save_event(db, event_data)
            print(
                f"[HTTP] {source_ip} -> {username}:{password} | "
                f"Type: {analysis['attack_type']} | "
                f"Risk: {analysis['risk_score']} ({analysis['risk_level']}) | "
                f"ID: {event.id}"
            )
            from defense.firewall import check_and_auto_block
            check_and_auto_block(event_data)
            if event_data.get("risk_score", 0) >= 70 or event_data.get("is_tor"):
                from alerts.email_alerts import send_alert_email
                send_alert_email(event_data)
        except Exception as e:
            print(f"[HTTP] Error handling event: {e}")
        finally:
            db.close()

        return render_template_string(LOGIN_PAGE, error="Invalid credentials. Access denied.")

    return render_template_string(LOGIN_PAGE)


def start_http_honeypot(host=None, port=None):
    """Start the HTTP honeypot server."""
    host = host or HTTP_HOST
    port = port or HTTP_PORT
    print(f"[HTTP] Honeypot listening on {host}:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    start_http_honeypot()