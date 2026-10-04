"""
HoneyTrack — Threat Intelligence Email Alerts Dispatcher
Handles real-time security alerts via Gmail SMTP with non-blocking asynchronous dispatch,
HackerOne-styled responsive HTML email templates, and SMTP connection diagnostics.
"""

import smtplib
import threading
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import time
from datetime import datetime, timezone

from config import settings

logger = logging.getLogger(__name__)

# Track the last alert timestamp per IP to enforce cooldown
_last_alert_times = {}
_auth_error_warned = False


def get_clean_smtp_password():
    """Strip spaces from Google App Password if formatted in 4-character blocks."""
    if not settings.SMTP_PASSWORD:
        return ""
    return str(settings.SMTP_PASSWORD).replace(" ", "").strip()


def send_alert_email(event_data: dict, recipient_email: str = None, async_send: bool = True):
    """
    Sends an executive threat intelligence alert email for high-risk adversary intercepts.
    Runs asynchronously in a background thread by default so honeypots are never stalled.
    """
    if not settings.EMAIL_ALERTS_ENABLED:
        return

    to_email = recipient_email or settings.ALERT_TO_EMAIL or settings.SMTP_USERNAME
    if not to_email:
        logger.warning("[EMAIL] No alert recipient email configured.")
        return

    # Check risk threshold
    risk = event_data.get("risk_score", 0)
    is_tor = event_data.get("is_tor", False)
    if risk < settings.ALERT_RISK_THRESHOLD and not is_tor:
        return

    # Enforce cooldown per IP to avoid spamming the inbox during sustained brute force
    source_ip = event_data.get("source_ip", "Unknown")
    current_time = time.time()
    last_time = _last_alert_times.get(source_ip, 0)
    if (current_time - last_time) < settings.ALERT_COOLDOWN_SECONDS:
        return

    _last_alert_times[source_ip] = current_time

    if async_send:
        worker_thread = threading.Thread(
            target=_send_alert_worker,
            args=(event_data, to_email),
            name=f"HoneyTrack-Alert-{source_ip}",
            daemon=True
        )
        worker_thread.start()
    else:
        _send_alert_worker(event_data, to_email)


def _send_alert_worker(event_data: dict, to_email: str):
    """Performs the actual SMTP delivery in a background thread."""
    global _auth_error_warned

    password = get_clean_smtp_password()
    if not settings.SMTP_USERNAME or not password:
        if not _auth_error_warned:
            logger.warning("[EMAIL] Email alerts are enabled but SMTP credentials are not configured.")
            _auth_error_warned = True
        return

    source_ip = event_data.get("source_ip", "Unknown")
    service = event_data.get("service", "Unknown")
    risk = event_data.get("risk_score", 0)
    is_tor = event_data.get("is_tor", False)
    country = event_data.get("country", "Unknown")
    city = event_data.get("city", "Unknown")
    isp = event_data.get("isp", "Unknown")
    attack_type = event_data.get("attack_type", "Intrusion Attempt")
    cmd = event_data.get("command")
    username = event_data.get("username")
    password_attempt = event_data.get("password")
    user_agent = event_data.get("user_agent")
    ts_str = event_data.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Threat classification color
    severity_label = "CRITICAL ADVERSARY" if risk >= 70 else ("ELEVATED RISK" if risk >= 40 else "SUSPICIOUS INTRUSION")
    sev_color = "#dc2626" if risk >= 70 else "#ea580c"

    # Monospace payload representation
    if cmd:
        payload_markup = f"""
        <div style="background-color: #090d16; border: 1px solid #1e293b; border-radius: 4px; padding: 10px; margin-top: 5px; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 12px; color: #4ade80;">
          <span style="color: #94a3b8;"># Captured terminal execution:</span><br/>
          <span style="color: #f43f5e;">$</span> <strong style="color: #ffffff;">{cmd}</strong>
        </div>
        """
    elif username or password_attempt:
        payload_markup = f"""
        <div style="background-color: #090d16; border: 1px solid #1e293b; border-radius: 4px; padding: 10px; margin-top: 5px; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 12px; color: #e2e8f0;">
          <span style="color: #94a3b8;"># Captured authentication credentials:</span><br/>
          <span style="color: #38bdf8;">User:</span> <strong style="color: #ffffff;">{username or '-'}</strong> &nbsp;|&nbsp;
          <span style="color: #f43f5e;">Pass:</span> <strong style="color: #ffffff;">{password_attempt or '-'}</strong>
        </div>
        """
    elif user_agent:
        payload_markup = f"""
        <div style="background-color: #090d16; border: 1px solid #1e293b; border-radius: 4px; padding: 10px; margin-top: 5px; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 12px; color: #e2e8f0;">
          <span style="color: #94a3b8;"># Captured scanner signature:</span><br/>
          <strong style="color: #fde047;">{user_agent}</strong>
        </div>
        """
    else:
        payload_markup = "<span style='color: #64748b;'>None recorded</span>"

    tor_badge = """
    <span style="background-color: rgba(124,58,237,0.15); border: 1px solid #7c3aed; color: #a78bfa; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: bold; margin-left: 6px;">
      TOR EXIT NODE
    </span>
    """ if is_tor else ""

    html_body = f"""
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>HoneyTrack Threat Alert</title>
      </head>
      <body style="margin: 0; padding: 20px; background-color: #020617; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #e2e8f0;">
        <table align="center" width="100%" cellpadding="0" cellspacing="0" style="max-width: 620px; background-color: #090d16; border: 1px solid #1e293b; border-radius: 8px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
          <!-- Header Banner -->
          <tr>
            <td style="background-color: #0f172a; padding: 18px 24px; border-bottom: 2px solid {sev_color};">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td>
                    <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 700; color: {sev_color}; letter-spacing: 0.1em;">
                      [!] HONEYTRACK // TACTICAL INCIDENT DISPATCH
                    </span>
                    <h1 style="margin: 6px 0 0; font-size: 20px; color: #ffffff; font-weight: 700;">
                      {severity_label} DETECTED
                    </h1>
                  </td>
                  <td align="right">
                    <span style="display: inline-block; background-color: {sev_color}; color: #ffffff; font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 4px;">
                      SCORE: {risk}/100
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Summary Callout -->
          <tr>
            <td style="padding: 20px 24px;">
              <p style="margin: 0 0 16px; font-size: 13.5px; line-height: 1.5; color: #cbd5e1;">
                Autonomous decoy sensors intercepted unauthorized malicious activity targeting your protected network perimeter.
              </p>

              <!-- Telemetry Metadata Table -->
              <table width="100%" cellpadding="8" cellspacing="0" style="background-color: #0f172a; border: 1px solid #1e293b; border-radius: 6px; font-size: 12.5px;">
                <tr>
                  <td width="35%" style="color: #64748b; font-weight: 600; border-bottom: 1px solid #1e293b;">Attacker Host IP:</td>
                  <td style="border-bottom: 1px solid #1e293b; font-family: 'JetBrains Mono', monospace; font-weight: 700; color: #ffffff;">
                    {source_ip} {tor_badge}
                  </td>
                </tr>
                <tr>
                  <td style="color: #64748b; font-weight: 600; border-bottom: 1px solid #1e293b;">Target Honeypot:</td>
                  <td style="border-bottom: 1px solid #1e293b; font-weight: 700; color: #38bdf8;">
                    {service} Decoy Service
                  </td>
                </tr>
                <tr>
                  <td style="color: #64748b; font-weight: 600; border-bottom: 1px solid #1e293b;">Attack Classification:</td>
                  <td style="border-bottom: 1px solid #1e293b; color: #f87171; font-weight: 600;">
                    {attack_type}
                  </td>
                </tr>
                <tr>
                  <td style="color: #64748b; font-weight: 600; border-bottom: 1px solid #1e293b;">Geographic Sourcing:</td>
                  <td style="border-bottom: 1px solid #1e293b; color: #e2e8f0;">
                    {city}, {country}
                  </td>
                </tr>
                <tr>
                  <td style="color: #64748b; font-weight: 600; border-bottom: 1px solid #1e293b;">ISP / Autonomous System:</td>
                  <td style="border-bottom: 1px solid #1e293b; color: #cbd5e1;">
                    {isp}
                  </td>
                </tr>
                <tr>
                  <td style="color: #64748b; font-weight: 600;">Intercept Timestamp:</td>
                  <td style="font-family: 'JetBrains Mono', monospace; color: #94a3b8;">
                    {ts_str}
                  </td>
                </tr>
              </table>

              <!-- Forensic Evidence -->
              <h3 style="margin: 20px 0 8px; font-size: 13px; font-weight: 700; color: #94a3b8; font-family: 'JetBrains Mono', monospace; letter-spacing: 0.05em;">
                FORENSIC EVIDENCE &amp; PAYLOAD
              </h3>
              {payload_markup}

              <!-- Recommended Defensive Actions -->
              <h3 style="margin: 20px 0 8px; font-size: 13px; font-weight: 700; color: #94a3b8; font-family: 'JetBrains Mono', monospace; letter-spacing: 0.05em;">
                RECOMMENDED FIREWALL MITIGATION
              </h3>
              <div style="background-color: #020617; border: 1px solid #1e293b; border-radius: 4px; padding: 10px; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px;">
                <span style="color: #38bdf8;">sudo ufw deny from {source_ip} to any comment 'HoneyTrack Auto-Drop'</span><br/>
                <span style="color: #a3e635;">sudo iptables -A INPUT -s {source_ip} -j DROP</span>
              </div>

              <!-- Button CTA -->
              <div style="margin-top: 24px; text-align: center;">
                <a href="http://localhost:5000" style="display: inline-block; background-color: #dc2626; color: #ffffff; text-decoration: none; font-size: 13px; font-weight: 700; padding: 11px 24px; border-radius: 6px; box-shadow: 0 4px 12px rgba(220,38,38,0.4);">
                  VIEW LIVE THREAT DASHBOARD &rarr;
                </a>
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color: #020617; padding: 14px 24px; border-top: 1px solid #1e293b; font-size: 11px; color: #64748b; font-family: 'JetBrains Mono', monospace; text-align: center;">
              HoneyTrack Autonomous Deception Framework &bull; Real-Time Automated Threat Intelligence
            </td>
          </tr>
        </table>
      </body>
    </html>
    """

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[HoneyTrack ALERT] High-Risk Activity Detected from {source_ip} (Score: {risk})"
        msg["From"] = settings.ALERT_FROM_EMAIL or settings.SMTP_USERNAME
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(settings.SMTP_USERNAME, password)
            server.sendmail(settings.ALERT_FROM_EMAIL or settings.SMTP_USERNAME, to_email, msg.as_string())

        print(f"[EMAIL SUCCESS] Alert dispatched to {to_email} for IP {source_ip}")
        logger.info(f"[EMAIL] Alert email dispatched to {to_email} for {source_ip}")

    except smtplib.SMTPAuthenticationError as e:
        if not _auth_error_warned:
            print("[EMAIL AUTH NOTICE] Gmail SMTP Authentication failed: Invalid or expired App Password.")
            print("[EMAIL HELP] Ensure you have a valid 16-character Google App Password in config/settings.py.")
            _auth_error_warned = True
        logger.error(f"[EMAIL] SMTP Authentication error: {e}")
    except Exception as e:
        logger.error(f"[EMAIL] Error dispatching threat alert: {e}")


def send_login_notification(user_name: str, user_email: str, ip_address: str = "127.0.0.1", async_send: bool = True):
    """
    Sends an authorized session notification to the operator upon establishing a dashboard session.
    """
    if not settings.EMAIL_ALERTS_ENABLED or not user_email:
        return

    if async_send:
        threading.Thread(
            target=_send_login_notification_worker,
            args=(user_name, user_email, ip_address),
            name="HoneyTrack-Login-Notification",
            daemon=True
        ).start()
    else:
        _send_login_notification_worker(user_name, user_email, ip_address)


def _send_login_notification_worker(user_name: str, user_email: str, ip_address: str):
    password = get_clean_smtp_password()
    if not settings.SMTP_USERNAME or not password:
        return

    timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html_body = f"""
    <!DOCTYPE html>
    <html>
      <body style="margin: 0; padding: 20px; background-color: #020617; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #e2e8f0;">
        <table align="center" width="100%" cellpadding="0" cellspacing="0" style="max-width: 580px; background-color: #090d16; border: 1px solid #1e293b; border-radius: 8px; overflow: hidden;">
          <tr>
            <td style="background-color: #0f172a; padding: 18px 24px; border-bottom: 2px solid #16a34a;">
              <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 700; color: #16a34a; letter-spacing: 0.1em;">
                [✓] HONEYTRACK // SESSION SECURITY
              </span>
              <h2 style="margin: 6px 0 0; font-size: 18px; color: #ffffff;">OPERATOR SESSION ESTABLISHED</h2>
            </td>
          </tr>
          <tr>
            <td style="padding: 20px 24px;">
              <p style="margin: 0 0 16px; font-size: 13px; color: #cbd5e1;">
                A new authorized operator session has connected to the HoneyTrack Threat Intelligence Center.
              </p>
              <table width="100%" cellpadding="8" cellspacing="0" style="background-color: #0f172a; border: 1px solid #1e293b; border-radius: 6px; font-size: 12px;">
                <tr><td width="35%" style="color: #64748b;">Operator Call-sign:</td><td style="font-weight: 700; color: #ffffff;">{user_name}</td></tr>
                <tr><td style="color: #64748b;">Recipient Email:</td><td>{user_email}</td></tr>
                <tr><td style="color: #64748b;">Origin Address:</td><td style="font-family: 'JetBrains Mono', monospace;">{ip_address}</td></tr>
                <tr><td style="color: #64748b;">Session Timestamp:</td><td style="font-family: 'JetBrains Mono', monospace;">{timestamp_str}</td></tr>
                <tr><td style="color: #64748b;">Clearance:</td><td style="color: #16a34a; font-weight: 700;">LEVEL-4 AUTHORIZED</td></tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="background-color: #020617; padding: 12px 24px; border-top: 1px solid #1e293b; font-size: 10.5px; color: #64748b; text-align: center; font-family: 'JetBrains Mono', monospace;">
              If you did not initiate this authentication, disconnect your sensor cluster immediately.
            </td>
          </tr>
        </table>
      </body>
    </html>
    """

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[HoneyTrack Security] Operator Login Notification: {user_name}"
        msg["From"] = settings.ALERT_FROM_EMAIL or settings.SMTP_USERNAME
        msg["To"] = user_email
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(settings.SMTP_USERNAME, password)
            server.sendmail(settings.ALERT_FROM_EMAIL or settings.SMTP_USERNAME, user_email, msg.as_string())

        print(f"[EMAIL SUCCESS] Login notification delivered to {user_email}")
    except Exception as e:
        logger.error(f"[EMAIL] Failed to send login notification: {e}")


def test_smtp_connection(test_recipient: str = None) -> tuple[bool, str]:
    """
    Performs a synchronous test of the SMTP configuration and sends a test threat alert.
    Returns (success: bool, message: str).
    """
    password = get_clean_smtp_password()
    if not settings.SMTP_USERNAME or not password:
        return False, "SMTP credentials missing: SMTP_USERNAME or SMTP_PASSWORD is not configured."

    recipient = test_recipient or settings.ALERT_TO_EMAIL or settings.SMTP_USERNAME

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(settings.SMTP_USERNAME, password)

            # Send a verified test alert
            test_event = {
                "source_ip": "185.220.101.5",
                "service": "SSH Decoy",
                "attack_type": "Exploit Verification (SMTP Test)",
                "risk_score": 95,
                "city": "Frankfurt",
                "country": "Germany",
                "isp": "Tor Exit Node",
                "username": "root",
                "password": "Password2026!",
                "command": "uname -a && cat /etc/passwd",
                "is_tor": True,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            }

            _send_alert_worker(test_event, recipient)

        return True, f"Authentication successful! Test security alert delivered to {recipient} via Gmail SMTP."

    except smtplib.SMTPAuthenticationError as e:
        return False, f"Gmail SMTP Authentication Failed (535): Invalid or revoked Google App Password. Error: {e.smtp_error.decode('utf-8', errors='ignore') if isinstance(e.smtp_error, bytes) else str(e)}"
    except Exception as e:
        return False, f"SMTP Connection Error: {str(e)}"
