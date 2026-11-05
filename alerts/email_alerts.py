"""
HoneyTrack — Threat Intelligence Email Alerts Dispatcher
Handles real-time security alerts via Gmail SMTP with non-blocking asynchronous dispatch,
HackerOne-styled responsive HTML email templates, and SMTP connection diagnostics.
"""

import os
import base64
import smtplib
import threading
import logging
import html
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
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


def build_alert_subject(event_data: dict) -> str:
    """
    Constructs high-clarity contextual email alert subjects matching HoneyTrack operational style.
    
    Examples:
      - HoneyTrack alert: Tor exit node accessed your SSH decoy (risk 95)
      - HoneyTrack: Commands run on your SSH decoy from Frankfurt, Germany
      - [HoneyTrack] SSH decoy hit by Tor exit node, Frankfurt, Germany
      - [HoneyTrack] Risk 95: 185.220.101.5 ran uname -a on SSH decoy
      - [HoneyTrack] 18 Oct 2026, 13:43 UTC: High-risk SSH activity
    """
    raw_service = event_data.get("service") or "SSH"
    svc = raw_service.replace(" Decoy", "").replace(" Service", "").replace(" decoy", "").strip() or "SSH"
    source_ip = event_data.get("source_ip", "Unknown")
    risk = int(event_data.get("risk_score", 0))
    is_tor = bool(event_data.get("is_tor", False))
    city = (event_data.get("city") or "").strip()
    country = (event_data.get("country") or "").strip()
    cmd = (event_data.get("command") or "").strip()

    has_loc = city and country and city != "Unknown" and country != "Unknown"
    loc_str = f"{city}, {country}" if has_loc else (country if country and country != "Unknown" else "")

    short_cmd = ""
    if cmd:
        first_segment = cmd.split("&&")[0].split(";")[0].split("|")[0].strip()
        short_cmd = first_segment[:22]

    # Select contextual subject matching the requested style
    if short_cmd and is_tor and risk >= 70:
        return f"[HoneyTrack] Risk {risk}: {source_ip} ran {short_cmd} on {svc} decoy"
    elif is_tor and loc_str:
        return f"[HoneyTrack] {svc} decoy hit by Tor exit node, {loc_str}"
    elif is_tor:
        return f"HoneyTrack alert: Tor exit node accessed your {svc} decoy (risk {risk})"
    elif short_cmd and loc_str:
        return f"HoneyTrack: Commands run on your {svc} decoy from {loc_str}"
    elif short_cmd:
        return f"[HoneyTrack] Risk {risk}: {source_ip} ran {short_cmd} on {svc} decoy"
    elif risk >= 70:
        now_utc = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
        return f"[HoneyTrack] {now_utc}: High-risk {svc} activity"
    else:
        return f"HoneyTrack alert: Security alert on {svc} decoy (risk {risk})"


def build_alert_html(event_data: dict, to_email: str) -> str:
    """Builds the responsive dark-themed executive incident dispatch email matching HoneyTrack design with fully inlined styles for 100% email client fidelity."""
    source_ip = event_data.get("source_ip", "Unknown")
    raw_service = event_data.get("service", "SSH")
    svc_name = raw_service.replace(" Decoy", "").replace(" Service", "").replace(" decoy", "").strip() or "SSH"
    risk = int(event_data.get("risk_score", 0))
    is_tor = bool(event_data.get("is_tor", False))
    country = event_data.get("country", "Unknown")
    city = event_data.get("city", "Unknown")
    isp = event_data.get("isp", "Tor Exit Node" if is_tor else "Unknown Network")
    attack_type = event_data.get("attack_type", "Intrusion Attempt")
    cmd = event_data.get("command")
    username = event_data.get("username")
    password_attempt = event_data.get("password")
    user_agent = event_data.get("user_agent")

    now = datetime.now(timezone.utc)
    when_str = now.strftime("%A, %d %b %Y · %H:%M UTC")
    short_time = now.strftime("%H:%M UTC")
    ts_formatted = now.strftime("%Y-%m-%d at %H:%M:%S UTC")

    operator_name = "Operator"
    if to_email:
        name_part = to_email.split("@")[0]
        clean_name = ''.join([c for c in name_part if not c.isdigit()]).strip()
        if clean_name.lower().endswith("n") and clean_name.lower() not in ("admin", "root", "operator", "john"):
            clean_name = clean_name[:-1]
        if clean_name:
            operator_name = clean_name.capitalize()

    if svc_name == "SSH":
        headline = "Heads up, someone's poking around your SSH decoy"
    elif svc_name == "HTTP":
        headline = "Heads up, someone's probing your HTTP decoy"
    elif svc_name == "FTP":
        headline = "Heads up, someone's poking around your FTP decoy"
    else:
        headline = f"Heads up, someone's poking around your {svc_name} decoy"

    if is_tor:
        origin_phrase = f"a Tor exit node in {city or 'Frankfurt'}, {country or 'Germany'}"
    elif city and country and city != "Unknown" and country != "Unknown":
        origin_phrase = f"{city}, {country}"
    else:
        origin_phrase = f"{source_ip}"

    if cmd:
        action_phrase = "logged in, and ran a single command to check what the machine was and read its list of users."
    elif username or password_attempt:
        action_phrase = f"and attempted authentication with username '{html.escape(str(username or 'root'))}'."
    elif user_agent:
        action_phrase = "and executed automated vulnerability reconnaissance."
    else:
        action_phrase = f"and initiated unauthorized {html.escape(str(attack_type))}."

    summary_lead = f"At {short_time} someone connected to your {svc_name} decoy from {origin_phrase}, {action_phrase}"

    threshold = getattr(settings, 'ALERT_RISK_THRESHOLD', 70)
    cooldown_sec = getattr(settings, 'ALERT_COOLDOWN_SECONDS', 300)
    cooldown_min = max(1, cooldown_sec // 60)

    if is_tor and risk >= threshold:
        why_trigger = "This one hit both."
    elif is_tor:
        why_trigger = "This one came through a verified Tor exit relay."
    else:
        why_trigger = f"This incident scored {risk}, meeting your security threshold of {threshold}."

    why_text = f"You only get these emails when the score reaches {threshold} or the traffic comes from Tor. {why_trigger} I'll stay quiet about {source_ip} for the next {cooldown_min} minutes so your inbox doesn't fill up."

    if city and country and city != "Unknown" and country != "Unknown":
        loc_display = f"{city}, {country}"
    elif country and country != "Unknown":
        loc_display = country
    else:
        loc_display = "Unknown Location"

    tor_badge = ' <span class="tor" style="display: inline-block; margin-left: 8px; padding: 1px 8px; border-radius: 4px; background-color: #231a3d; border: 1px solid #5b44a8; color: #c4b5fd; font-size: 11px; font-weight: 700; letter-spacing: 0.06em; vertical-align: 1px;">Tor exit</span>' if is_tor else ''

    if cmd:
        evidence_title = "What they typed"
        evidence_markup = (
            '<div style="text-align: left; margin: 0; padding: 0; direction: ltr;">'
            '<span class="cmt" style="color: #6b778c; display: block; text-align: left; font-family: inherit;"># Caught from the session</span>'
            f'<span class="prompt" style="color: #f0615f; font-family: inherit;">$ </span><span class="cmd" style="color: #ffffff; font-family: inherit;">{html.escape(cmd)}</span>'
            '</div>'
        )
        if "uname" in cmd or "passwd" in cmd:
            evidence_note = "Nothing fancy. It's what most people try first after getting a shell: see what the machine is running, then see who has accounts on it."
        else:
            evidence_note = "Terminal reconnaissance command intercepted inside the secure HoneyTrack isolation environment."
    elif username or password_attempt:
        evidence_title = "Credentials attempted"
        evidence_markup = (
            '<div style="text-align: left; margin: 0; padding: 0; direction: ltr;">'
            '<span class="cmt" style="color: #6b778c; display: block; text-align: left; font-family: inherit;"># Caught authentication attempt</span>'
            f'<span class="prompt" style="color: #f0615f; font-family: inherit;">User: </span><span class="cmd" style="color: #ffffff; font-family: inherit;">{html.escape(str(username or "-"))}</span><br>'
            f'<span class="prompt" style="color: #f0615f; font-family: inherit;">Pass: </span><span class="cmd" style="color: #ffffff; font-family: inherit;">{html.escape(str(password_attempt or "-"))}</span>'
            '</div>'
        )
        evidence_note = "Credential stuffing probe recorded and cataloged in HoneyTrack threat intelligence."
    elif user_agent:
        evidence_title = "Scanner signature"
        evidence_markup = (
            '<div style="text-align: left; margin: 0; padding: 0; direction: ltr;">'
            '<span class="cmt" style="color: #6b778c; display: block; text-align: left; font-family: inherit;"># Caught HTTP User-Agent</span>'
            f'<span class="cmd" style="color: #ffffff; display: block; text-align: left; font-family: inherit;">{html.escape(user_agent)}</span>'
            '</div>'
        )
        evidence_note = "Automated scanner signature identified by HoneyTrack decoy sensors."
    else:
        evidence_title = "Forensic signature"
        evidence_markup = (
            '<div style="text-align: left; margin: 0; padding: 0; direction: ltr;">'
            '<span class="cmt" style="color: #6b778c; display: block; text-align: left; font-family: inherit;"># Raw network telemetry</span>'
            f'<span class="cmd" style="color: #ffffff; display: block; text-align: left; font-family: inherit;">{html.escape(source_ip)} &rarr; Unauthorized port connection probe</span>'
            '</div>'
        )
        evidence_note = "Network connection anomaly recorded and blocked by active defense filters."

    if is_tor:
        tor_firewall_note = "Tor exit nodes get swapped around a lot, so don't expect the block to last forever."
    else:
        tor_firewall_note = "Adding this drop rule will immediately terminate and discard all incoming packets from this address."

    dashboard_url = getattr(settings, 'DASHBOARD_URL', 'http://localhost:5000')

    # Prepare inline base64 fallback for browser and offline previews
    logo_b64 = ""
    logo_path = os.path.join(settings.BASE_DIR, "dashboard", "static", "img", "email_logo.png")
    if not os.path.exists(logo_path):
        logo_path = os.path.join(settings.BASE_DIR, "dashboard", "static", "img", "logo.png")
    if os.path.exists(logo_path):
        try:
            with open(logo_path, "rb") as lf:
                logo_b64 = base64.b64encode(lf.read()).decode("ascii")
        except Exception:
            logo_b64 = ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <meta name="supported-color-schemes" content="dark">
  <title>HoneyTrack alert</title>
  <style>
    :root {{ color-scheme: dark; }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 32px 16px;
      background-color: #070a12;
      color: #e4e8f0;
      font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      font-size: 15px;
      line-height: 1.6;
      -webkit-text-size-adjust: 100%;
    }}
    table {{ border-collapse: collapse; border-spacing: 0; }}
    td {{ padding: 0; vertical-align: top; }}
    a {{ color: #4cc2ff; }}
    p {{ margin: 0 0 14px; text-align: left; }}
    .outer {{ width: 100%; background-color: #070a12; }}
    .wrap {{ width: 100%; max-width: 640px; margin: 0 auto; text-align: left; }}
    .card {{ background-color: #0d1320; border: 1px solid #1d2638; border-radius: 10px; text-align: left; }}
    .bar td {{ padding: 18px 36px; border-bottom: 1px solid #1d2638; }}
    .brand {{ font-weight: 700; font-size: 16px; color: #ffffff; vertical-align: middle; }}
    .brand-icon {{ display: block; width: 28px; height: 35px; border: 0; outline: none; text-decoration: none; vertical-align: middle; }}
    .when {{ font-size: 12.5px; color: #8a96ab; text-align: right; }}
    .pad {{ padding: 28px 36px; text-align: left; }}
    .pad-tight {{ padding: 28px 36px 4px 36px; text-align: left; }}
    .pad-cta {{ padding: 8px 36px 34px 36px; text-align: center; }}
    .pad-sign {{ padding: 0 36px 30px 36px; text-align: left; }}
    .divider {{ border-top: 1px solid #1d2638; font-size: 0; line-height: 0; height: 0; }}
    h1 {{ margin: 0; font-size: 28px; line-height: 1.2; font-weight: 700; color: #ffffff; text-align: left; }}
    h2 {{ margin: 0 0 12px; font-size: 18px; line-height: 1.3; font-weight: 700; color: #ffffff; text-align: left; }}
    .lead {{ color: #cfd6e3; text-align: left; }}
    .muted {{ color: #8a96ab; font-size: 14px; text-align: left; }}
    .small {{ font-size: 13px; }}
    .note {{ margin: 12px 0 0 0; text-align: left; }}
    .strong {{ color: #ffffff; font-weight: 700; }}
    .why {{ background-color: #0a0f1a; border: 1px solid #1d2638; border-radius: 8px; padding: 14px 16px; font-size: 14px; color: #aab4c6; text-align: left; }}
    .details {{ width: 100%; border: 1px solid #1d2638; border-radius: 8px; text-align: left; }}
    .details td {{ padding: 11px 16px; border-bottom: 1px solid #172033; font-size: 14px; text-align: left; }}
    .details .last td {{ border-bottom: 0; }}
    .k {{ width: 150px; color: #8a96ab; text-align: left; }}
    .v {{ color: #ffffff; font-weight: 600; word-break: break-word; text-align: left; }}
    .mono {{ font-family: ui-monospace, "SF Mono", Menlo, Consolas, "Courier New", monospace; }}
    .cyan {{ color: #4cc2ff; }}
    .red {{ color: #ff7a78; }}
    .tor {{ display: inline-block; margin-left: 8px; padding: 1px 8px; border-radius: 4px; background-color: #231a3d; border: 1px solid #5b44a8; color: #c4b5fd; font-size: 11px; font-weight: 700; }}
    .code-box {{ margin: 0; padding: 14px 16px; background-color: #070b13; border: 1px solid #1d2638; border-radius: 8px; font-size: 13px; line-height: 1.7; white-space: pre-wrap; word-break: break-word; text-align: left !important; direction: ltr !important; }}
    .cmt {{ color: #6b778c; text-align: left; }}
    .prompt {{ color: #f0615f; }}
    .cmd {{ color: #ffffff; text-align: left; }}
    .fw {{ color: #a3e635; text-align: left; }}
    .btn {{ display: inline-block; background-color: #dc2626; color: #ffffff !important; text-decoration: none; font-weight: 700; font-size: 15px; padding: 14px 28px; border-radius: 8px; }}
    .sign {{ margin: 0; color: #cfd6e3; text-align: left; }}
    .foot td {{ padding: 18px 36px; border-top: 1px solid #1d2638; background-color: #0a0f1a; font-size: 12.5px; color: #6f7b90; text-align: center; border-radius: 0 0 10px 10px; }}
    @media only screen and (max-width: 520px) {{
      body {{ padding: 16px 10px !important; }}
      .bar td, .pad, .pad-tight, .pad-cta, .pad-sign, .foot td {{ padding-left: 20px !important; padding-right: 20px !important; }}
      .bar td {{ display: block !important; text-align: left !important; }}
      h1 {{ font-size: 23px !important; }}
      .details td {{ display: block !important; width: auto !important; border-bottom: 0 !important; padding: 4px 16px !important; }}
      .details .k {{ padding-top: 12px !important; font-size: 12.5px !important; }}
      .details .v {{ padding-bottom: 12px !important; border-bottom: 1px solid #172033 !important; }}
      .details .last .v {{ border-bottom: 0 !important; }}
    }}
  </style>
</head>
<body style="margin: 0; padding: 32px 16px; background-color: #070a12; color: #e4e8f0; font-family: -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; font-size: 15px; line-height: 1.6; -webkit-text-size-adjust: 100%;">

  <!-- Preheader preview text for inbox snippet -->
  <div class="preheader" style="display: none !important; max-height: 0; overflow: hidden; opacity: 0; font-size: 1px; line-height: 1px; color: #070a12; mso-hide: all;">
    Someone from {loc_display} just logged in to your {svc_name} decoy.
  </div>

  <table role="presentation" class="outer" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; background-color: #070a12; margin: 0; padding: 0; border-collapse: collapse; border-spacing: 0;">
    <tr>
      <td align="center" style="padding: 0; vertical-align: top;">
        <table role="presentation" class="wrap card" width="100%" align="center" cellpadding="0" cellspacing="0" style="width: 100%; max-width: 640px; margin: 0 auto; background-color: #0d1320; border: 1px solid #1d2638; border-radius: 10px; border-collapse: collapse; border-spacing: 0; text-align: left; overflow: hidden;">
          <tr>
            <td align="left" style="padding: 0; vertical-align: top; text-align: left;">

              <!-- Top bar -->
              <table role="presentation" class="bar" width="100%" cellpadding="0" cellspacing="0" align="left" style="width: 100%; border-collapse: collapse; border-spacing: 0; text-align: left;">
                <tr>
                  <td align="left" style="padding: 18px 36px; border-bottom: 1px solid #1d2638; vertical-align: middle; text-align: left;">
                    <table role="presentation" cellpadding="0" cellspacing="0" align="left" style="border-collapse: collapse; border-spacing: 0; vertical-align: middle;">
                      <tr>
                        <td align="left" style="vertical-align: middle; padding: 0 10px 0 0; line-height: 0;">
                          <img src="cid:honeytrack-logo" onerror="this.onerror=null;this.src='data:image/png;base64,{logo_b64}';" width="28" height="35" alt="HoneyTrack" class="brand-icon" style="display: block; width: 28px; height: 35px; border: 0; outline: none; text-decoration: none; vertical-align: middle;" />
                        </td>
                        <td align="left" style="vertical-align: middle; padding: 0;">
                          <span class="brand" style="font-weight: 700; font-size: 16px; letter-spacing: 0.02em; color: #ffffff; vertical-align: middle; display: inline-block;">HoneyTrack</span>
                        </td>
                      </tr>
                    </table>
                  </td>
                  <td class="when" align="right" style="padding: 18px 36px; border-bottom: 1px solid #1d2638; font-size: 12.5px; color: #8a96ab; text-align: right; vertical-align: middle;">
                    {when_str}
                  </td>
                </tr>
              </table>

              <!-- Headline -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" align="left" style="width: 100%; border-collapse: collapse; border-spacing: 0; text-align: left;">
                <tr>
                  <td class="pad-tight" align="left" style="padding: 28px 36px 4px 36px; vertical-align: top; text-align: left;">
                    <h1 align="left" style="margin: 0; font-size: 28px; line-height: 1.2; font-weight: 700; letter-spacing: -0.01em; color: #ffffff; text-align: left;">{headline}</h1>
                  </td>
                </tr>
              </table>

              <!-- Intro -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" align="left" style="width: 100%; border-collapse: collapse; border-spacing: 0; text-align: left;">
                <tr>
                  <td class="pad" align="left" style="padding: 28px 36px; vertical-align: top; text-align: left;">
                    <p class="lead" align="left" style="margin: 0 0 14px 0; color: #cfd6e3; font-size: 15px; line-height: 1.6; text-align: left;">Hi {operator_name},</p>
                    <p class="lead" align="left" style="margin: 0 0 14px 0; color: #cfd6e3; font-size: 15px; line-height: 1.6; text-align: left;">{summary_lead}</p>
                    <p class="lead" align="left" style="margin: 0 0 14px 0; color: #cfd6e3; font-size: 15px; line-height: 1.6; text-align: left;">Nothing real was touched. The decoy isn't connected to anything. I scored it <span class="strong" style="color: #ffffff; font-weight: 700;">{risk} out of 100</span>, which is why you're hearing about it.</p>
                    <div class="why" align="left" style="background-color: #0a0f1a; border: 1px solid #1d2638; border-radius: 8px; padding: 14px 16px; font-size: 14px; color: #aab4c6; line-height: 1.6; margin: 14px 0 0 0; text-align: left;">{why_text}</div>
                  </td>
                </tr>
              </table>

              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse; border-spacing: 0;">
                <tr>
                  <td class="divider" style="border-top: 1px solid #1d2638; font-size: 0; line-height: 0; height: 0; padding: 0;">&nbsp;</td>
                </tr>
              </table>

              <!-- Details -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" align="left" style="width: 100%; border-collapse: collapse; border-spacing: 0; text-align: left;">
                <tr>
                  <td class="pad" align="left" style="padding: 28px 36px; vertical-align: top; text-align: left;">
                    <h2 align="left" style="margin: 0 0 12px 0; font-size: 18px; line-height: 1.3; font-weight: 700; color: #ffffff; text-align: left;">The details</h2>
                    <table role="presentation" class="details" width="100%" align="left" cellpadding="0" cellspacing="0" style="width: 100%; border: 1px solid #1d2638; border-radius: 8px; border-collapse: collapse; border-spacing: 0; background-color: #080d16; text-align: left; overflow: hidden;">
                      <tr>
                        <td class="k" align="left" style="width: 150px; color: #8a96ab; padding: 11px 16px; border-bottom: 1px solid #172033; font-size: 14px; vertical-align: top; text-align: left;">IP address</td>
                        <td class="v mono" align="left" style="color: #ffffff; font-weight: 600; word-break: break-word; padding: 11px 16px; border-bottom: 1px solid #172033; font-size: 14px; font-family: ui-monospace, 'SF Mono', Menlo, Consolas, 'Courier New', monospace; vertical-align: top; text-align: left;">
                          {source_ip}{tor_badge}
                        </td>
                      </tr>
                      <tr>
                        <td class="k" align="left" style="width: 150px; color: #8a96ab; padding: 11px 16px; border-bottom: 1px solid #172033; font-size: 14px; vertical-align: top; text-align: left;">What it hit</td>
                        <td class="v cyan" align="left" style="color: #4cc2ff; font-weight: 600; word-break: break-word; padding: 11px 16px; border-bottom: 1px solid #172033; font-size: 14px; text-align: left;">{svc_name} decoy service</td>
                      </tr>
                      <tr>
                        <td class="k" align="left" style="width: 150px; color: #8a96ab; padding: 11px 16px; border-bottom: 1px solid #172033; font-size: 14px; vertical-align: top; text-align: left;">Looks like</td>
                        <td class="v red" align="left" style="color: #ff7a78; font-weight: 600; word-break: break-word; padding: 11px 16px; border-bottom: 1px solid #172033; font-size: 14px; text-align: left;">{attack_type}</td>
                      </tr>
                      <tr>
                        <td class="k" align="left" style="width: 150px; color: #8a96ab; padding: 11px 16px; border-bottom: 1px solid #172033; font-size: 14px; vertical-align: top; text-align: left;">Where from</td>
                        <td class="v" align="left" style="color: #ffffff; font-weight: 600; word-break: break-word; padding: 11px 16px; border-bottom: 1px solid #172033; font-size: 14px; text-align: left;">{loc_display}</td>
                      </tr>
                      <tr>
                        <td class="k" align="left" style="width: 150px; color: #8a96ab; padding: 11px 16px; border-bottom: 1px solid #172033; font-size: 14px; vertical-align: top; text-align: left;">Network</td>
                        <td class="v" align="left" style="color: #ffffff; font-weight: 600; word-break: break-word; padding: 11px 16px; border-bottom: 1px solid #172033; font-size: 14px; text-align: left;">{isp}</td>
                      </tr>
                      <tr class="last">
                        <td class="k" align="left" style="width: 150px; color: #8a96ab; padding: 11px 16px; border-bottom: 0; font-size: 14px; vertical-align: top; text-align: left;">When</td>
                        <td class="v mono" align="left" style="color: #ffffff; font-weight: 600; word-break: break-word; padding: 11px 16px; border-bottom: 0; font-size: 14px; font-family: ui-monospace, 'SF Mono', Menlo, Consolas, 'Courier New', monospace; vertical-align: top; text-align: left;">{ts_formatted}</td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>

              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse; border-spacing: 0;">
                <tr>
                  <td class="divider" style="border-top: 1px solid #1d2638; font-size: 0; line-height: 0; height: 0; padding: 0;">&nbsp;</td>
                </tr>
              </table>

              <!-- Captured command / forensic block -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" align="left" style="width: 100%; border-collapse: collapse; border-spacing: 0; text-align: left;">
                <tr>
                  <td class="pad" align="left" style="padding: 28px 36px; vertical-align: top; text-align: left;">
                    <h2 align="left" style="margin: 0 0 12px 0; font-size: 18px; line-height: 1.3; font-weight: 700; color: #ffffff; text-align: left;">{evidence_title}</h2>
                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" align="left" style="width: 100%; border-collapse: collapse; border-spacing: 0; text-align: left; margin: 0;">
                      <tr>
                        <td align="left" style="padding: 14px 16px; background-color: #070b13; border: 1px solid #1d2638; border-radius: 8px; font-family: ui-monospace, 'SF Mono', Menlo, Consolas, 'Courier New', monospace; font-size: 13px; line-height: 1.7; text-align: left !important; direction: ltr !important; color: #ffffff;">
                          {evidence_markup}
                        </td>
                      </tr>
                    </table>
                    <p class="muted note" align="left" style="margin: 12px 0 0 0; color: #8a96ab; font-size: 14px; line-height: 1.5; text-align: left;">{evidence_note}</p>
                  </td>
                </tr>
              </table>

              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse; border-spacing: 0;">
                <tr>
                  <td class="divider" style="border-top: 1px solid #1d2638; font-size: 0; line-height: 0; height: 0; padding: 0;">&nbsp;</td>
                </tr>
              </table>

              <!-- Firewall mitigation commands -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" align="left" style="width: 100%; border-collapse: collapse; border-spacing: 0; text-align: left;">
                <tr>
                  <td class="pad" align="left" style="padding: 28px 36px; vertical-align: top; text-align: left;">
                    <h2 align="left" style="margin: 0 0 12px 0; font-size: 18px; line-height: 1.3; font-weight: 700; color: #ffffff; text-align: left;">If you'd rather block them</h2>
                    <p class="muted" align="left" style="margin: 0 0 14px 0; color: #8a96ab; font-size: 14px; line-height: 1.5; text-align: left;">Either of these shuts the door on that address. Pick the one for whichever firewall you use.</p>
                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" align="left" style="width: 100%; border-collapse: collapse; border-spacing: 0; text-align: left; margin: 0;">
                      <tr>
                        <td align="left" style="padding: 14px 16px; background-color: #070b13; border: 1px solid #1d2638; border-radius: 8px; font-family: ui-monospace, 'SF Mono', Menlo, Consolas, 'Courier New', monospace; font-size: 13px; line-height: 1.7; text-align: left !important; direction: ltr !important; color: #a3e635;">
                          <div style="text-align: left; margin: 0; padding: 0; direction: ltr;">
                            <span class="fw" style="color: #a3e635; display: block; text-align: left; margin-bottom: 4px; font-family: inherit;">sudo ufw deny from {source_ip} to any comment 'HoneyTrack Auto-Drop'</span>
                            <span class="fw" style="color: #a3e635; display: block; text-align: left; font-family: inherit;">sudo iptables -A INPUT -s {source_ip} -j DROP</span>
                          </div>
                        </td>
                      </tr>
                    </table>
                    <p class="muted note" align="left" style="margin: 12px 0 0 0; color: #8a96ab; font-size: 14px; line-height: 1.5; text-align: left;">{tor_firewall_note}</p>
                  </td>
                </tr>
              </table>

              <!-- Dashboard CTA Button -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse; border-spacing: 0;">
                <tr>
                  <td class="pad-cta" align="center" style="padding: 8px 36px 34px 36px; text-align: center; vertical-align: top;">
                    <a class="btn" href="{dashboard_url}" style="display: inline-block; background-color: #dc2626; color: #ffffff !important; text-decoration: none; font-weight: 700; font-size: 15px; padding: 14px 28px; border-radius: 8px; text-align: center;">See it on the dashboard</a>
                    <p class="muted small" align="center" style="margin: 14px 0 0 0; color: #8a96ab; font-size: 13px; line-height: 1.5; text-align: center;">The full session and the map are there if you want a closer look.</p>
                  </td>
                </tr>
              </table>

              <!-- Sign-off -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" align="left" style="width: 100%; border-collapse: collapse; border-spacing: 0; text-align: left;">
                <tr>
                  <td class="pad-sign" align="left" style="padding: 0 36px 30px 36px; vertical-align: top; text-align: left;">
                    <p class="sign" align="left" style="margin: 0; color: #cfd6e3; font-size: 15px; line-height: 1.6; text-align: left;">Cheers,<br><span class="strong" style="color: #ffffff; font-weight: 700;">HoneyTrack</span></p>
                  </td>
                </tr>
              </table>

              <!-- Footer -->
              <table role="presentation" class="foot" width="100%" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse; border-spacing: 0;">
                <tr>
                  <td align="center" style="padding: 18px 36px; border-top: 1px solid #1d2638; background-color: #0a0f1a; font-size: 12.5px; color: #6f7b90; text-align: center; border-radius: 0 0 10px 10px; line-height: 1.5;">
                    Sent by HoneyTrack, running on your machine. Alerts go out at risk {threshold} or above, or for Tor traffic, once per IP every {cooldown_min} minutes.
                  </td>
                </tr>
              </table>

            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>

</body>
</html>"""


def _build_alert_mime_message(event_data: dict, to_email: str) -> MIMEMultipart:
    """Creates a configured MIMEMultipart email message with updated HTML body, inline CID logo, and dynamic subject."""
    msg = MIMEMultipart("related")
    subject = build_alert_subject(event_data)
    msg["Subject"] = subject
    msg["From"] = settings.ALERT_FROM_EMAIL or settings.SMTP_USERNAME
    msg["To"] = to_email
    
    msg_alt = MIMEMultipart("alternative")
    html_content = build_alert_html(event_data, to_email)
    msg_alt.attach(MIMEText(html_content, "html", "utf-8"))
    msg.attach(msg_alt)

    # Attach inline knight brand logo
    logo_path = os.path.join(settings.BASE_DIR, "dashboard", "static", "img", "email_logo.png")
    if not os.path.exists(logo_path):
        logo_path = os.path.join(settings.BASE_DIR, "dashboard", "static", "img", "logo.png")

    if os.path.exists(logo_path):
        try:
            with open(logo_path, "rb") as lf:
                img_data = lf.read()
            img_part = MIMEImage(img_data, _subtype="png")
            img_part.add_header("Content-ID", "<honeytrack-logo>")
            img_part.add_header("Content-Disposition", "inline", filename="honeytrack-logo.png")
            msg.attach(img_part)
        except Exception as e:
            logger.warning(f"[EMAIL] Failed to attach inline brand logo: {e}")

    return msg


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

    try:
        msg = _build_alert_mime_message(event_data, to_email)

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(settings.SMTP_USERNAME, password)
            server.sendmail(settings.ALERT_FROM_EMAIL or settings.SMTP_USERNAME, to_email, msg.as_string())

        print(f"[EMAIL SUCCESS] Alert dispatched to {to_email} for IP {source_ip} (Subject: {msg['Subject']})")
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
            server.ehlo()
            server.starttls()
            server.ehlo()
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

            msg = _build_alert_mime_message(test_event, recipient)
            server.sendmail(settings.ALERT_FROM_EMAIL or settings.SMTP_USERNAME, recipient, msg.as_string())

        return True, f"Authentication successful! Test security alert delivered to {recipient} via Gmail SMTP (Subject: {msg['Subject']})."

    except smtplib.SMTPAuthenticationError as e:
        return False, f"Gmail SMTP Authentication Failed (535): Invalid or revoked Google App Password. Error: {e.smtp_error.decode('utf-8', errors='ignore') if isinstance(e.smtp_error, bytes) else str(e)}"
    except Exception as e:
        return False, f"SMTP Connection Error: {str(e)}"
