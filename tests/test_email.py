"""
HoneyTrack — Email Alert Diagnostic & Verification Tool
Tests SMTP connection, Google App Password authentication, and sends a test alert email.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from config import settings

def test_smtp_connection():
    print("=" * 55)
    print(" HoneyTrack Email Alert Verification ")
    print("=" * 55)
    print(f"[1/3] Checking Configuration:")
    print(f"      SMTP Host:     {settings.SMTP_HOST}:{settings.SMTP_PORT}")
    print(f"      Username:      {settings.SMTP_USERNAME}")
    
    clean_pw = (settings.SMTP_PASSWORD or "").replace(" ", "").strip()
    masked_pw = clean_pw[:3] + "*" * (len(clean_pw) - 6) + clean_pw[-3:] if len(clean_pw) >= 6 else "***"
    print(f"      App Password:  {masked_pw} ({len(clean_pw)} chars)")
    print(f"      Recipient:     {settings.ALERT_TO_EMAIL or settings.SMTP_USERNAME}")

    if not clean_pw:
        print("\n[-] Error: SMTP_PASSWORD is empty in config/settings.py")
        return False

    print("\n[2/3] Connecting to Google SMTP Server...")
    try:
        server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=12)
        server.starttls()
        print("      [OK] TLS Encryption Established")
        
        print("      Authenticating credentials with Google...")
        server.login(settings.SMTP_USERNAME, clean_pw)
        print("      [OK] Authentication SUCCESSFUL!")
    except smtplib.SMTPAuthenticationError as e:
        print("\n[-] Authentication Failed (535 BadCredentials):")
        print("    Google rejected the 16-character App Password.")
        print("    Common reasons:")
        print("    1. 2-Step Verification is turned OFF or was toggled on the Google account.")
        print("    2. The App Password was generated under a different Google account in the browser.")
        print("    3. A typo occurred while copying the 16 letters.")
        print("\n    To fix:")
        print("    1. Open Incognito window, log in directly to: " + settings.SMTP_USERNAME)
        print("    2. Go to: https://myaccount.google.com/apppasswords")
        print("    3. Generate a new password named 'HoneyTrack', copy 16 letters.")
        print("    4. Paste into config/settings.py at line 155.")
        return False
    except Exception as e:
        print(f"\n[-] Connection failed: {e}")
        return False

    print("\n[3/3] Sending Test Alert Email...")
    try:
        recipient = settings.ALERT_TO_EMAIL or settings.SMTP_USERNAME
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "[HoneyTrack] Test Alert & System Verification"
        msg["From"] = settings.ALERT_FROM_EMAIL or settings.SMTP_USERNAME
        msg["To"] = recipient

        html_body = f"""
        <html>
          <body style="font-family: monospace; background-color: #0e0e0e; color: #e5e2e1; padding: 20px;">
            <div style="border: 1px solid #00e479; background-color: #131313; padding: 20px; border-radius: 4px; max-width: 550px;">
              <h2 style="color: #00e479; margin-top: 0;">[OK] HoneyTrack Email Alerts Verified</h2>
              <p>Your HoneyTrack defensive honeypot notification system is properly configured and operational.</p>
              <hr style="border: 0; border-top: 1px solid #353534; margin: 15px 0;">
              <p><b>Timestamp:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
              <p><b>Security Status:</b> Active Intercept Telemetry Enabled</p>
            </div>
          </body>
        </html>
        """
        msg.attach(MIMEText(html_body, "html"))
        server.sendmail(settings.ALERT_FROM_EMAIL or settings.SMTP_USERNAME, recipient, msg.as_string())
        server.quit()
        print(f"      [OK] Test email delivered successfully to {recipient}!")
        print("\n" + "=" * 55)
        print("  ALL EMAIL CHECKS PASSED [OK]")
        print("=" * 55)
        return True
    except Exception as e:
        print(f"[-] Failed to dispatch test email: {e}")
        return False

if __name__ == "__main__":
    success = test_smtp_connection()
    sys.exit(0 if success else 1)
