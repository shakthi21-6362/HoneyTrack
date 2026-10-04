import os
import tempfile
from datetime import datetime, timezone

from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

from config.settings import FTP_HOST, FTP_PORT
from database.database import SessionLocal
from database.repositories import save_event
from analysis.fingerprint import analyze_event

class HoneypotAuthorizer(DummyAuthorizer):
    """
    Custom authorizer for the FTP honeypot that accepts any credentials
    and logs the attempt to the database via the analysis pipeline.
    """
    def __init__(self, fake_dir: str):
        super().__init__()
        self.fake_dir = fake_dir

    def validate_authentication(self, username, password, handler):
        """
        Intercept authentication, log it, run analysis, and allow access.
        """
        source_ip = handler.remote_ip
        from defense.firewall import is_ip_blocked
        if is_ip_blocked(source_ip):
            print(f"[FTP/FIREWALL] Connection rejected for blacklisted IP {source_ip}")
            from pyftpdlib.authorizers import AuthenticationFailed
            raise AuthenticationFailed("Access denied by firewall.")

        print(f"[FTP] Login attempt from {source_ip} with username '{username}' and password '{password}'")

        try:
            # 1. Run analysis pipeline
            analysis_result = analyze_event(
                source_ip=source_ip,
                service='FTP',
                username=username,
                password=password,
                command=None,
                attempt_count=1
            )
            
            # 2. Build event data dictionary
            event_data = {
                "timestamp": datetime.now(timezone.utc),
                "source_ip": source_ip,
                "service": "FTP",
                "username": username,
                "password": password,
                "command": None,
                "user_agent": None,
                "country": analysis_result.get("country"),
                "city": analysis_result.get("city"),
                "isp": analysis_result.get("isp"),
                "latitude": analysis_result.get("latitude"),
                "longitude": analysis_result.get("longitude"),
                "attack_type": analysis_result.get("attack_type"),
                "risk_score": analysis_result.get("risk_score"),
                "is_tor": analysis_result.get("is_tor", False),
                "is_demo": False
            }
            
            # 3. Save event to database
            db = SessionLocal()
            try:
                save_event(db, event_data)
                from defense.firewall import check_and_auto_block
                check_and_auto_block(event_data)
                if event_data.get("risk_score", 0) >= 70 or event_data.get("is_tor"):
                    from alerts.email_alerts import send_alert_email
                    send_alert_email(event_data)
            finally:
                db.close()
                
        except Exception as e:
            print(f"[FTP] Error saving event to database: {e}")
            
        # 4. Accept ALL credentials and map them to the fake directory
        # If the user isn't already added, add them with read-only permissions
        if not self.has_user(username):
            self.add_user(username, password, self.fake_dir, perm='elr')
        else:
            # Update password in case they try again with a different one
            self.user_table[username]['pwd'] = password

class HoneypotFTPHandler(FTPHandler):
    """
    Custom FTP handler for the honeypot to capture and log specific commands
    or file transfers if needed.
    """
    def on_file_received(self, file: str):
        print(f"[FTP] Received file: {file}")

    def on_file_sent(self, file: str):
        print(f"[FTP] Sent file: {file}")
        
    def on_incomplete_file_received(self, file: str):
        print(f"[FTP] Incomplete file received: {file}")

    def on_incomplete_file_sent(self, file: str):
        print(f"[FTP] Incomplete file sent: {file}")

def start_ftp_honeypot(host: str = None, port: int = None):
    """
    Starts the FTP honeypot server.
    
    Args:
        host: IP address to bind to. Defaults to config settings.
        port: Port number to bind to. Defaults to config settings.
    """
    host = host or FTP_HOST
    port = port or FTP_PORT
    
    # Create a minimal fake filesystem in a temporary directory
    fake_dir = tempfile.mkdtemp(prefix="honeytrack_ftp_")
    
    # Create a couple of fake files to make it look enticing
    try:
        with open(os.path.join(fake_dir, "readme.txt"), "w") as f:
            f.write("Welcome to the backup server. Please do not modify files.\n")
        with open(os.path.join(fake_dir, "passwords.bak"), "w") as f:
            f.write("admin:admin123\nroot:toor\ndatabase:db_pass_2023\n")
    except Exception as e:
        print(f"[FTP] Error creating fake files: {e}")

    # Set up the authorizer and handler
    authorizer = HoneypotAuthorizer(fake_dir)
    
    handler = HoneypotFTPHandler
    handler.authorizer = authorizer
    handler.banner = "Welcome to FTP server ready."
    
    # Start the server
    address = (host, port)
    server = FTPServer(address, handler)
    
    print(f"[FTP] Starting FTP honeypot on {host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[FTP] Shutting down FTP honeypot...")
    except Exception as e:
        print(f"[FTP] Server error: {e}")
    finally:
        server.close_all()
