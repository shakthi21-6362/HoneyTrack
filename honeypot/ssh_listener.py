"""
SSH Honeypot listener module using Paramiko.
"""

import os
import socket
import threading
import logging
from datetime import datetime, timezone
import paramiko

from config.settings import (
    SSH_HOST,
    SSH_PORT,
    SSH_HOST_KEY_PATH,
    SSH_BANNER,
    SSH_FAKE_HOSTNAME,
    SSH_FAKE_MOTD,
    SSH_COMMAND_RESPONSES
)
from database.database import SessionLocal
from database.repositories import save_event
from analysis.fingerprint import analyze_event
from sessions.session_manager import session_manager
from sessions.session_recorder import session_recorder

logger = logging.getLogger(__name__)

class SSHServerInterface(paramiko.ServerInterface):
    """Paramiko ServerInterface implementation for the honeypot."""

    def __init__(self, client_ip: str):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.username = None
        self.password = None
        self.session_id = session_manager.start_session(client_ip, 'SSH')

    def check_channel_request(self, kind: str, chanid: int) -> int:
        """Allow session channel requests."""
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        """Accept all passwords and log the attempt."""
        self.username = username
        self.password = password
        logger.info(f"[SSH] Auth attempt from {self.client_ip} - User: {username}, Password: {password}")
        session_manager.update_session(self.session_id, username=username, password=password)

        # Log auth attempt event to database immediately
        db = SessionLocal()
        try:
            attempt_count = session_manager.get_attempt_count(self.client_ip, 'SSH')
            analysis_result = analyze_event(
                source_ip=self.client_ip,
                service='SSH',
                username=username,
                password=password,
                command=None,
                attempt_count=attempt_count
            )
            event_data = {
                "timestamp": datetime.now(timezone.utc),
                "source_ip": self.client_ip,
                "service": "SSH",
                "username": username,
                "password": password,
                "command": None,
                "user_agent": None,
                "country": analysis_result.get("country"),
                "city": analysis_result.get("city"),
                "isp": analysis_result.get("isp"),
                "latitude": analysis_result.get("latitude"),
                "longitude": analysis_result.get("longitude"),
                "attack_type": analysis_result.get("attack_type", "credential_attempt"),
                "risk_score": analysis_result.get("risk_score", 40),
                "is_tor": analysis_result.get("is_tor", False),
                "is_demo": False
            }
            save_event(db, event_data)
            from defense.firewall import check_and_auto_block
            check_and_auto_block(event_data)
            if event_data.get("risk_score", 0) >= 70 or event_data.get("is_tor"):
                from alerts.email_alerts import send_alert_email
                send_alert_email(event_data)
        except Exception as e:
            logger.error(f"[SSH] Error saving auth event: {e}")
        finally:
            db.close()

        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        """Reject public key auth to force password auth."""
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        """Only allow password authentication."""
        return 'password'
        
    def check_channel_shell_request(self, channel):
        """Allow shell requests."""
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """Allow PTY requests."""
        return True

def handle_connection(client_socket: socket.socket, client_addr: tuple, host_key: paramiko.RSAKey):
    """
    Handle an individual SSH client connection.

    Args:
        client_socket: The connected client socket.
        client_addr: Tuple of (ip, port).
        host_key: The RSA host key for the server.
    """
    client_ip = client_addr[0]
    from defense.firewall import is_ip_blocked
    if is_ip_blocked(client_ip):
        logger.info(f"[SSH/FIREWALL] Dropped connection from blacklisted IP {client_ip}")
        try:
            client_socket.sendall(b"Packet dropped by HoneyTrack Active Defense Firewall.\r\n")
            client_socket.close()
        except Exception:
            pass
        return

    transport = paramiko.Transport(client_socket)
    transport.add_server_key(host_key)
    transport.local_version = f"SSH-2.0-{SSH_BANNER}"

    server = SSHServerInterface(client_ip)
    
    try:
        transport.start_server(server=server)
    except paramiko.SSHException as e:
        logger.error(f"[SSH] SSH negotiation failed with {client_ip}: {e}")
        return

    channel = transport.accept(20)
    if channel is None:
        logger.info(f"[SSH] Client {client_ip} closed connection early.")
        session_manager.end_session(server.session_id)
        return
        
    server.event.wait(10)
    if not server.event.is_set():
        logger.info(f"[SSH] Client {client_ip} did not request a shell.")
        channel.close()
        session_manager.end_session(server.session_id)
        return

    # Emulate the fake shell
    try:
        session_recorder.start_recording(server.session_id, client_ip, service="SSH", username=server.username)
        motd_str = SSH_FAKE_MOTD + "\r\n"
        channel.send(motd_str.encode('utf-8'))
        session_recorder.record_event(server.session_id, "o", motd_str)

        prompt = f"root@{SSH_FAKE_HOSTNAME}:~# "
        channel.send(prompt.encode('utf-8'))
        session_recorder.record_event(server.session_id, "o", prompt)
        
        command_buffer = b""
        channel.settimeout(60.0) # 60 seconds inactivity timeout
        
        while True:
            char = channel.recv(1)
            if not char:
                break
                
            channel.send(char) # Echo
            session_recorder.record_event(server.session_id, "o", char.decode('utf-8', errors='ignore'))
            
            if char == b'\r':
                channel.send(b'\n')
                session_recorder.record_event(server.session_id, "o", "\n")
                command = command_buffer.decode('utf-8', errors='ignore').strip()
                command_buffer = b""
                
                if command:
                    logger.info(f"[SSH] Command from {client_ip}: {command}")
                    session_manager.update_session(server.session_id, command=command)
                    session_recorder.record_command(server.session_id, command)
                    
                    # Analyze and save event
                    db = SessionLocal()
                    try:
                        attempt_count = session_manager.get_attempt_count(client_ip, 'SSH')
                        analysis_result = analyze_event(
                            source_ip=client_ip,
                            service='SSH',
                            username=server.username,
                            password=server.password,
                            command=command,
                            attempt_count=attempt_count
                        )
                        
                        event_data = {
                            "timestamp": datetime.now(timezone.utc),
                            "source_ip": client_ip,
                            "service": "SSH",
                            "username": server.username,
                            "password": server.password,
                            "command": command,
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
                        
                        save_event(db, event_data)
                        from defense.firewall import check_and_auto_block
                        check_and_auto_block(event_data)
                        if event_data.get("risk_score", 0) >= 70 or event_data.get("is_tor"):
                            from alerts.email_alerts import send_alert_email
                            send_alert_email(event_data)
                    except Exception as e:
                        logger.error(f"[SSH] Error processing event: {e}")
                    finally:
                        db.close()
                        
                    if command in ['exit', 'logout']:
                        break
                    
                    # Send fake response
                    cmd_base = command.split()[0]
                    response = SSH_COMMAND_RESPONSES.get(cmd_base, f"-bash: {cmd_base}: command not found\n")
                    if not response.endswith('\n'):
                        response += '\n'
                    resp_crlf = response.replace('\n', '\r\n')
                    channel.send(resp_crlf.encode('utf-8'))
                    session_recorder.record_event(server.session_id, "o", resp_crlf)
                    
                channel.send(prompt.encode('utf-8'))
                session_recorder.record_event(server.session_id, "o", prompt)
            elif char == b'\x03': # Ctrl+C
                channel.send(b'^C\r\n' + prompt.encode('utf-8'))
                session_recorder.record_event(server.session_id, "o", "^C\r\n" + prompt)
                command_buffer = b""
            elif char == b'\x04': # Ctrl+D
                break
            elif char == b'\x7f' or char == b'\x08': # Backspace
                if len(command_buffer) > 0:
                    command_buffer = command_buffer[:-1]
                    channel.send(b'\x08 \x08')
                    session_recorder.record_event(server.session_id, "o", "\x08 \x08")
            else:
                command_buffer += char

    except socket.timeout:
        logger.info(f"[SSH] Connection timed out for {client_ip}")
    except Exception as e:
        logger.error(f"[SSH] Error handling client {client_ip}: {e}")
    finally:
        channel.close()
        transport.close()
        session_manager.end_session(server.session_id)
        session_recorder.finalize_recording(server.session_id, is_demo=False)
        logger.info(f"[SSH] Connection closed for {client_ip}")


def start_ssh_honeypot(host: str = None, port: int = None):
    """
    Start the SSH honeypot server.
    
    Args:
        host: The host IP to bind to. Defaults to config SSH_HOST.
        port: The port to bind to. Defaults to config SSH_PORT.
    """
    host = host or SSH_HOST
    port = port or SSH_PORT
    
    # Generate or load host key
    key_path = SSH_HOST_KEY_PATH
    if not os.path.exists(key_path):
        logger.info(f"[SSH] Generating new RSA host key at {key_path}")
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(key_path)
    else:
        logger.info(f"[SSH] Loading existing RSA host key from {key_path}")
        key = paramiko.RSAKey.from_private_key_file(key_path)
        
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(100)
        logger.info(f"[SSH] SSH Honeypot listening on {host}:{port}")
    except Exception as e:
        logger.error(f"[SSH] Failed to bind to {host}:{port} - {e}")
        return

    try:
        while True:
            client_socket, client_addr = server_socket.accept()
            logger.info(f"[SSH] Connection accepted from {client_addr[0]}:{client_addr[1]}")
            client_thread = threading.Thread(
                target=handle_connection,
                args=(client_socket, client_addr, key),
                daemon=True
            )
            client_thread.start()
    except KeyboardInterrupt:
        logger.info("[SSH] Stopping SSH honeypot...")
    except Exception as e:
        logger.error(f"[SSH] Server error: {e}")
    finally:
        server_socket.close()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    start_ssh_honeypot()
