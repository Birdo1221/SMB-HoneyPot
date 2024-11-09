import socket
import threading
import requests
import subprocess
import ipaddress
from datetime import datetime, timedelta
import time
import logging
import json
from dataclasses import dataclass, asdict
from typing import Dict, Optional, Set
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import signal
import sys
import base64

@dataclass
class AttackAttempt:
    ip_address: str
    timestamp: datetime
    credentials: Optional[str]
    port: int
    
    def get_safe_credentials(self) -> str:
        """Return credentials in a safe format for reporting"""
        if not self.credentials:
            return "No credentials captured"
        
        try:
            return f"Attempted credentials (Base64): {base64.b64encode(self.credentials.encode()).decode()}"
        except Exception:
            return "Invalid credential format"

class IPBanManager:
    def __init__(self, ban_duration_minutes: int = 30):
        self.ban_duration = timedelta(minutes=ban_duration_minutes)
        self.banned_ips: Dict[str, datetime] = {}
        self.ip_lock = threading.Lock()
        
    def should_ban(self, ip: str) -> bool:
        """Check if IP should be banned based on cooldown period"""
        with self.ip_lock:
            if ip not in self.banned_ips:
                return True
                
            last_ban_time = self.banned_ips[ip]
            current_time = datetime.utcnow()
            
            if current_time - last_ban_time >= self.ban_duration:
                return True
                
            return False
    
    def register_ban(self, ip: str) -> None:
        """Register an IP ban with current timestamp"""
        with self.ip_lock:
            self.banned_ips[ip] = datetime.utcnow()
    
    def remove_ban(self, ip: str) -> None:
        """Remove IP from banned list"""
        with self.ip_lock:
            self.banned_ips.pop(ip, None)
    
    def get_active_bans(self) -> Set[str]:
        """Get list of currently banned IPs"""
        current_time = datetime.utcnow()
        with self.ip_lock:
            return {
                ip for ip, ban_time in self.banned_ips.items()
                if current_time - ban_time < self.ban_duration
            }

class SMBHoneypot:
    def __init__(self, config_path: str = 'config.json'):
        self.load_config(config_path)
        self.setup_logging()
        self.reported_ips: Dict[str, datetime] = {}
        self.ban_manager = IPBanManager(self.config["ban_duration_minutes"])
        self.running = True
        self._setup_signal_handlers()
    
    def load_config(self, config_path: str) -> None:
        try:
            with open(config_path) as f:
                config = json.load(f)
        except FileNotFoundError:
            config = {
                "abuse_ipdb_api_key": "AbuseIPDB_KEY",
                "smb_port": 445,
                "log_file": "smb_honeypot.log",
                "reporting_interval_minutes": 15,
                "ban_duration_minutes": 30,
                "max_workers": 10,
                "connection_timeout": 3,
                "whitelist": ["127.0.0.1"]
            }
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=4)
                
        self.config = config
        self.validate_config()
    
    def validate_config(self) -> None:
        required_fields = [
            "abuse_ipdb_api_key",
            "smb_port",
            "log_file",
            "reporting_interval_minutes",
            "ban_duration_minutes",
            "max_workers",
            "connection_timeout",
            "whitelist"
        ]
        
        missing_fields = [field for field in required_fields if field not in self.config]
        if missing_fields:
            raise ValueError(f"Missing required config fields: {', '.join(missing_fields)}")
            
        try:
            self.whitelist = [ipaddress.ip_address(ip) for ip in self.config["whitelist"]]
        except ValueError as e:
            raise ValueError(f"Invalid IP in whitelist: {e}")
    
    def setup_logging(self) -> None:
        logging.basicConfig(
            filename=self.config["log_file"],
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        logging.getLogger().addHandler(console_handler)
    
    def _setup_signal_handlers(self) -> None:
        def signal_handler(signum, frame):
            logging.info("Shutdown signal received. Cleaning up...")
            self.running = False
            self.cleanup()
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def is_ip_whitelisted(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj == whitelisted for whitelisted in self.whitelist)
        except ValueError:
            return False
    
    def report_to_abuse_ipdb(self, attempt: AttackAttempt) -> None:
        if not self.config["abuse_ipdb_api_key"]:
            logging.warning("AbuseIPDB API key not configured. Skipping report.")
            return
            
        current_time = datetime.utcnow()
        if (attempt.ip_address in self.reported_ips and 
            (current_time - self.reported_ips[attempt.ip_address]) < 
            timedelta(minutes=self.config["reporting_interval_minutes"])):
            logging.info(f'Skipping report for IP {attempt.ip_address} (recently reported)')
            return
        
        timestamp_str = attempt.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')
        comment = (
            f"[SMB Honeypot Report]\n"
            f"Timestamp: {timestamp_str}\n"
            f"Port: {attempt.port}\n"
            f"{attempt.get_safe_credentials()}\n"
            f"Attack Type: Unauthorized SMB connection attempt"
        )
        
        url = "https://api.abuseipdb.com/api/v2/report"
        data = {
            "ip": attempt.ip_address,
            "categories": "18,14,15",  # Port scan, Brute-Force, SMB
            "comment": comment
        }
        headers = {
            "Key": self.config["abuse_ipdb_api_key"],
            "Accept": "application/json"
        }

        try:
            response = requests.post(url, data=data, headers=headers, timeout=10)
            response.raise_for_status()
            self.reported_ips[attempt.ip_address] = current_time
            logging.info(f'Reported IP {attempt.ip_address} to AbuseIPDB successfully')
            logging.debug(f'Report details: {comment}')
        except requests.exceptions.RequestException as e:
            logging.error(f'Error reporting IP {attempt.ip_address} to AbuseIPDB: {e}')
    
    def execute_iptables_command(self, command: str, ip: str) -> bool:
        """Execute iptables command and return success status"""
        try:
            subprocess.run(
                command,
                shell=True,
                check=True,
                capture_output=True,
                text=True
            )
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f'iptables command failed for IP {ip}: {e.stderr}')
            return False
    
    def ban_ip(self, ip: str) -> None:
        """Ban an IP address if it's not already banned or in cooldown"""
        if not self.ban_manager.should_ban(ip):
            logging.info(f'Skipping ban for IP {ip} (in cooldown period)')
            return
            
        ban_command = f'iptables -A INPUT -s {ip} -j DROP'
        
        if self.execute_iptables_command(ban_command, ip):
            self.ban_manager.register_ban(ip)
            logging.info(f'Banned IP {ip}')
            
            # Schedule unban
            threading.Timer(
                self.config["ban_duration_minutes"] * 60,
                self.unban_ip,
                args=[ip]
            ).start()
    
    def unban_ip(self, ip: str) -> None:
        """Remove IP ban if it exists"""
        unban_command = f'iptables -D INPUT -s {ip} -j DROP'
        
        if self.execute_iptables_command(unban_command, ip):
            self.ban_manager.remove_ban(ip)
            logging.info(f'Unbanned IP {ip}')
    
    def parse_smb_credentials(self, raw_data: bytes) -> Optional[str]:
        """Parse and extract potential credentials from SMB connection data"""
        try:
            data_str = raw_data.decode('utf-8', errors='ignore').strip()
            
            if '\x00' in data_str:
                parts = data_str.split('\x00')
                return "|".join(part for part in parts if part)
            return data_str if data_str else None
        except Exception as e:
            logging.error(f'Error parsing credentials: {e}')
            return None
    
    def handle_connection(self, client: socket.socket, addr: tuple) -> None:
        ip_address = addr[0]
        
        if self.is_ip_whitelisted(ip_address):
            logging.info(f'Whitelisted IP {ip_address} - allowing connection')
            client.close()
            return
            
        attempt = AttackAttempt(
            ip_address=ip_address,
            timestamp=datetime.utcnow(),
            credentials=None,
            port=addr[1]
        )
        
        try:
            client.settimeout(self.config["connection_timeout"])
            raw_data = client.recv(1024)
            attempt.credentials = self.parse_smb_credentials(raw_data)
            logging.info(f'Connection attempt from {ip_address} - Captured data: {attempt.get_safe_credentials()}')
        except socket.timeout:
            logging.warning(f'Timeout reading from {ip_address}')
        except Exception as e:
            logging.error(f'Error handling connection from {ip_address}: {e}')
        finally:
            client.close()
        
        # Report and ban in separate threads
        threading.Thread(target=self.report_to_abuse_ipdb, args=(attempt,)).start()
        threading.Thread(target=lambda: self.ban_ip(ip_address)).start()
    
    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(('0.0.0.0', self.config["smb_port"]))
            sock.listen(100)
            logging.info(f'SMB honeypot listening on port {self.config["smb_port"]}')
            
            with ThreadPoolExecutor(max_workers=self.config["max_workers"]) as executor:
                while self.running:
                    try:
                        client, addr = sock.accept()
                        executor.submit(self.handle_connection, client, addr)
                    except socket.error as e:
                        if not self.running:
                            break
                        logging.error(f'Socket error: {e}')
                        continue
        except OSError as e:
            logging.error(f'Failed to start server: {e}')
            raise
        finally:
            self.cleanup()
            sock.close()
    
    def cleanup(self) -> None:
        """Clean up any remaining banned IPs"""
        active_bans = self.ban_manager.get_active_bans()
        for ip in active_bans:
            self.unban_ip(ip)

if __name__ == "__main__":
    honeypot = SMBHoneypot()
    honeypot.start()
