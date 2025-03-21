import socket
import threading
import requests
import subprocess
from datetime import datetime, timedelta
import time
import logging

ABUSE_IPDB_API_KEY = 'Random API strings, Example 0fd14aa5aeb7e102968a8348fd601d861b858d80a1c38bc907042df7c9e24befc076823cebf9a6a0'       
SMB_PORT = 445

reported_ips = {}
reporting_interval = timedelta(minutes=15)

# Configure logging
logging.basicConfig(level=logging.INFO)

def report_to_abuse_ipdb(ip):
    current_time = datetime.utcnow()
    if ip in reported_ips and (current_time - reported_ips[ip]) < reporting_interval:
        print(f'Skipping report for IP {ip} as it was reported recently.')
        return
    
    url = "https://api.abuseipdb.com/api/v2/report"
    data = {
        "ip": ip,
        "categories": "18,14,15",
        "comment": "[Birdo Server] SMB Unauthorized Attempt"
    }
    headers = {
        "Key": ABUSE_IPDB_API_KEY,
        "Accept": "application/json"
    }
    
    response = requests.post(url, data=data, headers=headers)
    
    if response.status_code == 200:
        reported_ips[ip] = current_time
        print(f'Reported IP {ip} to AbuseIPDB successfully.')
    else:
        print(f'Failed to report IP {ip} to AbuseIPDB: {response.status_code} {response.text}')

def ban_ip(ip):
    try:
        # Check if iptables is available before trying to run the command
        subprocess.run('which iptables', shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ban_command = f'iptables -A INPUT -s {ip} -j DROP'
        unban_command = f'iptables -D INPUT -s {ip} -j DROP'

        subprocess.run(ban_command, shell=True, check=True)
        print(f'Banned IP {ip} successfully.')

        # Unban the IP after 30 minutes
        time.sleep(30 * 60)
        subprocess.run(unban_command, shell=True, check=True)
        print(f'Unbanned IP {ip} successfully.')
    except subprocess.CalledProcessError as e:
        print(f'Failed to ban/unban IP {ip}: {e}')
    except FileNotFoundError:
        print('iptables command not found, skipping ban.')

def handle_connection(client, addr):
    ip_address = addr[0]
    print(f'Unauthorized connection attempt from {ip_address}')
    credentials = None

    try:
        # Simulate reading credentials (username and password)
        credentials = client.recv(1024).decode('utf-8', 'ignore').strip()
        logging.info(f'IP: {ip_address}, Credentials: {credentials}')
    except Exception as e:
        logging.error(f'Failed to read credentials from {ip_address}: {e}')

    report_to_abuse_ipdb(ip_address)
    threading.Thread(target=ban_ip, args=(ip_address,)).start()
    client.close()

def start_server(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(100)
        print(f'Starting SMB server on port {port}')

        while True:
            client, addr = sock.accept()
            print(f'Connection from {addr}')
            threading.Thread(target=handle_connection, args=(client, addr)).start()
    except OSError as e:
        if e.errno == 98:
            print(f'Port {port} is already in use. Skipping...')
        else:
            print(f'Failed to start server on port {port}: {e}')

if __name__ == "__main__":
    start_server(SMB_PORT)
