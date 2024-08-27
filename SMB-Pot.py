import socket
import threading
import requests
import subprocess
from datetime import datetime, timedelta
import time
import logging
from concurrent.futures import ThreadPoolExecutor

ABUSE_IPDB_API_KEY = 'cfed70b0f7de2d2f3a0ac56e41625cdf99fde3960bf8533ca553e870d05f990b342b3671824d3429'
SMB_PORT = 445

reported_ips = {}
reporting_interval = timedelta(minutes=15)

# Configure logging
logging.basicConfig(filename='smb_attempts.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def report_to_abuse_ipdb(ip):
    current_time = datetime.utcnow()
    if ip in reported_ips and (current_time - reported_ips[ip]) < reporting_interval:
        log_msg = f'Skipping report for IP {ip} as it was reported recently.'
        logging.info(log_msg)
        print(log_msg)
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

    try:
        response = requests.post(url, data=data, headers=headers, timeout=10)
        if response.status_code == 200:
            reported_ips[ip] = current_time
            log_msg = f'Reported IP {ip} to AbuseIPDB successfully.'
            logging.info(log_msg)
            print(log_msg)
        else:
            log_msg = f'Failed to report IP {ip} to AbuseIPDB: {response.status_code} {response.text}'
            logging.error(log_msg)
            print(log_msg)
    except requests.RequestException as e:
        log_msg = f'Error reporting IP {ip} to AbuseIPDB: {e}'
        logging.error(log_msg)
        print(log_msg)

def ban_ip(ip):
    ban_command = f'iptables -A INPUT -s {ip} -j DROP'
    unban_command = f'iptables -D INPUT -s {ip} -j DROP'

    try:
        subprocess.run(ban_command, shell=True, check=True)
        log_msg = f'Banned IP {ip} successfully.'
        logging.info(log_msg)
        print(log_msg)

        # Unban the IP after 30 minutes
        time.sleep(30 * 60)
        subprocess.run(unban_command, shell=True, check=True)
        log_msg = f'Unbanned IP {ip} successfully.'
        logging.info(log_msg)
        print(log_msg)
    except subprocess.CalledProcessError as e:
        log_msg = f'Failed to ban/unban IP {ip}: {e}'
        logging.error(log_msg)
        print(log_msg)

def handle_connection(client, addr):
    ip_address = addr[0]
    log_msg = f'Unauthorized connection attempt from {ip_address}'
    logging.info(log_msg)
    print(log_msg)
    credentials = None

    try:
        # Simulate reading credentials (username and password)
        client.settimeout(10)  # Add a timeout for the client connection
        credentials = client.recv(1024).decode('utf-8').strip()
        log_msg = f'IP: {ip_address}, Credentials: {credentials}'
        logging.info(log_msg)
        print(log_msg)
    except socket.timeout:
        log_msg = f'Timeout while reading credentials from {ip_address}'
        logging.warning(log_msg)
        print(log_msg)
    except Exception as e:
        log_msg = f'Failed to read credentials from {ip_address}: {e}'
        logging.error(log_msg)
        print(log_msg)
    finally:
        client.close()

    report_to_abuse_ipdb(ip_address)
    threading.Thread(target=ban_ip, args=(ip_address,)).start()

def start_server(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(100)
        log_msg = f'Starting SMB server on port {port}'
        logging.info(log_msg)
        print(log_msg)

        with ThreadPoolExecutor(max_workers=10) as executor:
            while True:
                client, addr = sock.accept()
                log_msg = f'Connection from {addr}'
                logging.info(log_msg)
                print(log_msg)
                executor.submit(handle_connection, client, addr)
    except OSError as e:
        if e.errno == 98:
            log_msg = f'Port {port} is already in use. Skipping...'
            logging.error(log_msg)
            print(log_msg)
        else:
            log_msg = f'Failed to start server on port {port}: {e}'
            logging.error(log_msg)
            print(log_msg)
    except Exception as e:
        log_msg = f'Unexpected error in server: {e}'
        logging.error(log_msg)
        print(log_msg)
    finally:
        if sock:
            sock.close()

if __name__ == "__main__":
    start_server(SMB_PORT)
