# SMB Honeypot

This script captures login and connection attempts to SMB port 445 and optionally reports the IP addresses to AbuseIPDB. It also logs these attempts in a separate `/logs/` directory, e.g., `smb_attempts_20250116.log`.

## Features
- **IP Reporting**: Optional integration with [AbuseIPDB](https://www.abuseipdb.com/) for reporting malicious IP addresses.
- **Logging**: Detailed logs of all login/connection attempts.
- **Open-source Example**: See my AbuseIPDB reports [here](https://www.abuseipdb.com/user/137416).

---

## Getting Started

### Prerequisites
- **Python 3.x**
- **Linux or WSL**: Requires `iptables` (not recommended on WSL due to compatibility issues). A Windows alternative must be used for Windows endpoints.

### AbuseIPDB Integration
You can make public reports via AbuseIPDB, but note that anonymous submissions cannot be tracked or deleted and may be perceived as less legitimate.

![AbuseIPDB Example](https://github.com/user-attachments/assets/f0cc7367-d557-4ff5-92ab-f63a73ec1f5f)

---

## Installation

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/Birdo1221/SMB-HoneyPot.git
    cd SMB-HoneyPot
    ```

2. **Install Required Packages**:
    ```bash
    pip install requests ipaddress
    ```

3. **Configure AbuseIPDB**:
    Replace the placeholder in the script with your AbuseIPDB API key:
    ```python
    ABUSE_IPDB_API_KEY = 'Replace with your AbuseIPDB API Token'
    ```
    If you having issue killing the processing or by using CTRL + Z or C, i would recommend using these commands instead,
       
    # Check what's using port 445
   ```sudo netstat -tulpn | grep 445```
    
    # Kill the process using port 445 (replace PID with the number you see from above command)
    ```sudo kill PID```
    
    # Or more aggressively if needed:
    ```sudo kill -9 PID```
   
---

## Usage

1. **Run the Script**:
    ```bash
    screen python3 main.py
    ```

2. **Enable Logging**:
    The script will create log files like `smb_attempts_20250116.log` in the `/logs/` directory.

3. **Edit Configurations**:
    Customize the script as needed, including your AbuseIPDB API key. To get an API key, visit the API tab [AbuseIPDB API](https://www.abuseipdb.com/) after logging in.

---

## Latest Version
