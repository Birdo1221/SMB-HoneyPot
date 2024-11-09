# SMB Honeypot

The script is designed to capture login / connection attempts for the SMB port 445 , this tries to exact the credentaisl used + reports the IP addresses to AbuseIPDB. 

I am currently using this myself, [ AbuseipDB Results ](https://www.abuseipdb.com/user/137416) .

## Getting Started
### Prerequisites
- Python 3.x
- Paramiko library
- Requests library
- Curl
- iptables  ==> Linux Only, Will need to find a Windows Alternative


  ### Example of the log file in action 
![image](https://github.com/user-attachments/assets/f0cc7367-d557-4ff5-92ab-f63a73ec1f5f)



### Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/Birdo1221/SMB-HoneyPot.git
    cd SMB-honeypot
    ```

2. Install the required Python packages:
    ```sh
    pip install paramiko requests
    ```

3. Replace the placeholder in the script with your Abuse-IPDB API key:
    ```python
    ABUSE_IPDB_API_KEY = 'Replace with Abuse-IPDB API Token'
    ```
## Usage

### 1. Just need to run the file
** Latest Version 

**Run:** `Python3 smbV2.py`

### 2. Running the logging varients will create the log file
**File:** `smb_attempts.log`

   You can change the name of the log file to whatever.
