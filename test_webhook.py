"""
Quick webhook test — sends a sample alert to a running agent instance and
prints back the evaluation, the approval token, and the exact approve/deny
URLs so you can test the full flow by hand.

This does NOT click Approve/Deny for you — containment actions are real API
calls to your platform, so you decide when (and whether) to trigger one.

Usage:
  python test_webhook.py                        # sends the default sample (crowdstrike, ransomware)
  python test_webhook.py defender_endpoint       # sends the Defender sample to that source
  python test_webhook.py tanium                  # sends the Tanium sample
  python test_webhook.py generic                 # sends a generic/custom sample
  python test_webhook.py crowdstrike --status    # also prints /status afterward

Requires the agent to already be running (`python agent.py`) in another
terminal. Reads `server.public_url` from config.yaml if present, otherwise
defaults to http://localhost:5000.
"""

import sys
import json
import requests

try:
    import yaml
    with open("config.yaml") as f:
        _config = yaml.safe_load(f) or {}
    BASE_URL = _config.get("server", {}).get("public_url", "http://localhost:5000")
except FileNotFoundError:
    BASE_URL = "http://localhost:5000"


# ------------------------------------------------------------------
# Sample alerts — one per source, each with fields that should make
# the evaluator offer a different mix of response actions.
# ------------------------------------------------------------------

SAMPLE_ALERTS = {
    "defender_endpoint": {
        "id": "da637000000000000_-1234567890",
        "alertCreationTime": "2026-07-08T14:32:00Z",
        "severity": "high",
        "title": "Suspicious process injection detected",
        "category": "DefenseEvasion",
        "detectionSource": "WindowsDefenderAtp",
        "threatFamilyName": "Cobalt Strike",
        "machineId": "defender-machine-9f21ab",
        "computerDnsName": "FIN-LAPTOP-07",
        "evidence": [
            {
                "entityType": "Process",
                "processId": "6820",
                "fileName": "rundll32.exe",
                "parentProcessFileName": "winword.exe",
            },
            {
                "entityType": "File",
                "fileName": "payload.dll",
                "sha256": "3b241101707d0e3bda9e2ac2c6de40a3f8f1b8a2c9f0a3b1c0d2e4f5a6b7c8d",
            },
        ],
        "mitreTechniques": ["T1055"],
    },
    "m365_defender": {
        "id": "m365-alert-778899",
        "severity": "critical",
        "title": "Impossible travel + suspicious inbox rule",
        "category": "InitialAccess",
        "detectionSource": "OfficeATP",
        "machineId": "defender-machine-9f21ab",
        "computerDnsName": "FIN-LAPTOP-07",
        "evidence": [
            {"entityType": "User", "userPrincipalName": "afinance@example.com"},
        ],
        "mitreTechniques": ["T1078", "T1114"],
    },
    "crowdstrike": {
        "alert_type": "ransomware_detected",
        "host_id": "test-host-001",
        "hostname": "WORKSTATION-42",
        "severity": "critical",
        "threat": "LockBit 3.0",
        "process_id": "4821",
        "file_hash": "44d88612fea8a8f36de82e1278abb02f",
        "timestamp": "2026-07-08T14:00:00Z",
    },
    "tanium": {
        "alert_type": "suspicious_powershell",
        "host_id": "test-endpoint-002",
        "hostname": "DEV-BOX-13",
        "severity": "high",
        "threat": "Encoded PowerShell command execution",
        "process_id": "9931",
        "timestamp": "2026-07-08T14:05:00Z",
    },
    "generic": {
        "alert_type": "unusual_outbound_traffic",
        "host_id": "custom-host-003",
        "hostname": "SRV-APP-05",
        "severity": "medium",
        "threat": "Beaconing to known C2 domain",
        "timestamp": "2026-07-08T14:10:00Z",
    },
}


def send_alert(source: str):
    if source not in SAMPLE_ALERTS:
        print(f"No sample alert for source '{source}'. Available: {list(SAMPLE_ALERTS)}")
        return None

    url = f"{BASE_URL}/webhook/alert/{source}"
    payload = SAMPLE_ALERTS[source]
    print(f"POST {url}")
    print(json.dumps(payload, indent=2))
    print("-" * 60)

    try:
        resp = requests.post(url, json=payload, timeout=30)
    except requests.ConnectionError:
        print(f"Could not connect to {BASE_URL} — is `python agent.py` running?")
        return None

    print(f"Status: {resp.status_code}")
    try:
        data = resp.json()
    except ValueError:
        print(resp.text)
        return None

    print(json.dumps(data, indent=2))

    token = data.get("token")
    if token:
        print("-" * 60)
        print("Approval links (do NOT click unless you want to trigger a real action):")
        for action in data.get("available_actions", []):
            print(f"  {action:<16} {BASE_URL}/approve/{token}/{action}")
        print(f"  {'deny':<16} {BASE_URL}/deny/{token}")
    return data


def print_status():
    url = f"{BASE_URL}/status"
    resp = requests.get(url, timeout=10)
    print("-" * 60)
    print(f"GET {url}")
    print(json.dumps(resp.json(), indent=2))


if __name__ == "__main__":
    args = sys.argv[1:]
    show_status = "--status" in args
    args = [a for a in args if a != "--status"]
    source = args[0] if args else "crowdstrike"

    send_alert(source)

    if show_status:
        print_status()
