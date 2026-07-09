# Containment Agent

**Project location:** `D:\Claude AI\Projects\containment-agent`
**Repository:** Initialize with `git remote add origin <your-github-url>` then `git push -u origin main`

A platform-agnostic AI agent that receives security alerts — from multiple sources at once — evaluates them with Claude AI, and sends human approval requests before taking a containment action. Supports Microsoft Defender (Endpoint + unified M365 Defender via Microsoft Graph), CrowdStrike, Tanium, and any custom platform.

---

## How It Works

```
Alert (any configured source) → AI Evaluation → Email + Slack Notification → Analyst Approves an Action → Action Executed
```

1. A security platform sends an alert to this agent via its own webhook path (`/webhook/alert/<source>`) — you can have several sources active simultaneously.
2. Claude reads the alert (any format) and produces: a severity rating, a plain-English summary, a **detailed explanation of why it fired** (MITRE ATT&CK technique, process tree, indicators — whatever's in the alert), and a **suggested fix**.
3. Claude also decides which response actions actually make sense given what's in the alert — isolate host, kill process, quarantine file, and/or block hash — and only offers the ones the alert data supports.
4. You receive an email and Slack message with one button per available action, plus a Deny button.
5. Click an action → the agent calls the source's platform API and executes it.
6. Everything is logged to `agent.log`.

---

## Setup

### 1. Navigate to the project folder

```bash
cd "D:\Claude AI\Projects\containment-agent"
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure the agent

Copy the example config and fill in your values:

```bash
copy config.example.yaml config.yaml
```

Open `config.yaml` and fill in:

- `sources` — enable one entry per alert source you want active (e.g. `defender_endpoint`, `m365_defender`, `crowdstrike`, `tanium`). Each source name becomes its own webhook path.
- `anthropic_api_key` — from https://console.anthropic.com
- Your platform credentials under `platforms` (only the sections matching the sources you enabled — e.g. `platforms.defender` needs an Azure AD app registration's `tenant_id`/`client_id`/`client_secret`)
- Slack webhook URL — from https://api.slack.com/messaging/webhooks
- Email settings — use a Gmail App Password if using Gmail

### 4. Run the agent

```bash
python agent.py
```

The agent starts a web server on port 5000 (configurable in config.yaml).

### 5. Expose the agent (for real alerts)

For approval links to work outside localhost, the server needs a public URL.
The easiest way during testing: use [ngrok](https://ngrok.com).

```bash
ngrok http 5000
```

Copy the `https://...ngrok.io` URL into `config.yaml` under `server.public_url`.

---

## Testing Locally

### Step 1 — Verify email credentials

Before running the agent, confirm your Gmail App Password is working:

```powershell
python test_email.py
```

You should see `LOGIN OK — credentials are working!`. If not, check that your app password in `config.yaml` was created while signed into the correct Google account.

### Step 2 — Start the agent

In a terminal:

```powershell
cd "D:\Claude AI\Projects\containment-agent"
python agent.py
```

You should see `Containment Agent starting on 0.0.0.0:5000`.

### Step 3 — Send a test alert

Easiest way — use the included test script, which has ready-made sample alerts for each source:

```powershell
python test_webhook.py crowdstrike
python test_webhook.py defender_endpoint
python test_webhook.py tanium
python test_webhook.py generic
python test_webhook.py crowdstrike --status   # also print /status afterward
```

It prints the evaluation Claude returned and the exact approve/deny links — it does not click them for you, since approving triggers a real API call against your platform.

Or, to send a raw alert by hand (replace `crowdstrike` with whichever source you configured):

```powershell
Invoke-WebRequest -Uri "http://localhost:5000/webhook/alert/crowdstrike" -Method POST -ContentType "application/json" -Body '{"alert_type": "ransomware_detected", "host_id": "test-host-001", "hostname": "WORKSTATION-42", "severity": "critical", "threat": "LockBit 3.0", "process_id": "4821", "file_hash": "44d88612fea8a8f36de82e1278abb02f"}'
```

> Note: On Windows, use `Invoke-WebRequest` — PowerShell's built-in `curl` alias does not support the same syntax.

### Step 4 — Check your inbox

You should receive an approval email within seconds. Click **Deny** on the test alert since no real platform is connected.

### Step 5 — Check approval status (optional)

Open a browser and go to:

```
http://localhost:5000/status
```

This shows all pending, approved, denied, and expired approval requests.

---

## File Structure

```
containment-agent/
├── agent.py              # Main server — run this
├── config.yaml           # All your settings go here
├── evaluator.py          # AI alert analysis (Claude)
├── requirements.txt      # Python packages
├── connectors/
│   ├── base.py           # Connector interface (isolate_host, kill_process,
│   │                     #   quarantine_file, block_hash, get_host_info)
│   ├── defender.py       # Microsoft Defender adapter (Graph Security API)
│   ├── crowdstrike.py    # CrowdStrike adapter
│   ├── tanium.py         # Tanium adapter
│   └── generic.py        # Custom platform adapter
└── notifiers/
    ├── email_notifier.py  # Email via SMTP
    └── slack_notifier.py  # Slack via webhook
```

## Adding a New Platform

1. Create `connectors/yourplatform.py`
2. Inherit from `BaseConnector`
3. Implement `isolate_host()` and `get_host_info()` — and optionally `kill_process()`, `quarantine_file()`, `block_hash()` if the platform API supports them
4. Register it in `CONNECTOR_CLASSES` in `agent.py`
5. Add a `sources.<name>` entry and credentials under `platforms.<name>` in `config.yaml`

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/webhook/alert/<source>` | Send alert JSON for a specific configured source (e.g. `/webhook/alert/defender_endpoint`) |
| POST | `/webhook/alert` | Legacy path — routes to the first configured source |
| GET | `/approve/<token>/<action>` | Executes the chosen action: `isolate`, `kill_process`, `quarantine_file`, or `block_hash` (linked in email/Slack) |
| GET | `/deny/<token>` | Denies the request — no action taken (linked in email/Slack) |
| GET | `/status` | Lists all approval requests, their available/taken actions, and status |

