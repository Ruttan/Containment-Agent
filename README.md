# Containment Agent

**Project location:** `D:\Claude AI\Projects\containment-agent`
**Repository:** Initialize with `git remote add origin <your-github-url>` then `git push -u origin main`

A platform-agnostic AI agent that receives security alerts, evaluates them with Claude AI, and sends human approval requests before isolating hosts. Supports CrowdStrike, Tanium, and any custom platform.

---

## How It Works

```
Alert → AI Evaluation → Email + Slack Notification → Analyst Approves → Host Isolated
```

1. Your security platform sends an alert to this agent via webhook.
2. Claude reads the alert (any format) and writes a plain-English summary with a severity rating.
3. You receive an email and Slack message with Approve / Deny buttons.
4. Click Approve → the agent calls your platform's API and isolates the host.
5. Everything is logged to `agent.log`.

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

- `platform` — set to `crowdstrike`, `tanium`, or `generic`
- `anthropic_api_key` — from https://console.anthropic.com
- Your platform credentials (only the section matching your platform)
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

Open a **second** terminal window and run:

```powershell
Invoke-WebRequest -Uri "http://localhost:5000/webhook/alert" -Method POST -ContentType "application/json" -Body '{"alert_type": "ransomware_detected", "host_id": "test-host-001", "hostname": "WORKSTATION-42", "severity": "critical", "threat": "LockBit 3.0"}'
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
│   ├── base.py           # Connector interface
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
3. Implement `isolate_host()` and `get_host_info()`
4. Add a case for it in `build_connector()` in `agent.py`
5. Add credentials to `config.yaml` under `platforms`

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/webhook/alert` | Send any alert JSON here |
| GET | `/approve/<token>` | Approves isolation (linked in email/Slack) |
| GET | `/deny/<token>` | Denies isolation (linked in email/Slack) |
| GET | `/status` | Lists all approval requests and their status |

