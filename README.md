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

- `secrets_provider` and `secrets_backends` — pick `azure_keyvault` or `keepass` and configure it. **This has to be done first** — every credential field below is a reference name, not a real value, and won't resolve until your vault/database actually has the matching entries. See "Secrets Management" further down for the full setup.
- `sources` — enable one entry per alert source you want active (e.g. `defender_endpoint`, `m365_defender`, `crowdstrike`, `tanium`). Each source name becomes its own webhook path.
- `anthropic_api_key` — store your real key (from https://console.anthropic.com) in your vault under the reference name shown in the config
- Your platform credentials under `platforms` (only the sections matching the sources you enabled)
- Slack webhook URL and email settings — same deal, real values live in the vault, config.yaml just has the reference names
- (Optional) `integrations.siem` — enable `splunk_hec` and/or `generic_webhook` to forward a full audit trail (alert, evaluation, outcome) to your SIEM

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
├── notifiers/
│   ├── email_notifier.py  # Email via SMTP
│   └── slack_notifier.py  # Slack via webhook
├── integrations/
│   └── siem_forwarder.py  # Optional: forwards alert + evaluation + outcome to Splunk HEC / a generic SIEM webhook
└── vault/
    ├── base.py             # SecretsProvider interface
    ├── factory.py          # Builds whichever backend is configured
    ├── resolver.py         # Resolves every credential field from a reference name to its real value
    ├── azure_keyvault.py   # Azure Key Vault backend
    └── keepass_provider.py # KeePass backend
```

## Secrets Management

`config.yaml` never holds a real credential. Every secret field is a *reference name* — the real value lives in either Azure Key Vault or a KeePass database, and the agent resolves it at startup. If you paste an actual API key into one of those fields instead of a reference name, the agent will fail to start with a clear error, since there's no code path that accepts a literal secret there.

### Option A — Azure Key Vault (recommended for team/production use)

1. Create a vault and add your secrets:
   ```bash
   az keyvault create --name your-vault-name --resource-group your-rg
   az keyvault secret set --vault-name your-vault-name --name anthropic-api-key --value sk-ant-...
   az keyvault secret set --vault-name your-vault-name --name crowdstrike-client-secret --value ...
   # repeat for every reference name shown in config.example.yaml
   ```
2. Grant your identity access — the **Key Vault Secrets User** role (get-only) is enough. If you're running this agent on Azure infrastructure (App Service, a VM, a container), assign it a **Managed Identity** and grant that identity access — no credential of any kind needs to exist anywhere in that case. For local development, `az login` works fine.
3. In `config.yaml`:
   ```yaml
   secrets_provider: "azure_keyvault"
   secrets_backends:
     azure_keyvault:
       vault_url: "https://your-vault-name.vault.azure.net/"
   ```

### Option B — KeePass

1. Open your `.kdbx` database and add one entry per credential. The entry's **Title** must exactly match the reference name shown in `config.example.yaml` (e.g. `anthropic-api-key`), and the real secret goes in that entry's **Password** field.
2. In `config.yaml`:
   ```yaml
   secrets_provider: "keepass"
   secrets_backends:
     keepass:
       database_path: "C:/path/to/your/vault.kdbx"
       keyfile_path: null   # only if your database uses one
   ```
3. The one credential that can't be eliminated is the database's own master password (inherent to KeePass, not something this integration can design around). The agent will prompt for it interactively at startup — nothing is logged or written to disk. If you need the agent to start unattended (e.g. as a background service), set the `KEEPASS_MASTER_PASSWORD` environment variable instead of typing it each time.

Neither backend has been live-tested end to end yet in this project — verify both the Key Vault and KeePass paths work in your environment before relying on them.

## Forwarding to Splunk or Another SIEM

Enable it in `config.yaml` under `integrations.siem` — see `config.example.yaml` for the full block. Two independent destinations:

- **`splunk_hec`** — native Splunk HTTP Event Collector support. Create a HEC token in Splunk under *Settings > Data Inputs > HTTP Event Collector*, then set `url` and `token`.
- **`generic_webhook`** — a plain JSON POST to any URL, for QRadar, Sentinel, LogRhythm, Elastic, or a syslog-forwarder shim. Add an `Authorization` header under `headers` if the destination needs one.

Every alert this agent evaluates gets forwarded — including ones below the notification threshold (`event_type: "alert_evaluated"`) — plus the full lifecycle once a notification does go out (`approval_requested` → `action_result` / `denied` / `expired`). Each event includes the raw alert, Claude's full evaluation (severity, explanation, suggested fix, available actions), and the outcome. A SIEM being unreachable never blocks the actual containment workflow — forwarding failures are logged and swallowed.

This hasn't been live-tested against a real Splunk HEC endpoint yet — verify the HEC URL/token work in your environment before relying on it.

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
