# context.md — Containment Agent

> This file is the authoritative AI-readable context for this project.
> Any AI engine, coding assistant, or agent working in this repository should read this file first.

---

## Project Location

- **Local path:** `D:\Claude AI\Projects\containment-agent`
- **Git branch:** `main`
- **To publish:** `git remote add origin <your-github-url>` then `git push -u origin main`

---

## Project Identity

- **Name**: Containment Agent
- **Type**: Security automation agent
- **Language**: Python 3.10+
- **Purpose**: Receives security alerts from any platform, evaluates them with an AI model, and executes host isolation after human approval via email and Slack.
- **Design principle**: Platform-agnostic. Adding a new platform requires only a new connector file — no changes to the core agent.

---

## Problem This Solves

Security platforms (CrowdStrike, Tanium, SIEMs) generate alerts that require fast but deliberate containment decisions. Fully automated isolation risks false positives taking down production hosts. Manual workflows are too slow. This agent sits in the middle: AI evaluates the alert instantly, humans approve with one click, the agent executes.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Containment Agent                      │
│                                                          │
│  Webhook ──► Evaluator (Claude AI) ──► Notifier         │
│                                           │              │
│                              Email + Slack notification  │
│                                           │              │
│                              Analyst clicks Approve      │
│                                           │              │
│                              Connector ──► Platform API  │
│                          (CrowdStrike / Tanium / Generic)│
└──────────────────────────────────────────────────────────┘
```

### Data Flow (step by step)

1. A security platform POSTs a JSON alert to `POST /webhook/alert`
2. `evaluator.py` sends the alert to Claude (claude-haiku-4-5) for triage
3. Claude returns structured JSON: severity, recommendation, host_id, summary
4. If severity meets the threshold, the agent fetches host details via the active connector
5. A unique approval token is created and stored in memory
6. `SlackNotifier` and `EmailNotifier` send the AI summary + Approve/Deny links
7. Analyst clicks Approve → `GET /approve/<token>` → connector calls platform isolation API
8. Analyst clicks Deny → `GET /deny/<token>` → no action, confirmation sent
9. Pending tokens expire automatically after `approval_timeout_minutes`

---

## File Map

Every file in this project and what it does:

```
containment-agent/
│
├── agent.py                  # Entry point. Flask server. Owns the approval store,
│                             # all HTTP routes, and the expiry background thread.
│                             # Import order: evaluator → notifiers → connectors.
│
├── evaluator.py              # AI triage layer. Calls Anthropic API with alert data.
│                             # Returns structured evaluation dict. Stateless.
│
├── config.yaml               # Runtime config (NOT committed — contains secrets).
│                             # See config.example.yaml for the committed template.
│
├── config.example.yaml       # Committed placeholder config. All values are dummy strings.
│                             # Users copy this to config.yaml and fill in real values.
│
├── requirements.txt          # Python dependencies: flask, requests, anthropic, pyyaml
│
├── context.md                # This file. AI-readable project context.
│
├── README.md                 # Human-readable setup guide and API reference.
│
├── LICENSE                   # MIT License.
│
├── connectors/
│   ├── __init__.py
│   ├── base.py               # Abstract base class. Defines the connector interface.
│   │                         # Two required methods: isolate_host(), get_host_info()
│   ├── crowdstrike.py        # CrowdStrike Falcon adapter. OAuth2 + Network Containment API.
│   ├── tanium.py             # Tanium Threat Response adapter. API token auth.
│   └── generic.py            # Fallback adapter. POSTs to any configurable endpoint.
│
└── notifiers/
    ├── __init__.py
    ├── slack_notifier.py     # Slack Incoming Webhook. Sends Block Kit approval card.
    └── email_notifier.py     # SMTP email. Sends HTML approval email with buttons.
```

---

## Key Interfaces

### Connector Interface (`connectors/base.py`)

Any new platform connector must implement:

```python
def isolate_host(self, host_id: str) -> dict:
    # Must return: {"success": bool, "message": str, "raw_response": dict}

def get_host_info(self, host_id: str) -> dict:
    # Must return: {"hostname": str, "ip_address": str, "os": str, "last_seen": str}
```

### Alert Input Schema (`POST /webhook/alert`)

The agent accepts **any** JSON alert body. The AI evaluator reads the raw JSON and extracts what it needs. There is no required schema. However, alerts that include these fields will produce better AI evaluations:

```json
{
  "host_id": "string — device ID or hostname",
  "hostname": "string",
  "severity": "string",
  "threat": "string — threat name or rule name",
  "alert_type": "string",
  "timestamp": "ISO 8601 string"
}
```

### Evaluation Output Schema (internal)

The `AlertEvaluator.evaluate()` method returns:

```json
{
  "severity": "low | medium | high | critical",
  "recommendation": "isolate | monitor | ignore",
  "summary": "2-3 sentence plain-English assessment",
  "host_id": "extracted host identifier",
  "threat_name": "name of the threat or rule",
  "confidence": "low | medium | high",
  "original_alert": { "...": "original alert dict" }
}
```

### Approval Store Schema (in-memory)

```python
pending_approvals: dict[str, dict] = {
    "<uuid-token>": {
        "evaluation": { ... },   # Output of AlertEvaluator.evaluate()
        "host_info": { ... },    # Output of connector.get_host_info()
        "created_at": datetime,  # UTC
        "status": "pending | approved | denied | expired"
    }
}
```

---

## Configuration Reference (`config.yaml`)

| Key | Type | Description |
|-----|------|-------------|
| `platform` | string | Active connector: `crowdstrike`, `tanium`, or `generic` |
| `anthropic_api_key` | string | Anthropic API key for alert evaluation |
| `platforms.crowdstrike.client_id` | string | CrowdStrike OAuth2 client ID |
| `platforms.crowdstrike.client_secret` | string | CrowdStrike OAuth2 client secret |
| `platforms.crowdstrike.base_url` | string | CrowdStrike API base URL |
| `platforms.tanium.api_token` | string | Tanium API session token |
| `platforms.tanium.base_url` | string | Tanium server base URL |
| `platforms.generic.isolation_endpoint` | string | URL to POST isolation requests to |
| `notifications.slack.webhook_url` | string | Slack Incoming Webhook URL |
| `notifications.email.smtp_host` | string | SMTP server hostname |
| `notifications.email.smtp_port` | int | SMTP port (typically 587) |
| `notifications.email.username` | string | SMTP login username |
| `notifications.email.password` | string | SMTP password or app password |
| `notifications.email.to_addresses` | list | List of recipient email addresses |
| `server.host` | string | Bind address (default `0.0.0.0`) |
| `server.port` | int | Port (default `5000`) |
| `server.public_url` | string | Public URL used in approve/deny links |
| `agent.min_severity_to_notify` | string | Minimum severity to trigger notification |
| `agent.approval_timeout_minutes` | int | Minutes before pending approval expires |
| `agent.log_to_file` | bool | Whether to write logs to a file |
| `agent.log_file` | string | Log file path |

---

## HTTP API Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/webhook/alert` | None | Receive an alert. Returns evaluation + token. |
| `GET` | `/approve/<token>` | None (token is secret) | Approve isolation. Executes containment. |
| `GET` | `/deny/<token>` | None (token is secret) | Deny isolation. No action taken. |
| `GET` | `/status` | None | List all approval requests and statuses. |

---

## AI Engine Instructions

If you are an AI engine working in this codebase:

**Do:**
- Read `config.example.yaml` to understand configuration shape. Never read or write `config.yaml` (it contains real credentials).
- To add a new platform: create `connectors/<platform>.py`, inherit `BaseConnector`, implement both required methods, add a case to `build_connector()` in `agent.py`, and add a config block to `config.example.yaml`.
- To add a new notifier: create `notifiers/<name>_notifier.py` with `send_approval_request()` and `send_result()` methods. Wire it into `agent.py` alongside the existing notifiers.
- Use the `evaluator.py` prompt template as the single source of truth for what the AI is asked to do. If requirements change, modify the prompt there.
- The approval store (`pending_approvals`) is in-memory. For production, replace with Redis or a database — the store interface is intentionally simple.

**Don't:**
- Don't modify `agent.py` routes to add platform-specific logic. Platform differences belong in connectors.
- Don't commit `config.yaml`, `agent.log`, or `__pycache__` — they are in `.gitignore`.
- Don't add authentication to the webhook endpoint without updating this context file.

---

## Extension Roadmap (not yet implemented)

- [ ] Persistent approval store (Redis / SQLite)
- [ ] Webhook signature verification (HMAC) per platform
- [ ] Multi-host alert handling (batch isolation)
- [ ] Microsoft Teams notifier
- [ ] PagerDuty notifier
- [ ] Audit export (CSV / SIEM forwarding)
- [ ] Web UI for the `/status` endpoint
