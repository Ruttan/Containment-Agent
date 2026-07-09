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
- **Purpose**: Receives security alerts from multiple configurable platforms simultaneously (Microsoft Defender for Endpoint, unified M365 Defender, CrowdStrike, Tanium, or any custom source), evaluates them with an AI model — which explains why the alert fired and suggests a fix — and executes an approved response action (isolate host, kill process, quarantine file, or block hash) after human approval via email and Slack.
- **Design principle**: Platform-agnostic and multi-source. Adding a new platform requires only a new connector file plus a `sources` entry in config — no changes to the core agent.

---

## Problem This Solves

Security platforms (CrowdStrike, Tanium, SIEMs) generate alerts that require fast but deliberate containment decisions. Fully automated isolation risks false positives taking down production hosts. Manual workflows are too slow. This agent sits in the middle: AI evaluates the alert instantly, humans approve with one click, the agent executes.

---

## Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                         Containment Agent                             │
│                                                                        │
│  Webhook (per source) ──► Evaluator (Claude AI) ──► Notifier          │
│  /webhook/alert/<source>        │                        │           │
│  (Defender / CrowdStrike /      │              Email + Slack:         │
│   Tanium / Generic — any        │              severity, why-it-fired,│
│   number active at once)        │              suggested fix, and     │
│                                  │              one button per         │
│                                  │              available action       │
│                                  │                        │           │
│                                  │              Analyst clicks an       │
│                                  │              action button           │
│                                  ▼                        │           │
│                     Connector for that source ◄───────────┘           │
│                     (isolate / kill_process /                         │
│                      quarantine_file / block_hash)                    │
│                              │                                        │
│                              ▼                                       │
│                       Platform API                                    │
└───────────────────────────────────────────────────────────────────────┘
```

### Data Flow (step by step)

1. A security platform POSTs a JSON alert to `POST /webhook/alert/<source>` (source = a key under `sources:` in config, e.g. `defender_endpoint`)
2. `evaluator.py` sends the alert to Claude (claude-haiku-4-5) for triage
3. Claude returns structured JSON: severity, recommendation, summary, **detailed explanation** (MITRE ATT&CK/process tree/indicators if present), **suggested_fix**, **available_actions** (subset of isolate/kill_process/quarantine_file/block_hash the alert data actually supports), host_id, process_id, file_path, file_hash
4. If severity meets the threshold, the agent fetches host details via that source's connector
5. A unique approval token is created and stored in memory, tagged with the source
6. `SlackNotifier` and `EmailNotifier` send the AI assessment (summary + explanation + suggested fix) plus one button per available action, and a Deny link
7. Analyst clicks an action → `GET /approve/<token>/<action>` → the source's connector executes that action (isolate_host / kill_process / quarantine_file / block_hash)
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
│   │                         # Required: isolate_host(), get_host_info()
│   │                         # Optional (default to "not supported"): kill_process(),
│   │                         # quarantine_file(), block_hash()
│   ├── defender.py           # Microsoft Defender adapter (Microsoft Graph Security API).
│   │                         # Covers Defender for Endpoint AND unified M365 Defender.
│   │                         # OAuth2 client-credentials auth. NOT live-tested — verify
│   │                         # exact Graph endpoint paths before production use.
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

Optionally, a connector can also implement (defaults return a "not supported" result):

```python
def kill_process(self, host_id: str, process_id: str) -> dict:
    # Same return shape as isolate_host

def quarantine_file(self, host_id: str, file_path: str = None, file_hash: str = None) -> dict:
    # Same return shape as isolate_host

def block_hash(self, file_hash: str) -> dict:
    # Same return shape as isolate_host
```

The evaluator only tells the notifier to offer an action if the alert data actually
supports it (e.g. `kill_process` only appears in `available_actions` if a `process_id`
was extracted). If a connector doesn't implement an action the user still can't trigger
it even if the evaluator suggested it — `BaseConnector`'s defaults return `success: False`.

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
  "explanation": "Detailed analyst-grade breakdown of why the alert fired (MITRE ATT&CK technique, process tree, indicators, etc.)",
  "suggested_fix": "Concrete remediation recommendation, including follow-up steps beyond what the agent can execute automatically",
  "available_actions": ["isolate", "kill_process", "quarantine_file", "block_hash"],
  "process_id": "extracted PID, or null",
  "file_path": "extracted file path, or null",
  "file_hash": "extracted file hash, or null",
  "mitre_technique": "e.g. 'T1055 - Process Injection', or null",
  "host_id": "extracted host identifier",
  "threat_name": "name of the threat or rule",
  "confidence": "low | medium | high",
  "original_alert": { "...": "original alert dict" }
}
```

`available_actions` is trimmed defensively in `evaluator.py` even if the model
suggests an action without the supporting data (e.g. `kill_process` without a
`process_id` gets stripped out).

### Approval Store Schema (in-memory)

```python
pending_approvals: dict[str, dict] = {
    "<uuid-token>": {
        "evaluation": { ... },   # Output of AlertEvaluator.evaluate()
        "host_info": { ... },    # Output of connector.get_host_info()
        "source": "defender_endpoint",  # which configured source this alert came from
        "created_at": datetime,  # UTC
        "status": "pending | approved | denied | expired",
        "action_taken": "isolate | kill_process | quarantine_file | block_hash | null"
    }
}
```

---

## Configuration Reference (`config.yaml`)

| Key | Type | Description |
|-----|------|-------------|
| `sources.<name>.connector` | string | Which connector handles this source: `defender`, `crowdstrike`, `tanium`, or `generic`. Source name becomes the webhook path `/webhook/alert/<name>`. Multiple sources can be active at once. |
| `platform` | string | Legacy single-connector mode (used only if `sources` is absent). |
| `anthropic_api_key` | string | Anthropic API key for alert evaluation |
| `platforms.defender.tenant_id` | string | Azure AD tenant ID |
| `platforms.defender.client_id` | string | Azure AD app registration client ID |
| `platforms.defender.client_secret` | string | Azure AD app registration client secret |
| `platforms.crowdstrike.client_id` | string | CrowdStrike OAuth2 client ID |
| `platforms.crowdstrike.client_secret` | string | CrowdStrike OAuth2 client secret |
| `platforms.crowdstrike.base_url` | string | CrowdStrike API base URL |
| `platforms.tanium.api_token` | string | Tanium API session token |
| `platforms.tanium.base_url` | string | Tanium server base URL |
| `platforms.generic.isolation_endpoint` | string | URL to POST isolation/response requests to |
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
| `POST` | `/webhook/alert/<source>` | None | Receive an alert for a specific configured source. Returns evaluation + token. |
| `POST` | `/webhook/alert` | None | Legacy path — routes to the first configured source. |
| `GET` | `/approve/<token>/<action>` | None (token is secret) | Execute the chosen action: `isolate`, `kill_process`, `quarantine_file`, or `block_hash`. |
| `GET` | `/approve/<token>` | None (token is secret) | Legacy path — defaults to `isolate`. |
| `GET` | `/deny/<token>` | None (token is secret) | Deny the request. No action taken. |
| `GET` | `/status` | None | List all approval requests, available/taken actions, and statuses. |

---

## AI Engine Instructions

If you are an AI engine working in this codebase:

**Do:**
- Read `config.example.yaml` to understand configuration shape. Never read or write `config.yaml` (it contains real credentials).
- To add a new platform: create `connectors/<platform>.py`, inherit `BaseConnector`, implement `isolate_host()`/`get_host_info()` (and any of `kill_process()`/`quarantine_file()`/`block_hash()` the platform supports), register it in `CONNECTOR_CLASSES` in `agent.py`, and add a `sources.<name>` + `platforms.<name>` block to `config.example.yaml`.
- To add a new notifier: create `notifiers/<name>_notifier.py` with `send_approval_request()` and `send_result()` methods (note `send_result` now takes `(host_info, action, result=None, actor="analyst")`). Wire it into `agent.py` alongside the existing notifiers.
- Use the `evaluator.py` prompt template as the single source of truth for what the AI is asked to do. If requirements change, modify the prompt there. `available_actions` should only ever include actions the alert data can actually support — that filtering happens both in the prompt and defensively in `evaluate()`.
- The approval store (`pending_approvals`) is in-memory. For production, replace with Redis or a database — the store interface is intentionally simple.
- Multiple `sources` can be active at once — each gets its own webhook path and its own connector instance, but all share the same evaluator and notifiers.

**Don't:**
- Don't modify `agent.py` routes to add platform-specific logic. Platform differences belong in connectors.
- Don't commit `config.yaml`, `agent.log`, or `__pycache__` — they are in `.gitignore`.
- Don't add authentication to the webhook endpoint without updating this context file.
- Don't let a connector's optional action methods silently no-op — either implement them for real or leave `BaseConnector`'s "not supported" default so failures are visible to the analyst.

---

## Extension Roadmap (not yet implemented)

- [ ] Persistent approval store (Redis / SQLite)
- [ ] Webhook signature verification (HMAC) per platform — this matters more now that multiple sources hit the same server
- [ ] Multi-host alert handling (batch isolation)
- [ ] Microsoft Teams notifier
- [ ] PagerDuty notifier
- [ ] Audit export (CSV / SIEM forwarding)
- [ ] Web UI for the `/status` endpoint
- [ ] Live-test the Defender connector against a real Graph Security API tenant (endpoints in `connectors/defender.py` are best-effort/unverified, same caveat as CrowdStrike/Tanium)
- [ ] Live-test the new kill_process/quarantine_file/block_hash methods added to CrowdStrike and Tanium connectors
