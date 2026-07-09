"""
Containment Agent — Main Server

This is the entry point. Run this file to start the agent.

What this server does:
  POST /webhook/alert/<source>    — receives alerts from a configured source
                                     (e.g. defender_endpoint, m365_defender,
                                     crowdstrike, tanium, generic)
  GET  /approve/<token>/<action>  — analyst clicks an action button
                                     (isolate | kill_process | quarantine_file | block_hash)
  GET  /deny/<token>              — analyst clicks Deny; no action taken
  GET  /status                    — lists all pending, completed, and expired approvals

Multiple alert sources can be active at once (see `sources:` in config.yaml).
Each source is routed to its own connector for executing response actions,
but all alerts flow through the same AI evaluator and notifiers.
"""

import uuid
import logging
import threading
import time
from datetime import datetime, timezone
from flask import Flask, request, jsonify
import yaml

from evaluator import AlertEvaluator
from notifiers.slack_notifier import SlackNotifier
from notifiers.email_notifier import EmailNotifier
from connectors.crowdstrike import CrowdStrikeConnector
from connectors.tanium import TaniumConnector
from connectors.generic import GenericConnector
from connectors.defender import DefenderConnector


CONNECTOR_CLASSES = {
    "crowdstrike": CrowdStrikeConnector,
    "tanium": TaniumConnector,
    "generic": GenericConnector,
    "defender": DefenderConnector,
}

VALID_ACTIONS = ("isolate", "kill_process", "quarantine_file", "block_hash")


# -----------------------------------------------------------------------
# Bootstrap
# -----------------------------------------------------------------------

def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def build_connectors(config: dict) -> dict:
    """
    Builds one connector instance per configured alert source and returns a
    dict keyed by source name, e.g.:
      {"defender_endpoint": DefenderConnector(...), "crowdstrike": CrowdStrikeConnector(...)}

    Falls back to the legacy single-`platform` config (pre-multi-source) if
    `sources` isn't present, so existing config.yaml files keep working.
    """
    sources_cfg = config.get("sources")
    if not sources_cfg:
        # Legacy single-platform mode
        platform = config.get("platform", "generic").lower()
        connector_cls = CONNECTOR_CLASSES.get(platform, GenericConnector)
        return {platform: connector_cls(config)}

    connectors = {}
    for source_name, source_cfg in sources_cfg.items():
        connector_type = source_cfg.get("connector", source_name).lower()
        connector_cls = CONNECTOR_CLASSES.get(connector_type)
        if connector_cls is None:
            logging.warning(f"Unknown connector type '{connector_type}' for source '{source_name}' — skipping.")
            continue
        connectors[source_name] = connector_cls(config)
    return connectors


def setup_logging(config: dict):
    handlers = [logging.StreamHandler()]
    agent_cfg = config.get("agent", {})
    if agent_cfg.get("log_to_file"):
        handlers.append(logging.FileHandler(agent_cfg.get("log_file", "agent.log")))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )


# -----------------------------------------------------------------------
# In-memory approval store
# Tracks pending approval requests keyed by a unique token.
# In production you'd swap this for Redis or a database.
# -----------------------------------------------------------------------

# Each entry: { "evaluation": {...}, "host_info": {...}, "created_at": datetime, "status": "pending" }
pending_approvals: dict[str, dict] = {}
approvals_lock = threading.Lock()


# -----------------------------------------------------------------------
# Flask app
# -----------------------------------------------------------------------

app = Flask(__name__)
CONFIG = {}
CONNECTORS = {}
DEFAULT_SOURCE = None
EVALUATOR = None
SLACK = None
EMAIL = None


def _get_connector_for_source(source: str):
    """Looks up the connector for a given alert source, falling back to the
    default source if an unrecognized one is used (keeps single-platform
    configs and ad-hoc test calls working)."""
    return CONNECTORS.get(source) or CONNECTORS.get(DEFAULT_SOURCE)


@app.route("/webhook/alert/<source>", methods=["POST"])
@app.route("/webhook/alert", methods=["POST"])  # legacy path — routes to the default/first configured source
def receive_alert(source: str = None):
    """
    Entry point for incoming alerts. `source` identifies which configured
    alert source/connector this came from (e.g. defender_endpoint,
    m365_defender, crowdstrike, tanium). Expects a JSON body — can be any
    format; the AI evaluator reads whatever shape the source sends.
    """
    source = source or DEFAULT_SOURCE
    connector = _get_connector_for_source(source)
    if connector is None:
        return jsonify({"error": f"Unknown or unconfigured alert source '{source}'."}), 400

    alert = request.get_json(force=True, silent=True)
    if not alert:
        return jsonify({"error": "No JSON body received."}), 400

    logging.info(f"Alert received from source='{source}': {alert}")

    # Step 1: AI evaluates the alert
    try:
        evaluation = EVALUATOR.evaluate(alert)
    except Exception as e:
        logging.error(f"Evaluation failed: {e}")
        return jsonify({"error": f"Evaluation failed: {e}"}), 500

    logging.info(f"Evaluation result: severity={evaluation.get('severity')}, "
                 f"recommendation={evaluation.get('recommendation')}, "
                 f"host={evaluation.get('host_id')}, "
                 f"available_actions={evaluation.get('available_actions')}")

    # Step 2: Check if we should notify
    if not EVALUATOR.should_notify(evaluation):
        logging.info("Alert below notification threshold — logged only.")
        return jsonify({
            "status": "logged",
            "message": "Alert did not meet notification threshold.",
            "evaluation": evaluation,
        })

    # Step 3: Fetch host details for the notification
    host_id = evaluation.get("host_id", "unknown")
    host_info = connector.get_host_info(host_id)

    # Step 4: Create an approval token and store the pending request
    token = str(uuid.uuid4())
    with approvals_lock:
        pending_approvals[token] = {
            "evaluation": evaluation,
            "host_info": host_info,
            "source": source,
            "created_at": datetime.now(timezone.utc),
            "status": "pending",
            "action_taken": None,
        }

    # Step 5: Send notifications
    public_url = CONFIG["server"]["public_url"]
    slack_ok = SLACK.send_approval_request(token, evaluation, host_info, public_url)
    email_ok = EMAIL.send_approval_request(token, evaluation, host_info, public_url)

    logging.info(f"Approval request sent — token={token}, slack={slack_ok}, email={email_ok}")

    return jsonify({
        "status": "approval_requested",
        "token": token,
        "host": host_info.get("hostname"),
        "severity": evaluation.get("severity"),
        "available_actions": evaluation.get("available_actions"),
    })


ACTION_LABELS = {
    "isolate": "Host Isolated",
    "kill_process": "Process Terminated",
    "quarantine_file": "File Quarantined",
    "block_hash": "Hash Blocked",
}


@app.route("/approve/<token>/<action>", methods=["GET"])
@app.route("/approve/<token>", methods=["GET"])  # legacy path — defaults to "isolate"
def approve(token: str, action: str = "isolate"):
    """Analyst clicks one of the action buttons (isolate / kill_process /
    quarantine_file / block_hash) in the email or Slack notification."""
    if action not in VALID_ACTIONS:
        return f"<h2>Unknown action '{action}'.</h2>", 400

    with approvals_lock:
        entry = pending_approvals.get(token)
        if not entry:
            return "<h2>Unknown or expired approval token.</h2>", 404
        if entry["status"] != "pending":
            return f"<h2>This request has already been {entry['status']}.</h2>", 409
        entry["status"] = "approved"
        entry["action_taken"] = action

    host_info = entry["host_info"]
    evaluation = entry["evaluation"]
    host_id = evaluation.get("host_id", "unknown")
    connector = _get_connector_for_source(entry.get("source"))

    logging.info(f"Action '{action}' approved — host={host_info.get('hostname')}, host_id={host_id}")

    # Execute the chosen response action against the source's connector
    if action == "isolate":
        result = connector.isolate_host(host_id)
    elif action == "kill_process":
        result = connector.kill_process(host_id, evaluation.get("process_id"))
    elif action == "quarantine_file":
        result = connector.quarantine_file(host_id, evaluation.get("file_path"), evaluation.get("file_hash"))
    elif action == "block_hash":
        result = connector.block_hash(evaluation.get("file_hash"))

    logging.info(f"Action result: {result}")

    # Notify outcome
    SLACK.send_result(host_info, action, result)
    EMAIL.send_result(host_info, action, result)

    label = ACTION_LABELS.get(action, action)
    if result["success"]:
        return f"""
        <html><body style="font-family:Arial;max-width:500px;margin:80px auto;text-align:center;">
          <h2 style="color:#27ae60;">✅ {label}</h2>
          <p><strong>{host_info.get('hostname')}</strong>: {result['message']}</p>
        </body></html>
        """
    else:
        return f"""
        <html><body style="font-family:Arial;max-width:500px;margin:80px auto;text-align:center;">
          <h2 style="color:#e74c3c;">⚠️ Action Failed</h2>
          <p>Approval was granted but the platform returned an error:</p>
          <p style="color:#666;">{result['message']}</p>
          <p>Check agent.log for details and attempt this action manually.</p>
        </body></html>
        """


@app.route("/deny/<token>", methods=["GET"])
def deny(token: str):
    """Analyst clicks the Deny link in email or Slack."""
    with approvals_lock:
        entry = pending_approvals.get(token)
        if not entry:
            return "<h2>Unknown or expired approval token.</h2>", 404
        if entry["status"] != "pending":
            return f"<h2>This request has already been {entry['status']}.</h2>", 409
        entry["status"] = "denied"

    host_info = entry["host_info"]
    logging.info(f"Isolation denied — host={host_info.get('hostname')}")

    SLACK.send_result(host_info, "denied")
    EMAIL.send_result(host_info, "denied")

    return f"""
    <html><body style="font-family:Arial;max-width:500px;margin:80px auto;text-align:center;">
      <h2 style="color:#c0392b;">❌ Isolation Denied</h2>
      <p>No action was taken on <strong>{host_info.get('hostname')}</strong>.</p>
    </body></html>
    """


@app.route("/status", methods=["GET"])
def status():
    """Returns a summary of all approval requests."""
    with approvals_lock:
        summary = [
            {
                "token": t,
                "source": e.get("source"),
                "host": e["host_info"].get("hostname"),
                "severity": e["evaluation"].get("severity"),
                "threat": e["evaluation"].get("threat_name"),
                "mitre_technique": e["evaluation"].get("mitre_technique"),
                "available_actions": e["evaluation"].get("available_actions"),
                "action_taken": e.get("action_taken"),
                "status": e["status"],
                "created_at": e["created_at"].isoformat(),
            }
            for t, e in pending_approvals.items()
        ]
    return jsonify(summary)


# -----------------------------------------------------------------------
# Expiry background thread
# Marks pending approvals as expired after the configured timeout.
# -----------------------------------------------------------------------

def expiry_worker(timeout_minutes: int):
    while True:
        time.sleep(60)
        now = datetime.now(timezone.utc)
        with approvals_lock:
            for token, entry in pending_approvals.items():
                if entry["status"] != "pending":
                    continue
                age_minutes = (now - entry["created_at"]).total_seconds() / 60
                if age_minutes >= timeout_minutes:
                    entry["status"] = "expired"
                    logging.info(f"Approval expired — token={token}, host={entry['host_info'].get('hostname')}")
                    SLACK.send_result(entry["host_info"], "expired")
                    EMAIL.send_result(entry["host_info"], "expired")


# -----------------------------------------------------------------------
# Startup
# -----------------------------------------------------------------------

if __name__ == "__main__":
    CONFIG = load_config()
    setup_logging(CONFIG)

    CONNECTORS = build_connectors(CONFIG)
    if not CONNECTORS:
        raise RuntimeError("No valid alert sources/connectors configured — check config.yaml's 'sources' block.")
    DEFAULT_SOURCE = next(iter(CONNECTORS))  # first configured source; used for the legacy /webhook/alert path
    logging.info(f"Configured alert sources: {list(CONNECTORS.keys())} (default: {DEFAULT_SOURCE})")

    EVALUATOR = AlertEvaluator(CONFIG)
    SLACK = SlackNotifier(CONFIG)
    EMAIL = EmailNotifier(CONFIG)

    timeout = CONFIG.get("agent", {}).get("approval_timeout_minutes", 30)
    t = threading.Thread(target=expiry_worker, args=(timeout,), daemon=True)
    t.start()

    server_cfg = CONFIG["server"]
    logging.info(f"Containment Agent starting on {server_cfg['host']}:{server_cfg['port']}")
    app.run(host=server_cfg["host"], port=server_cfg["port"])
