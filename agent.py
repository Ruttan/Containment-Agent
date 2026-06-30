"""
Containment Agent — Main Server

This is the entry point. Run this file to start the agent.

What this server does:
  POST /webhook/alert  — receives alerts from your security platform
  GET  /approve/<token> — analyst clicks Approve; triggers isolation
  GET  /deny/<token>    — analyst clicks Deny; no action taken
  GET  /status          — lists all pending, completed, and expired approvals
"""

import uuid
import logging
import threading
import time
from datetime import datetime, timezone
from flask import Flask, request, jsonify, redirect
import yaml

from evaluator import AlertEvaluator
from notifiers.slack_notifier import SlackNotifier
from notifiers.email_notifier import EmailNotifier
from connectors.crowdstrike import CrowdStrikeConnector
from connectors.tanium import TaniumConnector
from connectors.generic import GenericConnector


# -----------------------------------------------------------------------
# Bootstrap
# -----------------------------------------------------------------------

def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def build_connector(config: dict):
    platform = config.get("platform", "generic").lower()
    if platform == "crowdstrike":
        return CrowdStrikeConnector(config)
    elif platform == "tanium":
        return TaniumConnector(config)
    else:
        return GenericConnector(config)


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
CONNECTOR = None
EVALUATOR = None
SLACK = None
EMAIL = None


@app.route("/webhook/alert", methods=["POST"])
def receive_alert():
    """
    Entry point for incoming alerts.
    Expects a JSON body — can be any format (CrowdStrike, Tanium, SIEM, etc.).
    """
    alert = request.get_json(force=True, silent=True)
    if not alert:
        return jsonify({"error": "No JSON body received."}), 400

    logging.info(f"Alert received: {alert}")

    # Step 1: AI evaluates the alert
    try:
        evaluation = EVALUATOR.evaluate(alert)
    except Exception as e:
        logging.error(f"Evaluation failed: {e}")
        return jsonify({"error": f"Evaluation failed: {e}"}), 500

    logging.info(f"Evaluation result: severity={evaluation.get('severity')}, "
                 f"recommendation={evaluation.get('recommendation')}, "
                 f"host={evaluation.get('host_id')}")

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
    host_info = CONNECTOR.get_host_info(host_id)

    # Step 4: Create an approval token and store the pending request
    token = str(uuid.uuid4())
    with approvals_lock:
        pending_approvals[token] = {
            "evaluation": evaluation,
            "host_info": host_info,
            "created_at": datetime.now(timezone.utc),
            "status": "pending",
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
    })


@app.route("/approve/<token>", methods=["GET"])
def approve(token: str):
    """Analyst clicks the Approve link in email or Slack."""
    with approvals_lock:
        entry = pending_approvals.get(token)
        if not entry:
            return "<h2>Unknown or expired approval token.</h2>", 404
        if entry["status"] != "pending":
            return f"<h2>This request has already been {entry['status']}.</h2>", 409
        entry["status"] = "approved"

    host_info = entry["host_info"]
    evaluation = entry["evaluation"]
    host_id = evaluation.get("host_id", "unknown")

    logging.info(f"Isolation approved — host={host_info.get('hostname')}, host_id={host_id}")

    # Execute isolation
    result = CONNECTOR.isolate_host(host_id)
    logging.info(f"Isolation result: {result}")

    # Notify outcome
    SLACK.send_result(host_info, "isolated")
    EMAIL.send_result(host_info, "isolated")

    if result["success"]:
        return f"""
        <html><body style="font-family:Arial;max-width:500px;margin:80px auto;text-align:center;">
          <h2 style="color:#27ae60;">✅ Host Isolated</h2>
          <p><strong>{host_info.get('hostname')}</strong> has been isolated from the network.</p>
          <p style="color:#666;">{result['message']}</p>
        </body></html>
        """
    else:
        return f"""
        <html><body style="font-family:Arial;max-width:500px;margin:80px auto;text-align:center;">
          <h2 style="color:#e74c3c;">⚠️ Isolation Failed</h2>
          <p>Approval was granted but the platform returned an error:</p>
          <p style="color:#666;">{result['message']}</p>
          <p>Check agent.log for details and attempt manual isolation.</p>
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
                "host": e["host_info"].get("hostname"),
                "severity": e["evaluation"].get("severity"),
                "threat": e["evaluation"].get("threat_name"),
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

    CONNECTOR = build_connector(CONFIG)
    EVALUATOR = AlertEvaluator(CONFIG)
    SLACK = SlackNotifier(CONFIG)
    EMAIL = EmailNotifier(CONFIG)

    timeout = CONFIG.get("agent", {}).get("approval_timeout_minutes", 30)
    t = threading.Thread(target=expiry_worker, args=(timeout,), daemon=True)
    t.start()

    server_cfg = CONFIG["server"]
    logging.info(f"Containment Agent starting on {server_cfg['host']}:{server_cfg['port']}")
    app.run(host=server_cfg["host"], port=server_cfg["port"])
