"""
SIEM Forwarder — sends a full audit trail of every alert this agent handles
to an external SIEM: the raw alert, Claude's evaluation (severity,
explanation, suggested fix, available actions), and the eventual outcome
(approved/denied/expired + which action was actually executed and whether
it succeeded).

Two delivery mechanisms, independently toggleable, either or both can be on
at once:
  - Splunk HTTP Event Collector (HEC) — the standard way Splunk ingests
    events over HTTP.
  - Generic HTTP/JSON webhook — works for any other SIEM that can accept a
    POST (QRadar, Sentinel, LogRhythm, Elastic, etc.), or for a
    file-tailing / syslog-forwarder shim if that's how a given SIEM prefers
    to receive events.

Required config fields (all under `integrations.siem`):
  splunk_hec.enabled        bool
  splunk_hec.url            e.g. "https://splunk.example.com:8088"
  splunk_hec.token          HEC token (Settings > Data Inputs > HTTP Event Collector)
  splunk_hec.index          optional, index name
  splunk_hec.sourcetype     optional, defaults to "containment_agent"

  generic_webhook.enabled   bool
  generic_webhook.url       any HTTPS endpoint that accepts a JSON POST
  generic_webhook.headers   optional dict of extra headers (e.g. an API key)

Failures here are logged but never raised — a SIEM being unreachable should
never block or break the actual containment workflow.
"""

import logging
import requests
from datetime import datetime, timezone


class SIEMForwarder:

    def __init__(self, config: dict):
        siem_cfg = config.get("integrations", {}).get("siem", {})

        self.hec_cfg = siem_cfg.get("splunk_hec", {}) or {}
        self.hec_enabled = bool(self.hec_cfg.get("enabled"))

        self.webhook_cfg = siem_cfg.get("generic_webhook", {}) or {}
        self.webhook_enabled = bool(self.webhook_cfg.get("enabled"))

        self.enabled = self.hec_enabled or self.webhook_enabled
        if self.enabled:
            logging.info(
                f"SIEM forwarding enabled — splunk_hec={self.hec_enabled}, "
                f"generic_webhook={self.webhook_enabled}"
            )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def forward(self, event_type: str, token: str, source: str, evaluation: dict,
                host_info: dict, status: str, action_taken: str = None, result: dict = None):
        """
        Builds a single audit event and sends it to every enabled destination.

        event_type: "alert_evaluated" | "approval_requested" | "action_result" | "denied" | "expired"
        status: "pending" | "approved" | "denied" | "expired"
        """
        if not self.enabled:
            return

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "token": token,
            "source": source,
            "status": status,
            "action_taken": action_taken,
            "host": {
                "hostname": host_info.get("hostname") if host_info else None,
                "ip_address": host_info.get("ip_address") if host_info else None,
                "os": host_info.get("os") if host_info else None,
                "host_id": evaluation.get("host_id") if evaluation else None,
            },
            "evaluation": {
                "severity": evaluation.get("severity"),
                "recommendation": evaluation.get("recommendation"),
                "confidence": evaluation.get("confidence"),
                "threat_name": evaluation.get("threat_name"),
                "mitre_technique": evaluation.get("mitre_technique"),
                "summary": evaluation.get("summary"),
                "explanation": evaluation.get("explanation"),
                "suggested_fix": evaluation.get("suggested_fix"),
                "available_actions": evaluation.get("available_actions"),
            } if evaluation else {},
            "action_result": result,
            "raw_alert": evaluation.get("original_alert") if evaluation else None,
        }

        if self.hec_enabled:
            self._send_splunk_hec(event)
        if self.webhook_enabled:
            self._send_generic_webhook(event)

    # ------------------------------------------------------------------
    # Delivery mechanisms
    # ------------------------------------------------------------------

    def _send_splunk_hec(self, event: dict):
        url = f"{self.hec_cfg['url'].rstrip('/')}/services/collector/event"
        headers = {
            "Authorization": f"Splunk {self.hec_cfg['token']}",
            "Content-Type": "application/json",
        }
        payload = {
            "event": event,
            "sourcetype": self.hec_cfg.get("sourcetype", "containment_agent"),
        }
        if self.hec_cfg.get("index"):
            payload["index"] = self.hec_cfg["index"]

        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=10, verify=self.hec_cfg.get("verify_ssl", True))
            if resp.status_code >= 300:
                logging.warning(f"Splunk HEC forward failed ({resp.status_code}): {resp.text}")
        except Exception as e:
            logging.warning(f"Splunk HEC forward failed: {e}")

    def _send_generic_webhook(self, event: dict):
        url = self.webhook_cfg["url"]
        headers = {"Content-Type": "application/json"}
        headers.update(self.webhook_cfg.get("headers", {}) or {})

        try:
            resp = requests.post(url, json=event, headers=headers, timeout=10)
            if resp.status_code >= 300:
                logging.warning(f"Generic SIEM webhook forward failed ({resp.status_code}): {resp.text}")
        except Exception as e:
            logging.warning(f"Generic SIEM webhook forward failed: {e}")
