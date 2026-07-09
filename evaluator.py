"""
AI Evaluation Layer.

This is the brain of the agent. When an alert arrives, this module:
1. Sends the raw alert data to Claude (via the Anthropic API).
2. Asks Claude to assess the severity and explain what happened in plain English.
3. Returns a structured evaluation that drives the rest of the workflow.

Why Claude? Because alerts from different platforms look completely different.
Claude can read any format and extract what matters without hand-coded parsers
for every possible alert schema.
"""

import json
import anthropic


EVALUATION_PROMPT = """
You are a cybersecurity analyst assistant embedded in an automated containment agent.
An alert has been received that may require a containment response on a host.

Your job is to evaluate this alert and return a JSON object with the following fields:

{{
  "severity": "low" | "medium" | "high" | "critical",
  "recommendation": "isolate" | "monitor" | "ignore",
  "summary": "A 2-3 sentence plain-English explanation of what the alert means and why isolation may be warranted.",
  "explanation": "A detailed, analyst-grade breakdown of WHY this alert fired. Reference specific evidence present in the alert data: MITRE ATT&CK technique/tactic if identifiable, process tree / parent-child process relationships, command lines, file hashes, network indicators (IPs, domains), user account involved, and any detection logic or rule name. Write this as several sentences or short paragraphs — this is the 'deep detail' the analyst reads before deciding, so do not just repeat the summary. If the alert data is sparse, say plainly what is and isn't known rather than inventing detail.",
  "suggested_fix": "A concrete, specific remediation recommendation — e.g. which process to kill, which file/hash to quarantine or block, whether to isolate the host, and any follow-up steps (credential reset, reimage, further hunting query) beyond what the agent can execute automatically.",
  "available_actions": "An array containing zero or more of: 'isolate', 'kill_process', 'quarantine_file', 'block_hash'. Only include an action if the alert data actually contains what's needed to execute it (e.g. only include 'kill_process' if a process ID/PID is present in the alert; only include 'quarantine_file' or 'block_hash' if a file path or hash is present). Always include 'isolate' if a host/device identifier is present and recommendation is 'isolate'.",
  "process_id": "The process ID/PID from the alert if present, otherwise null. Required for the kill_process action to work.",
  "file_path": "The file path from the alert if present, otherwise null.",
  "file_hash": "The file hash (SHA1/SHA256/MD5) from the alert if present, otherwise null. Required for quarantine_file/block_hash actions to work.",
  "mitre_technique": "The MITRE ATT&CK technique ID and name if identifiable (e.g. 'T1055 - Process Injection'), otherwise null.",
  "host_id": "The host identifier extracted from the alert (device ID, hostname, etc.)",
  "threat_name": "The name of the threat or alert rule if present, otherwise 'Unknown'",
  "confidence": "low" | "medium" | "high"
}}

Rules:
- severity "critical" or "high" with recommendation "isolate" means the agent will send an approval request.
- Be conservative: if you are unsure, lean toward "monitor" rather than "isolate".
- Extract the host_id exactly as it appears in the alert. If multiple hosts are present, pick the primary victim host.
- Only list an action in "available_actions" if the alert genuinely contains the data needed to execute it. Do not guess or fabricate a process_id or file_hash that isn't in the alert.
- Return ONLY the JSON object. No explanation text outside the JSON.

Alert data:
{alert_data}
"""


class AlertEvaluator:

    def __init__(self, config: dict):
        self.client = anthropic.Anthropic(api_key=config["anthropic_api_key"])
        self.min_severity = config.get("agent", {}).get("min_severity_to_notify", "medium")

    def evaluate(self, alert: dict) -> dict:
        """
        Takes a raw alert dict (from any platform) and returns a structured evaluation.
        """
        alert_text = json.dumps(alert, indent=2)
        prompt = EVALUATION_PROMPT.format(alert_data=alert_text)

        message = self.client.messages.create(
            model="claude-haiku-4-5-20251001",  # Fast and cheap — appropriate for triage
            max_tokens=1024,  # raised from 512 to fit the longer explanation/suggested_fix fields
            messages=[{"role": "user", "content": prompt}],
        )

        raw = message.content[0].text.strip()

        # Strip markdown code fences if Claude wraps the JSON
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()

        evaluation = json.loads(raw)

        # Defaults so downstream code (notifiers, agent routes) never has to
        # guard against missing keys, even if the model omits an optional field.
        evaluation.setdefault("explanation", evaluation.get("summary", "No detailed explanation available."))
        evaluation.setdefault("suggested_fix", "No specific remediation suggested.")
        evaluation.setdefault("available_actions", [])
        evaluation.setdefault("process_id", None)
        evaluation.setdefault("file_path", None)
        evaluation.setdefault("file_hash", None)
        evaluation.setdefault("mitre_technique", None)

        # Belt-and-suspenders: never offer an action the alert can't actually support.
        if not evaluation.get("process_id"):
            evaluation["available_actions"] = [a for a in evaluation["available_actions"] if a != "kill_process"]
        if not evaluation.get("file_hash"):
            evaluation["available_actions"] = [
                a for a in evaluation["available_actions"] if a not in ("quarantine_file", "block_hash")
            ]

        # Attach the original alert for downstream use
        evaluation["original_alert"] = alert

        return evaluation

    def should_notify(self, evaluation: dict) -> bool:
        """
        Returns True if the alert meets the minimum severity threshold
        defined in config to trigger an approval notification.
        """
        severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        alert_rank = severity_rank.get(evaluation.get("severity", "low"), 1)
        min_rank = severity_rank.get(self.min_severity, 2)
        return alert_rank >= min_rank and evaluation.get("recommendation") == "isolate"
