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
An alert has been received that may require isolating a host from the network.

Your job is to evaluate this alert and return a JSON object with the following fields:

{{
  "severity": "low" | "medium" | "high" | "critical",
  "recommendation": "isolate" | "monitor" | "ignore",
  "summary": "A 2-3 sentence plain-English explanation of what the alert means and why isolation may be warranted.",
  "host_id": "The host identifier extracted from the alert (device ID, hostname, etc.)",
  "threat_name": "The name of the threat or alert rule if present, otherwise 'Unknown'",
  "confidence": "low" | "medium" | "high"
}}

Rules:
- severity "critical" or "high" with recommendation "isolate" means the agent will send an approval request.
- Be conservative: if you are unsure, lean toward "monitor" rather than "isolate".
- Extract the host_id exactly as it appears in the alert. If multiple hosts are present, pick the primary victim host.
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
            max_tokens=512,
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
